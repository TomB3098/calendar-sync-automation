from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sync_exchange_icloud_calendar import (
    GOOGLE_META_MODE,
    MODE_BLOCKED,
    MODE_FULL,
    SOURCE_EXCHANGE,
    SOURCE_GOOGLE,
    SOURCE_ICLOUD,
    ExchangeClient,
    GoogleClient,
    ICloudClient,
    SyncEvent,
    google_source_skip_reason,
    now_utc,
    parse_any_datetime,
    normalize_calendar_description,
    normalize_singleline_text,
    stable_sync_id,
)

from .config import AppSettings
from .repository import AppRepository
from .security import iso_z

SOURCE_WEBAPP = "webapp"
LOG_FIELD_LABELS = {
    "title": "Titel",
    "starts_at": "Start",
    "ends_at": "Ende",
    "all_day": "Ganztag",
    "description": "Beschreibung",
    "location": "Ort",
    "recurrence": "Wiederholung",
}
LOG_FIELD_ORDER = ("title", "starts_at", "ends_at", "all_day", "description", "location", "recurrence")


def _log_snapshot_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Ja" if value else "Nein"
    if isinstance(value, list):
        return "\n".join(str(item) for item in value)
    return str(value)


def _build_change_rows(before: Optional[Dict[str, Any]], after: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
    before_data = before or {}
    after_data = after or {}
    keys = list(LOG_FIELD_ORDER)
    for key in list(before_data.keys()) + list(after_data.keys()):
        if key not in keys:
            keys.append(key)

    rows: List[Dict[str, str]] = []
    for key in keys:
        before_value = _log_snapshot_value(before_data.get(key))
        after_value = _log_snapshot_value(after_data.get(key))
        if before_value == after_value:
            continue
        rows.append(
            {
                "field": key,
                "label": LOG_FIELD_LABELS.get(key, key.replace("_", " ").title()),
                "before": before_value,
                "after": after_value,
            }
        )
    return rows


def _snapshot_internal_event(event: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not event:
        return None
    recurrence = [line for line in str(event.get("recurrence_rule") or "").splitlines() if line.strip()]
    return {
        "title": normalize_singleline_text(str(event.get("title") or "")),
        "starts_at": str(event.get("starts_at") or ""),
        "ends_at": str(event.get("ends_at") or ""),
        "all_day": bool(event.get("is_all_day")),
        "description": normalize_calendar_description(str(event.get("description") or ""), source_format="auto"),
        "location": normalize_singleline_text(str(event.get("location") or "")),
        "recurrence": recurrence,
    }


@dataclass
class ProviderRuntimeConfig:
    timeout_sec: int
    exchange_tenant_id: str = ""
    exchange_client_id: str = ""
    exchange_client_secret: str = ""
    exchange_user: str = ""
    icloud_user: str = ""
    icloud_app_pw: str = ""
    icloud_principal_path: str = ""
    icloud_target_calendar_display: str = "Kalender"
    google_calendar_id: str = "primary"
    google_oauth_client_id: str = ""
    google_oauth_client_secret: str = ""
    google_oauth_refresh_token: str = ""
    google_service_account_json: str = ""
    google_impersonate_user: str = ""


class SyncJobLogger:
    def __init__(self, repository: AppRepository, job_id: int):
        self.repository = repository
        self.job_id = job_id
        self.has_errors = False

    def info(self, message: str, **data: Any) -> None:
        self.repository.add_sync_log(
            self.job_id,
            level="info",
            provider=str(data.get("provider", "") or ""),
            action=str(data.get("action", "") or ""),
            sync_id=str(data.get("sync_id", "") or ""),
            message=message,
            payload=data,
        )

    def warn(self, message: str, **data: Any) -> None:
        self.repository.add_sync_log(
            self.job_id,
            level="warn",
            provider=str(data.get("provider", "") or ""),
            action=str(data.get("action", "") or ""),
            sync_id=str(data.get("sync_id", "") or ""),
            message=message,
            payload=data,
        )

    def error(self, message: str, **data: Any) -> None:
        self.has_errors = True
        self.repository.add_sync_log(
            self.job_id,
            level="error",
            provider=str(data.get("provider", "") or ""),
            action=str(data.get("action", "") or ""),
            sync_id=str(data.get("sync_id", "") or ""),
            message=message,
            payload=data,
        )

    def action(
        self,
        provider: str,
        action: str,
        sync_id: str,
        detail: str = "",
        *,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        body = dict(payload or {})
        body["detail"] = detail
        if before is not None or after is not None:
            body["before"] = before
            body["after"] = after
            body["changes"] = _build_change_rows(before, after)
        self.repository.add_sync_log(
            self.job_id,
            level="info",
            provider=provider,
            action=action,
            sync_id=sync_id,
            message=detail or action,
            payload=body,
        )


class BaseConnectionAdapter:
    def __init__(self, connection: Dict[str, Any], runtime_cfg: ProviderRuntimeConfig):
        self.connection = connection
        self.runtime_cfg = runtime_cfg

    @property
    def provider(self) -> str:
        return self.connection["provider"]

    def list_events(self, start: datetime, end: datetime, log: SyncJobLogger) -> List[SyncEvent]:
        raise NotImplementedError

    def upsert_event(
        self,
        existing: Optional[SyncEvent],
        desired: SyncEvent,
        sync_id: str,
        source: str,
        mode: str,
        blocked_title: str,
        log: SyncJobLogger,
    ) -> str:
        raise NotImplementedError

    def delete_event(self, event: SyncEvent, sync_id: str, log: SyncJobLogger) -> None:
        raise NotImplementedError


class ExchangeAdapter(BaseConnectionAdapter):
    def __init__(self, connection: Dict[str, Any], runtime_cfg: ProviderRuntimeConfig):
        super().__init__(connection, runtime_cfg)
        self.client = ExchangeClient(runtime_cfg)

    def list_events(self, start: datetime, end: datetime, log: SyncJobLogger) -> List[SyncEvent]:
        return self.client.list_events(start, end, log)

    def upsert_event(
        self,
        existing: Optional[SyncEvent],
        desired: SyncEvent,
        sync_id: str,
        source: str,
        mode: str,
        blocked_title: str,
        log: SyncJobLogger,
    ) -> str:
        return self.client.upsert_event(existing, desired, sync_id, source, mode, blocked_title, False, log)

    def delete_event(self, event: SyncEvent, sync_id: str, log: SyncJobLogger) -> None:
        self.client.delete_event(event, sync_id, False, log)


class ICloudAdapter(BaseConnectionAdapter):
    def __init__(self, connection: Dict[str, Any], runtime_cfg: ProviderRuntimeConfig):
        super().__init__(connection, runtime_cfg)
        self.client = ICloudClient(runtime_cfg)

    def list_events(self, start: datetime, end: datetime, log: SyncJobLogger) -> List[SyncEvent]:
        return self.client.list_events(start, end, log)

    def upsert_event(
        self,
        existing: Optional[SyncEvent],
        desired: SyncEvent,
        sync_id: str,
        source: str,
        mode: str,
        blocked_title: str,
        log: SyncJobLogger,
    ) -> str:
        return self.client.upsert_event(existing, desired, sync_id, source, mode, blocked_title, False, log)

    def delete_event(self, event: SyncEvent, sync_id: str, log: SyncJobLogger) -> None:
        self.client.delete_event(event, sync_id, False, log)


class GoogleAdapter(BaseConnectionAdapter):
    def __init__(self, connection: Dict[str, Any], runtime_cfg: ProviderRuntimeConfig):
        super().__init__(connection, runtime_cfg)
        self.client = GoogleClient(runtime_cfg)

    def list_events(self, start: datetime, end: datetime, log: SyncJobLogger) -> List[SyncEvent]:
        return self.client.list_events(start, end)

    def upsert_event(
        self,
        existing: Optional[SyncEvent],
        desired: SyncEvent,
        sync_id: str,
        source: str,
        mode: str,
        blocked_title: str,
        log: SyncJobLogger,
    ) -> str:
        return self.client.upsert_event(existing, desired, sync_id, source, mode, blocked_title, False, log)

    def delete_event(self, event: SyncEvent, sync_id: str, log: SyncJobLogger) -> None:
        self.client.delete_event(event, sync_id, False, log)


class SyncService:
    def __init__(self, repository: AppRepository, settings: AppSettings):
        self.repository = repository
        self.settings = settings

    def start_user_sync(self, user_id: int, triggered_by: str) -> Tuple[Optional[Dict[str, Any]], bool]:
        stale_before = iso_z(now_utc() - timedelta(minutes=self.settings.sync_job_stale_minutes))
        self.repository.expire_stale_running_sync_jobs(
            user_id,
            stale_before,
            "Recovered stale sync job after timeout",
        )
        try:
            job = self.repository.create_sync_job(user_id, triggered_by, "Manual web sync", status="running")
        except sqlite3.IntegrityError:
            running_job = self.repository.get_running_sync_job(user_id)
            return running_job, False
        return job, True

    def run_sync_job(self, user_id: int, job_id: int) -> Dict[str, Any]:
        job = self.repository.get_sync_job(job_id) or {"id": job_id}
        logger = SyncJobLogger(self.repository, int(job["id"]))
        try:
            self._run_user_sync(user_id, logger)
        except Exception as exc:
            logger.error("sync_failed", error=str(exc))
            return self.repository.finish_sync_job(int(job["id"]), "failed", str(exc)) or job
        if logger.has_errors:
            return self.repository.finish_sync_job(int(job["id"]), "completed_with_errors", "Sync completed with errors") or job
        return self.repository.finish_sync_job(int(job["id"]), "completed", "Sync completed") or job

    def _run_user_sync(self, user_id: int, logger: SyncJobLogger) -> None:
        connections = self.repository.list_active_connections(user_id)
        logger.info("sync_started", connection_count=len(connections))

        start = now_utc() - timedelta(days=1)
        end = now_utc() + timedelta(days=self.settings.sync_window_days)
        adapters: Dict[int, BaseConnectionAdapter] = {}
        remote_events_by_connection: Dict[int, Dict[str, SyncEvent]] = {}

        for connection in connections:
            try:
                adapter = self._build_adapter(connection)
                remote_events = adapter.list_events(start, end, logger)
                adapters[int(connection["id"])] = adapter
                remote_events_by_connection[int(connection["id"])] = {
                    event.provider_id: event for event in remote_events
                }
                logger.info(
                    "provider_fetch_complete",
                    provider=connection["provider"],
                    action="list",
                    detail=f"Fetched {len(remote_events)} events",
                    connection_id=connection["id"],
                )
            except Exception as exc:
                logger.error(
                    "provider_fetch_failed",
                    provider=connection["provider"],
                    action="list",
                    connection_id=connection["id"],
                    error=str(exc),
                )

        for connection in connections:
            adapter = adapters.get(int(connection["id"]))
            if not adapter:
                continue
            remote_events = remote_events_by_connection.get(int(connection["id"]))
            if remote_events is None:
                continue
            self._import_connection_events(
                user_id,
                connection,
                adapter,
                remote_events,
                logger,
                start,
                end,
            )

        for connection in connections:
            adapter = adapters.get(int(connection["id"]))
            if not adapter:
                continue
            remote_events = remote_events_by_connection.get(int(connection["id"]))
            if remote_events is None:
                continue
            self._export_internal_events(
                user_id,
                connection,
                adapter,
                remote_events,
                logger,
                start,
                end,
            )

        logger.info("sync_finished", action="summary", detail="Sync pass finished")

    def _import_connection_events(
        self,
        user_id: int,
        connection: Dict[str, Any],
        adapter: BaseConnectionAdapter,
        remote_events: Dict[str, SyncEvent],
        logger: SyncJobLogger,
        window_start: datetime,
        window_end: datetime,
    ) -> None:
        seen_external_ids = set()
        blocked_title = connection["blocked_title"] or "Blocked"
        now_iso = iso_z(now_utc())

        for remote_event in remote_events.values():
            sync_id = remote_event.sync_id or stable_sync_id(connection["provider"], remote_event.provider_id)
            try:
                remote_event.sync_id = sync_id
                seen_external_ids.add(remote_event.provider_id)
                link = self.repository.get_link_by_connection_and_external_id(int(connection["id"]), remote_event.provider_id)
                event = self.repository.get_internal_event(user_id, int(link["event_id"])) if link else None
                if event is None:
                    event = self.repository.find_internal_event_by_sync_id(user_id, sync_id)
                if connection["provider"] == SOURCE_GOOGLE:
                    skip_reason = google_source_skip_reason(remote_event, blocked_title)
                    if skip_reason == "google-blocked-mirror":
                        if event:
                            self.repository.upsert_event_link(
                                user_id,
                                int(event["id"]),
                                int(connection["id"]),
                                external_event_id=remote_event.provider_id,
                                external_uid=remote_event.uid or "",
                                sync_id=sync_id,
                                source=remote_event.source or connection["provider"],
                                mode=remote_event.mode or MODE_BLOCKED,
                                fingerprint=remote_event.fingerprint(MODE_BLOCKED, blocked_title),
                                last_seen_at=now_iso,
                                last_synced_at=link.get("last_synced_at") if link else None,
                                deleted_at=None,
                                provider_payload=remote_event.raw,
                            )
                            logger.action(connection["provider"], "skipped", sync_id, "google-blocked-mirror-linked")
                        else:
                            logger.action(connection["provider"], "skipped", sync_id, skip_reason)
                        continue

                if event and event.get("deleted_at"):
                    logger.action(connection["provider"], "skipped", sync_id, "internal-deleted")
                    if link:
                        self.repository.upsert_event_link(
                            user_id,
                            int(event["id"]),
                            int(connection["id"]),
                            external_event_id=remote_event.provider_id,
                            external_uid=remote_event.uid or "",
                            sync_id=sync_id,
                            source=remote_event.source or connection["provider"],
                            mode=remote_event.mode or MODE_FULL,
                            fingerprint=remote_event.fingerprint(MODE_FULL, blocked_title),
                            last_seen_at=now_iso,
                            last_synced_at=link.get("last_synced_at"),
                            deleted_at=None,
                            provider_payload=remote_event.raw,
                        )
                    continue

                should_apply = True
                remote_fingerprint = remote_event.fingerprint(MODE_FULL, blocked_title)
                if link and link.get("last_synced_at") and link.get("fingerprint") == remote_fingerprint:
                    remote_modified = remote_event.modified_at
                    last_synced = parse_any_datetime(link.get("last_synced_at"))
                    if remote_modified and last_synced and remote_modified <= last_synced:
                        should_apply = False

                if event and should_apply:
                    internal_updated = parse_any_datetime(event.get("updated_at"))
                    if (
                        remote_event.modified_at
                        and internal_updated
                        and internal_updated > remote_event.modified_at
                        and event.get("source_connection_id") != connection["id"]
                    ):
                        should_apply = False

                if event is None:
                    event = self.repository.create_internal_event(
                        user_id,
                        title=remote_event.title,
                        description=remote_event.description,
                        location=remote_event.location,
                        starts_at=self._internal_start(remote_event),
                        ends_at=self._internal_end(remote_event),
                        is_all_day=bool(remote_event.start.get("all_day")),
                        recurrence_rule="\n".join(remote_event.recurrence or []),
                        source_provider=connection["provider"],
                        source_connection_id=int(connection["id"]),
                        origin_provider=connection["provider"],
                        origin_connection_id=int(connection["id"]),
                        sync_id=sync_id,
                    )
                    logger.action(
                        connection["provider"],
                        "created",
                        sync_id,
                        "imported-into-webapp",
                        before=None,
                        after=_snapshot_internal_event(event),
                    )
                elif should_apply:
                    before_snapshot = _snapshot_internal_event(event)
                    event = self.repository.update_internal_event(
                        user_id,
                        int(event["id"]),
                        title=remote_event.title,
                        description=remote_event.description,
                        location=remote_event.location,
                        starts_at=self._internal_start(remote_event),
                        ends_at=self._internal_end(remote_event),
                        is_all_day=bool(remote_event.start.get("all_day")),
                        recurrence_rule="\n".join(remote_event.recurrence or []),
                        source_provider=connection["provider"],
                        source_connection_id=int(connection["id"]),
                        deleted_at=None,
                    ) or event
                    logger.action(
                        connection["provider"],
                        "updated",
                        sync_id,
                        "imported-into-webapp",
                        before=before_snapshot,
                        after=_snapshot_internal_event(event),
                    )
                else:
                    logger.action(connection["provider"], "skipped", sync_id, "internal-newer")

                self.repository.upsert_event_link(
                    user_id,
                    int(event["id"]),
                    int(connection["id"]),
                    external_event_id=remote_event.provider_id,
                    external_uid=remote_event.uid or "",
                    sync_id=sync_id,
                    source=remote_event.source or connection["provider"],
                    mode=remote_event.mode or MODE_FULL,
                    fingerprint=remote_event.fingerprint(MODE_FULL, blocked_title),
                    last_seen_at=now_iso,
                    last_synced_at=link.get("last_synced_at") if link else None,
                    deleted_at=None,
                    provider_payload=remote_event.raw,
                )
            except Exception as exc:
                logger.error(
                    "provider_import_event_failed",
                    provider=connection["provider"],
                    action="import",
                    sync_id=sync_id,
                    external_event_id=remote_event.provider_id,
                    error=str(exc),
                )

        for link in self.repository.list_links_for_connection(int(connection["id"])):
            if link["external_event_id"] in seen_external_ids:
                continue
            if link.get("deleted_at"):
                continue
            event = self.repository.get_internal_event(user_id, int(link["event_id"]))
            if event and not self._is_internal_event_in_window(event, window_start, window_end):
                continue
            try:
                self.repository.mark_link_deleted(int(link["id"]))
                logger.action(connection["provider"], "deleted", link["sync_id"], "missing-from-provider")

                if not event:
                    continue
                if self._should_delete_internal_event_for_missing_link(event, link, connection):
                    before_snapshot = _snapshot_internal_event(event)
                    self.repository.soft_delete_internal_event(user_id, int(event["id"]))
                    logger.action(
                        "webapp",
                        "deleted",
                        event["sync_id"],
                        "provider-delete-propagated",
                        before=before_snapshot,
                        after=None,
                        payload={
                            "missing_provider": connection["provider"],
                            "connection_id": connection["id"],
                        },
                    )
                else:
                    logger.action(
                        connection["provider"],
                        "skipped",
                        link["sync_id"],
                        "missing-provider-preserved-newer-change",
                    )
            except Exception as exc:
                logger.error(
                    "provider_missing_link_cleanup_failed",
                    provider=connection["provider"],
                    action="delete",
                    sync_id=link["sync_id"],
                    external_event_id=link["external_event_id"],
                    error=str(exc),
                )

    @staticmethod
    def _find_matching_remote_event(
        desired: SyncEvent,
        remote_events: Dict[str, SyncEvent],
        blocked_title: str,
        mode: str,
        claimed_ids: Optional[set] = None,
    ) -> Optional[SyncEvent]:
        """Find a remote event that matches `desired` by content.

        This prevents creating a duplicate when the same real-world event
        already exists natively in the target calendar (e.g. Google) and was
        also imported from another provider (Exchange/iCloud).
        """
        claimed = claimed_ids or set()
        d_start = desired.start.get("dateTime") or desired.start.get("date") or ""
        d_end = desired.end.get("dateTime") or desired.end.get("date") or ""
        if not d_start or not d_end:
            return None
        desired_fingerprint = desired.fingerprint(mode, blocked_title)
        for provider_id, remote in remote_events.items():
            if provider_id in claimed:
                continue
            r_start = remote.start.get("dateTime") or remote.start.get("date") or ""
            r_end = remote.end.get("dateTime") or remote.end.get("date") or ""
            if r_start != d_start or r_end != d_end:
                continue
            if remote.fingerprint(mode, blocked_title) == desired_fingerprint:
                return remote
        return None

    @staticmethod
    def _remember_exported_remote_event(
        remote_events: Dict[str, SyncEvent],
        connection: Dict[str, Any],
        desired: SyncEvent,
        provider_id: str,
        sync_id: str,
        mode: str,
    ) -> None:
        remote_events[provider_id] = SyncEvent(
            provider=connection["provider"],
            provider_id=provider_id,
            title=desired.title,
            description=desired.description,
            location=desired.location,
            start=dict(desired.start),
            end=dict(desired.end),
            recurrence=list(desired.recurrence or []),
            sync_id=sync_id,
            source=SOURCE_WEBAPP,
            mode=mode,
            modified_at=now_utc(),
            href=provider_id if connection["provider"] == SOURCE_ICLOUD else None,
            raw={"id": provider_id},
        )

    def _export_internal_events(
        self,
        user_id: int,
        connection: Dict[str, Any],
        adapter: BaseConnectionAdapter,
        remote_events: Dict[str, SyncEvent],
        logger: SyncJobLogger,
        window_start: datetime,
        window_end: datetime,
    ) -> None:
        blocked_title = connection["blocked_title"] or "Blocked"
        now_iso = iso_z(now_utc())
        # Pre-populate with remote IDs already linked via import so that
        # content-matching cannot steal them for a different internal event.
        claimed_remote_ids: set = {
            link["external_event_id"]
            for link in self.repository.list_links_for_connection(int(connection["id"]))
            if link.get("external_event_id")
        }

        for event in self.repository.list_internal_events(user_id, include_deleted=True):
            if not event.get("deleted_at") and not self._is_internal_event_in_window(event, window_start, window_end):
                continue
            sync_id = event["sync_id"]
            try:
                link = self.repository.get_link_by_event_and_connection(int(event["id"]), int(connection["id"]))
                existing = remote_events.get(link["external_event_id"]) if link else None

                if existing is None and link is None:
                    mode = self._event_mode_for_connection(connection, event, link)
                    desired_preview = self._internal_to_sync_event(connection["provider"], event)
                    matched = self._find_matching_remote_event(
                        desired_preview,
                        remote_events,
                        blocked_title,
                        mode,
                    )
                    if matched:
                        if matched.provider_id in claimed_remote_ids:
                            # Same time slot is already covered by another
                            # internal event's link — skip to avoid duplicate.
                            logger.action(
                                connection["provider"], "skipped", sync_id,
                                "duplicate-time-slot-covered",
                            )
                            continue
                        existing = matched
                        logger.action(
                            connection["provider"], "skipped", sync_id,
                            "content-matched-existing",
                        )

                if existing:
                    claimed_remote_ids.add(existing.provider_id)

                if event.get("deleted_at"):
                    if link and not link.get("deleted_at"):
                        remote_placeholder = existing or self._placeholder_remote_event(connection["provider"], link)
                        adapter.delete_event(remote_placeholder, sync_id, logger)
                        self.repository.mark_link_deleted(int(link["id"]))
                    continue

                mode = self._event_mode_for_connection(connection, event, link)
                desired = self._internal_to_sync_event(connection["provider"], event)
                provider_id = adapter.upsert_event(
                    existing=existing,
                    desired=desired,
                    sync_id=sync_id,
                    source=SOURCE_WEBAPP,
                    mode=mode,
                    blocked_title=blocked_title,
                    log=logger,
                )
                claimed_remote_ids.add(provider_id)
                self._remember_exported_remote_event(
                    remote_events,
                    connection,
                    desired,
                    provider_id,
                    sync_id,
                    mode,
                )

                payload = existing.raw if existing else {}
                self.repository.upsert_event_link(
                    user_id,
                    int(event["id"]),
                    int(connection["id"]),
                    external_event_id=provider_id,
                    external_uid=str(existing.uid or "") if existing else "",
                    sync_id=sync_id,
                    source=SOURCE_WEBAPP,
                    mode=mode,
                    fingerprint=desired.fingerprint(mode, blocked_title),
                    last_seen_at=now_iso,
                    last_synced_at=now_iso,
                    deleted_at=None,
                    provider_payload=payload,
                )
            except Exception as exc:
                logger.error(
                    "provider_export_event_failed",
                    provider=connection["provider"],
                    action="export",
                    sync_id=sync_id,
                    event_id=event["id"],
                    error=str(exc),
                )

    def _build_adapter(self, connection: Dict[str, Any]) -> BaseConnectionAdapter:
        runtime_cfg = self._build_runtime_config(connection)
        provider = connection["provider"]
        if provider == SOURCE_EXCHANGE:
            self._require_settings(connection, ["exchange_tenant_id", "exchange_client_id", "exchange_client_secret", "exchange_user"])
            return ExchangeAdapter(connection, runtime_cfg)
        if provider == SOURCE_ICLOUD:
            self._require_settings(connection, ["icloud_user", "icloud_app_pw", "icloud_principal_path"])
            return ICloudAdapter(connection, runtime_cfg)
        if provider == SOURCE_GOOGLE:
            self._require_google_settings(connection)
            return GoogleAdapter(connection, runtime_cfg)
        raise RuntimeError(f"unsupported provider: {provider}")

    def _build_runtime_config(self, connection: Dict[str, Any]) -> ProviderRuntimeConfig:
        settings = connection["settings"]
        return ProviderRuntimeConfig(
            timeout_sec=int(settings.get("timeout_sec", self.settings.provider_timeout_sec)),
            exchange_tenant_id=str(settings.get("exchange_tenant_id", "")),
            exchange_client_id=str(settings.get("exchange_client_id", "")),
            exchange_client_secret=str(settings.get("exchange_client_secret", "")),
            exchange_user=str(settings.get("exchange_user", "")),
            icloud_user=str(settings.get("icloud_user", "")),
            icloud_app_pw=str(settings.get("icloud_app_pw", "")),
            icloud_principal_path=str(settings.get("icloud_principal_path", "")),
            icloud_target_calendar_display=str(settings.get("icloud_target_calendar_display", "Kalender")),
            google_calendar_id=str(settings.get("google_calendar_id", "primary")),
            google_oauth_client_id=str(settings.get("google_oauth_client_id", "")),
            google_oauth_client_secret=str(settings.get("google_oauth_client_secret", "")),
            google_oauth_refresh_token=str(settings.get("google_oauth_refresh_token", "")),
            google_service_account_json=str(settings.get("google_service_account_json", "")),
            google_impersonate_user=str(settings.get("google_impersonate_user", "")),
        )

    def _require_settings(self, connection: Dict[str, Any], required_keys: List[str]) -> None:
        settings = connection["settings"]
        missing = [key for key in required_keys if not settings.get(key)]
        if missing:
            raise RuntimeError("missing connection settings: " + ", ".join(missing))

    def _require_google_settings(self, connection: Dict[str, Any]) -> None:
        settings = connection["settings"]
        oauth_ready = all(
            [
                settings.get("google_oauth_client_id"),
                settings.get("google_oauth_client_secret"),
                settings.get("google_oauth_refresh_token"),
            ]
        )
        service_ready = bool(settings.get("google_service_account_json"))
        if not (oauth_ready or service_ready):
            raise RuntimeError("missing google auth settings")

    def _mode_for_connection(self, connection: Dict[str, Any]) -> str:
        if connection["provider"] == SOURCE_GOOGLE:
            return MODE_BLOCKED
        return MODE_FULL

    def _event_mode_for_connection(
        self,
        connection: Dict[str, Any],
        event: Dict[str, Any],
        link: Optional[Dict[str, Any]],
    ) -> str:
        if connection["provider"] != SOURCE_GOOGLE:
            return MODE_FULL

        linked_mode = str((link or {}).get("mode") or "").strip().lower()
        if linked_mode in {MODE_FULL, MODE_BLOCKED}:
            return linked_mode

        if int(event.get("origin_connection_id") or 0) == int(connection["id"]):
            return MODE_FULL
        if str(event.get("origin_provider") or "").strip().lower() == SOURCE_GOOGLE:
            return MODE_FULL
        return MODE_BLOCKED

    def _internal_to_sync_event(self, provider: str, event: Dict[str, Any]) -> SyncEvent:
        if event["is_all_day"]:
            start = {"all_day": True, "date": event["starts_at"][:10]}
            end = {"all_day": True, "date": event["ends_at"][:10]}
        else:
            start = {"all_day": False, "dateTime": event["starts_at"]}
            end = {"all_day": False, "dateTime": event["ends_at"]}
        recurrence = [line for line in str(event.get("recurrence_rule", "") or "").splitlines() if line.strip()]
        return SyncEvent(
            provider=provider,
            provider_id=str(event["id"]),
            title=normalize_singleline_text(str(event["title"])),
            description=normalize_calendar_description(str(event.get("description") or ""), source_format="auto"),
            location=normalize_singleline_text(str(event.get("location") or "")),
            start=start,
            end=end,
            recurrence=recurrence,
            sync_id=event["sync_id"],
            source=SOURCE_WEBAPP,
            mode=MODE_FULL,
            modified_at=parse_any_datetime(event.get("updated_at")),
        )

    def _internal_start(self, event: SyncEvent) -> str:
        if event.start.get("all_day"):
            return f"{event.start['date']}T00:00:00Z"
        return event.start["dateTime"]

    def _internal_end(self, event: SyncEvent) -> str:
        if event.end.get("all_day"):
            return f"{event.end['date']}T00:00:00Z"
        return event.end["dateTime"]

    def _is_internal_event_in_window(self, event: Dict[str, Any], start: datetime, end: datetime) -> bool:
        starts_at = parse_any_datetime(event.get("starts_at"))
        ends_at = parse_any_datetime(event.get("ends_at")) or starts_at
        if not starts_at or not ends_at:
            return True
        return ends_at >= start and starts_at <= end

    def _should_delete_internal_event_for_missing_link(
        self,
        event: Dict[str, Any],
        link: Dict[str, Any],
        connection: Dict[str, Any],
    ) -> bool:
        if event.get("deleted_at"):
            return False

        missing_connection_id = int(connection["id"])
        if int(event.get("source_connection_id") or 0) == missing_connection_id:
            return True
        if int(event.get("origin_connection_id") or 0) == missing_connection_id:
            return True

        event_updated = parse_any_datetime(event.get("updated_at"))
        reference_time = self._missing_link_reference_time(link)
        if not event_updated or not reference_time:
            return True
        return event_updated <= reference_time

    def _missing_link_reference_time(self, link: Dict[str, Any]) -> Optional[datetime]:
        last_seen = parse_any_datetime(link.get("last_seen_at"))
        last_synced = parse_any_datetime(link.get("last_synced_at"))
        if last_seen and last_synced:
            return max(last_seen, last_synced)
        return last_seen or last_synced

    def _placeholder_remote_event(self, provider: str, link: Dict[str, Any]) -> SyncEvent:
        payload = link.get("provider_payload") or {}
        uid = ""
        if isinstance(payload, dict):
            uid = str(payload.get("uid") or payload.get("UID") or "")
            if provider == SOURCE_ICLOUD and "ics" in payload:
                uid = uid or ""
        return SyncEvent(
            provider=provider,
            provider_id=str(link["external_event_id"]),
            title="",
            description="",
            location="",
            start={"all_day": False, "dateTime": iso_z(datetime(1970, 1, 1, tzinfo=UTC))},
            end={"all_day": False, "dateTime": iso_z(datetime(1970, 1, 1, tzinfo=UTC))},
            sync_id=link["sync_id"],
            uid=uid or None,
            href=str(link["external_event_id"]) if provider == SOURCE_ICLOUD else None,
            raw=payload if isinstance(payload, dict) else {"payload": json.dumps(payload)},
        )
