import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

import sync_exchange_icloud_calendar as mod


class CalendarSyncLogicTests(unittest.TestCase):
    def test_datetime_normalization_handles_offsets_and_tzid(self) -> None:
        self.assertEqual(
            mod.normalize_google_dt({"dateTime": "2026-03-07T10:00:00+02:00"}),
            {"all_day": False, "dateTime": "2026-03-07T08:00:00Z"},
        )
        self.assertEqual(
            mod.dt_ics_to_normalized("20260307T100000", "TZID=Europe/Berlin"),
            {"all_day": False, "dateTime": "2026-03-07T09:00:00Z"},
        )

    def test_reconcile_orphaned_events_reuses_known_sync_id(self) -> None:
        state = mod.SyncState(Path(tempfile.mkdtemp()) / "state.json")
        log = mod.Logger()

        known = mod.SyncEvent(
            provider=mod.SOURCE_EXCHANGE,
            provider_id="ex-1",
            title="Meeting",
            start={"all_day": False, "dateTime": "2026-03-10T09:00:00Z"},
            end={"all_day": False, "dateTime": "2026-03-10T10:00:00Z"},
            description="Agenda",
            location="Room",
            sync_id="sync-known",
            sync_origin=mod.SYNC_ORIGIN_METADATA,
        )
        orphan = mod.SyncEvent(
            provider=mod.SOURCE_ICLOUD,
            provider_id="/calendar/orphan.ics",
            title="Meeting",
            start={"all_day": False, "dateTime": "2026-03-10T09:00:00Z"},
            end={"all_day": False, "dateTime": "2026-03-10T10:00:00Z"},
            description="Agenda",
            location="Room",
            sync_id="sync-stable",
            sync_origin=mod.SYNC_ORIGIN_STABLE,
        )
        by_provider = {
            mod.SOURCE_EXCHANGE: [known],
            mod.SOURCE_ICLOUD: [orphan],
            mod.SOURCE_GOOGLE: [],
        }

        mod.reconcile_orphaned_events(
            by_provider=by_provider,
            enabled_providers=[mod.SOURCE_EXCHANGE, mod.SOURCE_ICLOUD],
            state=state,
            blocked_title="Blocked",
            log=log,
        )

        self.assertEqual(orphan.sync_id, "sync-known")
        self.assertEqual(orphan.sync_origin, mod.SYNC_ORIGIN_MATCHED)

    def test_infer_group_delete_reason_when_source_missing(self) -> None:
        state = mod.SyncState(Path(tempfile.mkdtemp()) / "state.json")
        sync_id = "sync-delete"
        current = mod.SyncEvent(
            provider=mod.SOURCE_ICLOUD,
            provider_id="/calendar/event.ics",
            title="Meeting",
            start={"all_day": False, "dateTime": "2026-03-10T09:00:00Z"},
            end={"all_day": False, "dateTime": "2026-03-10T10:00:00Z"},
            description="Agenda",
            location="Room",
            sync_id=sync_id,
        )
        fingerprint = current.fingerprint(mod.MODE_FULL, "Blocked")
        state.set_provider_record(
            sync_id=sync_id,
            provider=mod.SOURCE_EXCHANGE,
            provider_id="ex-1",
            fingerprint=fingerprint,
            source=mod.SOURCE_EXCHANGE,
            mode=mod.MODE_FULL,
            modified_at=datetime.now(UTC),
        )
        state.set_provider_record(
            sync_id=sync_id,
            provider=mod.SOURCE_ICLOUD,
            provider_id=current.provider_id,
            fingerprint=fingerprint,
            source=mod.SOURCE_EXCHANGE,
            mode=mod.MODE_FULL,
            modified_at=datetime.now(UTC),
        )

        reason = mod.infer_group_delete_reason(
            sync_id=sync_id,
            current_by_provider={
                mod.SOURCE_EXCHANGE: None,
                mod.SOURCE_ICLOUD: current,
            },
            state=state,
            blocked_title="Blocked",
        )

        self.assertIsNotNone(reason)
        assert reason is not None
        self.assertTrue(reason.startswith("source-deleted:"))

    def test_sync_three_way_propagates_delete(self) -> None:
        state_path = Path(tempfile.mkdtemp()) / "state.json"
        cfg = mod.Config(
            exchange_tenant_id="tenant",
            exchange_client_id="client",
            exchange_client_secret="secret",
            exchange_user="user@example.com",
            icloud_user="icloud@example.com",
            icloud_app_pw="pw",
            icloud_principal_path="/principal/",
            icloud_target_calendar_display="Kalender",
            google_enabled=False,
            google_calendar_id="primary",
            google_blocked_title="Blocked",
            google_oauth_client_id="",
            google_oauth_client_secret="",
            google_oauth_refresh_token="",
            google_service_account_json="",
            google_impersonate_user="",
            state_path=state_path,
            dry_run=False,
            window_days=30,
            timeout_sec=5,
        )

        sync_id = "sync-1"
        exchange_event = mod.SyncEvent(
            provider=mod.SOURCE_EXCHANGE,
            provider_id="ex-1",
            title="Meeting",
            start={"all_day": False, "dateTime": "2026-03-10T09:00:00Z"},
            end={"all_day": False, "dateTime": "2026-03-10T10:00:00Z"},
            description="Agenda",
            location="Room",
            sync_id=sync_id,
            sync_origin=mod.SYNC_ORIGIN_METADATA,
            source=mod.SOURCE_EXCHANGE,
            mode=mod.MODE_FULL,
        )
        icloud_event = mod.SyncEvent(
            provider=mod.SOURCE_ICLOUD,
            provider_id="/calendar/event.ics",
            title="Meeting",
            start={"all_day": False, "dateTime": "2026-03-10T09:00:00Z"},
            end={"all_day": False, "dateTime": "2026-03-10T10:00:00Z"},
            description="Agenda",
            location="Room",
            sync_id=sync_id,
            sync_origin=mod.SYNC_ORIGIN_METADATA,
            source=mod.SOURCE_EXCHANGE,
            mode=mod.MODE_FULL,
            href="/calendar/event.ics",
        )

        datasets = {
            "exchange": [exchange_event],
            "icloud": [icloud_event],
        }
        actions = []

        class FakeExchange:
            def __init__(self, cfg: mod.Config) -> None:
                self.cfg = cfg

            def list_events(self, start: datetime, end: datetime, log: mod.Logger):
                return list(datasets["exchange"])

            def upsert_event(self, existing, desired, sync_id, source, mode, blocked_title, dry_run, log):
                actions.append(("exchange_upsert", sync_id, existing.provider_id if existing else None))
                return existing.provider_id if existing else "new-ex"

            def delete_event(self, event, sync_id, dry_run, log, detail=""):
                actions.append(("exchange_delete", sync_id, event.provider_id, detail))

        class FakeICloud:
            def __init__(self, cfg: mod.Config) -> None:
                self.cfg = cfg

            def list_events(self, start: datetime, end: datetime, log: mod.Logger):
                return list(datasets["icloud"])

            def upsert_event(self, existing, desired, sync_id, source, mode, blocked_title, dry_run, log):
                actions.append(("icloud_upsert", sync_id, existing.provider_id if existing else None))
                return existing.provider_id if existing else "/calendar/new.ics"

            def delete_event(self, event, sync_id, dry_run, log, detail=""):
                actions.append(("icloud_delete", sync_id, event.provider_id, detail))

        orig_exchange = mod.ExchangeClient
        orig_icloud = mod.ICloudClient
        mod.ExchangeClient = FakeExchange
        mod.ICloudClient = FakeICloud
        try:
            mod.sync_three_way(cfg, dry_run=False, window_days=30)

            actions.clear()
            datasets["exchange"] = []
            datasets["icloud"] = [icloud_event]
            mod.sync_three_way(cfg, dry_run=False, window_days=30)
        finally:
            mod.ExchangeClient = orig_exchange
            mod.ICloudClient = orig_icloud

        self.assertTrue(any(action[0] == "icloud_delete" and action[1] == sync_id for action in actions), actions)


if __name__ == "__main__":
    unittest.main()
