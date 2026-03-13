import json
import tempfile
import time
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock, patch

import requests
import sync_exchange_icloud_calendar as mod


class CalendarSyncLogicTests(unittest.TestCase):
    def make_cfg(self) -> mod.Config:
        return mod.Config(
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
            state_path=Path(tempfile.mkdtemp()) / "state.json",
            dry_run=False,
            window_days=30,
            timeout_sec=5,
            write_delay_ms=0,
            max_writes_per_run=500,
            write_backoff_enabled=False,
            write_backoff_base_ms=100,
            write_backoff_max_ms=1000,
        )

    def test_normalize_calendar_description_removes_exchange_html_wrapper(self) -> None:
        raw = (
            '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head>'
            '<body>Hotel &amp;amp; Flug<br>Tag&nbsp;2</body></html>'
        )
        self.assertEqual(mod.normalize_calendar_description(raw, source_format="html"), "Hotel & Flug\nTag 2")

    def test_sync_event_fingerprint_matches_plain_text_and_html_wrapped_description(self) -> None:
        html_event = mod.SyncEvent(
            provider=mod.SOURCE_EXCHANGE,
            provider_id="ex-1",
            title="Trip",
            start={"all_day": False, "dateTime": "2026-03-10T09:00:00Z"},
            end={"all_day": False, "dateTime": "2026-03-10T10:00:00Z"},
            description="<html><body>Hotel &amp;amp; Flug<br>Tag 2</body></html>",
            location="Room",
        )
        plain_event = mod.SyncEvent(
            provider=mod.SOURCE_ICLOUD,
            provider_id="/calendar/event.ics",
            title="Trip",
            start={"all_day": False, "dateTime": "2026-03-10T09:00:00Z"},
            end={"all_day": False, "dateTime": "2026-03-10T10:00:00Z"},
            description="Hotel & Flug\nTag 2",
            location="Room",
        )
        self.assertEqual(
            html_event.fingerprint(mod.MODE_FULL, "Blocked"),
            plain_event.fingerprint(mod.MODE_FULL, "Blocked"),
        )

    def test_normalize_calendar_description_removes_legacy_sync_markers(self) -> None:
        raw = (
            '<html><body>&lt;html&gt;&lt;body&gt;AETHER_SYNC_SRC:EXCHANGE&lt;br&gt;'
            'SOURCE_ID:abc123&lt;/body&gt;&lt;/html&gt;</body></html>'
        )
        self.assertEqual(mod.normalize_calendar_description(raw, source_format="auto"), "")

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

    def test_icloud_request_retries_transient_503(self) -> None:
        client = mod.ICloudClient(self.make_cfg())
        first = Mock(status_code=503)
        first.raise_for_status.side_effect = None
        second = Mock(status_code=207)
        second.raise_for_status.side_effect = None
        log = mod.Logger()

        with patch.object(mod.requests, "request", side_effect=[first, second]) as request_mock:
            with patch.object(mod.time, "sleep", return_value=None) as sleep_mock:
                response = client._request_with_retry("REPORT", "https://example.test/caldav", log=log, operation="list-events")

        self.assertIs(response, second)
        self.assertEqual(request_mock.call_count, 2)
        sleep_mock.assert_called_once()

    def test_exchange_list_events_reads_all_editable_calendars(self) -> None:
        client = mod.ExchangeClient(self.make_cfg())
        client._token = "token"
        log = mod.Logger()

        calendars_response = Mock(status_code=200)
        calendars_response.raise_for_status.side_effect = None
        calendars_response.json.return_value = {
            "value": [
                {"id": "default-cal", "name": "Kalender", "isDefaultCalendar": True, "canEdit": True},
                {"id": "team-cal", "name": "Team", "isDefaultCalendar": False, "canEdit": True},
                {"id": "birthdays", "name": "Geburtstage", "isDefaultCalendar": False, "canEdit": False},
            ]
        }
        default_view_response = Mock(status_code=200)
        default_view_response.raise_for_status.side_effect = None
        default_view_response.json.return_value = {"value": []}
        team_view_response = Mock(status_code=200)
        team_view_response.raise_for_status.side_effect = None
        team_view_response.json.return_value = {
            "value": [
                {
                    "id": "event-team-1",
                    "subject": "Manuell in Team-Kalender",
                    "start": {"dateTime": "2026-04-05T10:00:00.0000000", "timeZone": "UTC"},
                    "end": {"dateTime": "2026-04-05T11:00:00.0000000", "timeZone": "UTC"},
                    "isAllDay": False,
                    "lastModifiedDateTime": "2026-03-10T10:00:00Z",
                    "body": {"contentType": "text", "content": "Beschreibung"},
                    "location": {"displayName": "Raum A"},
                    "recurrence": None,
                }
            ]
        }

        with patch.object(
            mod.requests,
            "get",
            side_effect=[calendars_response, default_view_response, team_view_response],
        ) as get_mock:
            events = client.list_events(
                datetime(2026, 4, 5, 0, 0, tzinfo=UTC),
                datetime(2026, 4, 6, 0, 0, tzinfo=UTC),
                log,
            )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].title, "Manuell in Team-Kalender")
        self.assertEqual(events[0].raw.get("calendarName"), "Team")
        called_urls = [call.args[0] for call in get_mock.call_args_list]
        self.assertIn("/users/user@example.com/calendars", called_urls[0])
        self.assertIn("/users/user@example.com/calendars/default-cal/calendarView", called_urls[1])
        self.assertIn("/users/user@example.com/calendars/team-cal/calendarView", called_urls[2])

    def test_google_upsert_recreates_event_when_time_model_changes(self) -> None:
        cfg = self.make_cfg()
        cfg.google_enabled = True
        client = mod.GoogleClient(cfg)
        client._token = "token"
        log = mod.Logger()

        existing = mod.SyncEvent(
            provider=mod.SOURCE_GOOGLE,
            provider_id="google-old",
            title="Urlaub",
            start={"all_day": False, "dateTime": "2026-03-05T00:00:00Z"},
            end={"all_day": False, "dateTime": "2026-03-13T00:00:00Z"},
            sync_id="sync-urlaub",
            source=mod.SOURCE_ICLOUD,
            mode=mod.MODE_BLOCKED,
        )
        desired = mod.SyncEvent(
            provider=mod.SOURCE_ICLOUD,
            provider_id="icloud-1",
            title="Urlaub",
            start={"all_day": True, "date": "2026-03-05"},
            end={"all_day": True, "date": "2026-03-13"},
            sync_id="sync-urlaub",
            source=mod.SOURCE_ICLOUD,
            mode=mod.MODE_BLOCKED,
        )

        delete_response = Mock(status_code=204)
        delete_response.raise_for_status.side_effect = None
        create_response = Mock(status_code=200)
        create_response.raise_for_status.side_effect = None
        create_response.json.return_value = {"id": "google-new"}

        with patch.object(mod.requests, "delete", return_value=delete_response) as delete_mock:
            with patch.object(mod.requests, "post", return_value=create_response) as post_mock:
                with patch.object(mod.requests, "patch") as patch_mock:
                    new_id = client.upsert_event(
                        existing=existing,
                        desired=desired,
                        sync_id="sync-urlaub",
                        source=mod.SOURCE_ICLOUD,
                        mode=mod.MODE_BLOCKED,
                        blocked_title="Blocked",
                        dry_run=False,
                        log=log,
                    )

        self.assertEqual(new_id, "google-new")
        delete_mock.assert_called_once()
        post_mock.assert_called_once()
        patch_mock.assert_not_called()
        payload = json.loads(post_mock.call_args.kwargs["data"])
        self.assertEqual(payload["start"], {"date": "2026-03-05"})
        self.assertEqual(payload["end"], {"date": "2026-03-13"})
        self.assertEqual(payload["summary"], "Blocked")

    def test_google_token_refresh_error_surfaces_google_reason(self) -> None:
        cfg = self.make_cfg()
        cfg.google_enabled = True
        cfg.google_oauth_client_id = "client-id"
        cfg.google_oauth_client_secret = "client-secret"
        cfg.google_oauth_refresh_token = "refresh-token"
        client = mod.GoogleClient(cfg)

        response = Mock(status_code=400, text='{"error":"invalid_grant"}')
        response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Token has been expired or revoked.",
        }

        with patch.object(mod.requests, "post", return_value=response):
            with self.assertRaises(RuntimeError) as exc_info:
                client._token_from_refresh()

        self.assertIn("invalid_grant", str(exc_info.exception))
        self.assertIn("expired or revoked", str(exc_info.exception))

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

    def test_execute_provider_write_continues_after_http_error_and_throttles(self) -> None:
        state = mod.SyncState(Path(tempfile.mkdtemp()) / "state.json")
        log = mod.Logger()
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
            state_path=Path(tempfile.mkdtemp()) / "state2.json",
            dry_run=False,
            window_days=30,
            timeout_sec=5,
            write_delay_ms=60,
            max_writes_per_run=10,
            write_backoff_enabled=False,
            write_backoff_base_ms=10,
            write_backoff_max_ms=50,
        )

        desired = mod.SyncEvent(
            provider=mod.SOURCE_EXCHANGE,
            provider_id="ex-1",
            title="Meeting",
            start={"all_day": False, "dateTime": "2026-03-10T09:00:00Z"},
            end={"all_day": False, "dateTime": "2026-03-10T10:00:00Z"},
        )

        response = requests.Response()
        response.status_code = 507
        response._content = b'{"error":{"code":"InsufficientStorage","message":"quota"}}'
        err = requests.HTTPError("507", response=response)

        write_index = 0
        _, write_index = mod.execute_provider_write(
            provider=mod.SOURCE_ICLOUD,
            sync_id="sync-1",
            cfg=cfg,
            state=state,
            log=log,
            dry_run=False,
            write_index=write_index,
            op_label="upsert",
            fn=lambda: (_ for _ in ()).throw(err),
            desired=desired,
            source=mod.SOURCE_EXCHANGE,
            mode=mod.MODE_FULL,
        )

        self.assertEqual(write_index, 1)
        self.assertEqual(log.stats.get("icloud_errors", 0), 1)
        self.assertIsNotNone(state.get_retry_entry("sync-1", mod.SOURCE_ICLOUD))

        t0 = time.monotonic()
        result, write_index = mod.execute_provider_write(
            provider=mod.SOURCE_EXCHANGE,
            sync_id="sync-1",
            cfg=cfg,
            state=state,
            log=log,
            dry_run=False,
            write_index=write_index,
            op_label="upsert",
            fn=lambda: "ex-ok",
            desired=desired,
            source=mod.SOURCE_EXCHANGE,
            mode=mod.MODE_FULL,
        )
        elapsed = time.monotonic() - t0

        self.assertEqual(result, "ex-ok")
        self.assertEqual(write_index, 2)
        self.assertGreaterEqual(elapsed, 0.05)

    def test_execute_provider_write_dry_run_honors_cap(self) -> None:
        state = mod.SyncState(Path(tempfile.mkdtemp()) / "state.json")
        log = mod.Logger()
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
            state_path=Path(tempfile.mkdtemp()) / "state3.json",
            dry_run=True,
            window_days=30,
            timeout_sec=5,
            write_delay_ms=0,
            max_writes_per_run=1,
            write_backoff_enabled=False,
            write_backoff_base_ms=10,
            write_backoff_max_ms=50,
        )

        desired = mod.SyncEvent(
            provider=mod.SOURCE_EXCHANGE,
            provider_id="ex-1",
            title="Meeting",
            start={"all_day": False, "dateTime": "2026-03-10T09:00:00Z"},
            end={"all_day": False, "dateTime": "2026-03-10T10:00:00Z"},
        )

        write_index = 0
        first, write_index = mod.execute_provider_write(
            provider=mod.SOURCE_EXCHANGE,
            sync_id="sync-cap",
            cfg=cfg,
            state=state,
            log=log,
            dry_run=True,
            write_index=write_index,
            op_label="upsert",
            fn=lambda: "ok-1",
            desired=desired,
            source=mod.SOURCE_EXCHANGE,
            mode=mod.MODE_FULL,
        )
        second, write_index = mod.execute_provider_write(
            provider=mod.SOURCE_ICLOUD,
            sync_id="sync-cap",
            cfg=cfg,
            state=state,
            log=log,
            dry_run=True,
            write_index=write_index,
            op_label="upsert",
            fn=lambda: "ok-2",
            desired=desired,
            source=mod.SOURCE_EXCHANGE,
            mode=mod.MODE_FULL,
        )

        self.assertEqual(first, "ok-1")
        self.assertIsNone(second)
        self.assertEqual(log.stats.get("write_cap_skipped", 0), 1)

    def test_sync_three_way_propagates_delete(self) -> None:
        cfg = self.make_cfg()

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
