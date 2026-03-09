import base64
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

from sync_exchange_icloud_calendar import SyncEvent
from webapp.config import AppSettings
from webapp.database import Database
from webapp.repository import AppRepository
from webapp.security import CRYPTOGRAPHY_AVAILABLE, PasswordHasher, SecretBox, SessionManager, validate_password_policy
from webapp.sync_service import BaseConnectionAdapter, SyncJobLogger, SyncService

try:
    from fastapi.testclient import TestClient

    from webapp.main import create_app

    FASTAPI_AVAILABLE = True
except ModuleNotFoundError:
    FASTAPI_AVAILABLE = False


TEST_DATA_KEY = base64.urlsafe_b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii")


class FakeConnectionAdapter(BaseConnectionAdapter):
    def __init__(
        self,
        connection: Dict[str, Any],
        runtime_cfg: Any,
        remote_events: List[SyncEvent],
    ):
        super().__init__(connection, runtime_cfg)
        self.remote_events = remote_events
        self.deleted_provider_ids: List[str] = []
        self.upserted_provider_ids: List[str | None] = []
        self.upsert_calls: List[Dict[str, Any]] = []

    def list_events(self, start: Any, end: Any, log: SyncJobLogger) -> List[SyncEvent]:
        return list(self.remote_events)

    def upsert_event(
        self,
        existing: SyncEvent | None,
        desired: SyncEvent,
        sync_id: str,
        source: str,
        mode: str,
        blocked_title: str,
        log: SyncJobLogger,
    ) -> str:
        self.upserted_provider_ids.append(existing.provider_id if existing else None)
        self.upsert_calls.append(
            {
                "existing_provider_id": existing.provider_id if existing else None,
                "desired_title": desired.title,
                "desired_description": desired.description,
                "desired_location": desired.location,
                "mode": mode,
                "source": source,
            }
        )
        return existing.provider_id if existing else f"created-{sync_id}"

    def delete_event(self, event: SyncEvent, sync_id: str, log: SyncJobLogger) -> None:
        self.deleted_provider_ids.append(event.provider_id)


class FailingConnectionAdapter(FakeConnectionAdapter):
    def upsert_event(
        self,
        existing: SyncEvent | None,
        desired: SyncEvent,
        sync_id: str,
        source: str,
        mode: str,
        blocked_title: str,
        log: SyncJobLogger,
    ) -> str:
        raise RuntimeError("transient adapter failure")


class FakeSyncService(SyncService):
    def __init__(self, repository: AppRepository, settings: AppSettings, adapters_by_connection_id: Dict[int, BaseConnectionAdapter]):
        super().__init__(repository, settings)
        self.adapters_by_connection_id = adapters_by_connection_id

    def _build_adapter(self, connection: Dict[str, Any]) -> BaseConnectionAdapter:
        return self.adapters_by_connection_id[int(connection["id"])]


class WebappCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database = Database(Path(tempfile.mkdtemp()) / "webapp.sqlite3")
        self.database.initialize()
        self.repository = AppRepository(self.database)

    def make_settings(self, database_path: Path | None = None, **overrides: Any) -> AppSettings:
        data = {
            "app_name": "Test Calendar Console",
            "database_path": database_path or self.database.path,
            "app_secret": "test-secret-value",
            "data_encryption_key": TEST_DATA_KEY,
            "session_cookie_name": "test_session",
            "session_cookie_domain": None,
            "session_cookie_samesite": "lax",
            "csrf_cookie_name": "test_csrf",
            "session_ttl_hours": 12,
            "sync_window_days": 30,
            "provider_timeout_sec": 30,
            "sync_job_stale_minutes": 120,
            "auto_sync_poll_seconds": 30,
            "auto_sync_worker_enabled": False,
            "secure_cookies": False,
            "force_https": False,
            "allowed_hosts": ("127.0.0.1", "localhost", "::1", "testserver"),
            "login_rate_limit_attempts": 5,
            "login_rate_limit_window_minutes": 15,
            "hsts_seconds": 0,
        }
        data.update(overrides)
        return AppSettings(**data)

    def iso(self, value: datetime) -> str:
        return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def in_window_times(self, start_offset_hours: int = 2, duration_hours: int = 1) -> tuple[str, str]:
        start = datetime.now(UTC).replace(microsecond=0, second=0) + timedelta(hours=start_offset_hours)
        end = start + timedelta(hours=duration_hours)
        return self.iso(start), self.iso(end)

    def csrf_token(self, client: Any, cookie_name: str = "test_csrf") -> str:
        token = client.cookies.get(cookie_name)
        self.assertTrue(token)
        return str(token)

    def test_password_hash_session_and_password_policy(self) -> None:
        hasher = PasswordHasher()
        encoded = hasher.hash_password("very-long-secret-pass")
        self.assertTrue(hasher.verify_password("very-long-secret-pass", encoded))
        self.assertFalse(hasher.verify_password("wrong", encoded))
        self.assertIsNone(validate_password_policy("very-long-secret-pass"))
        self.assertIsNotNone(validate_password_policy("short"))

        sessions = SessionManager("unit-test-secret", 4)
        token = sessions.create(42)
        parsed = sessions.parse(token)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.user_id, 42)
        self.assertTrue(parsed.session_id)

    @unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "cryptography dependency is not installed")
    def test_repository_encrypts_connection_settings_when_secret_box_is_used(self) -> None:
        secure_repository = AppRepository(self.database, SecretBox(TEST_DATA_KEY))
        user = secure_repository.create_user("tester@example.com", "hash")
        connection = secure_repository.create_connection(
            int(user["id"]),
            provider="google",
            display_name="Work Google",
            sync_mode="blocked",
            blocked_title="Blocked",
            settings={"google_oauth_refresh_token": "refresh-token"},
        )
        self.assertEqual(connection["settings"]["google_oauth_refresh_token"], "refresh-token")

        with self.database.connect() as db:
            row = db.execute("SELECT settings_json FROM calendar_connections WHERE id = ?", (int(connection["id"]),)).fetchone()
        self.assertIsNotNone(row)
        self.assertTrue(str(row["settings_json"]).startswith("enc:"))
        self.assertNotIn("refresh-token", str(row["settings_json"]))

    def test_repository_can_create_user_event_connection_and_link(self) -> None:
        user = self.repository.create_user("tester@example.com", "hash")
        self.assertEqual(self.repository.count_users(), 1)

        connection = self.repository.create_connection(
            int(user["id"]),
            provider="google",
            display_name="Work Google",
            sync_mode="blocked",
            blocked_title="Blocked",
            settings={"google_calendar_id": "primary"},
        )
        self.assertTrue(connection["is_active"])

        event = self.repository.create_internal_event(
            int(user["id"]),
            title="Planning",
            starts_at="2026-03-08T09:00:00Z",
            ends_at="2026-03-08T10:00:00Z",
            description="Weekly planning",
            location="HQ",
        )
        self.assertEqual(event["title"], "Planning")

        link = self.repository.upsert_event_link(
            int(user["id"]),
            int(event["id"]),
            int(connection["id"]),
            external_event_id="google-1",
            sync_id=event["sync_id"],
            source="webapp",
            mode="blocked",
            fingerprint="abc",
            last_seen_at="2026-03-08T09:00:00Z",
            last_synced_at="2026-03-08T09:00:00Z",
            provider_payload={"sample": True},
        )
        self.assertEqual(link["external_event_id"], "google-1")
        self.assertEqual(len(self.repository.list_links_for_event(int(event["id"]))), 1)

    def test_sync_service_deletes_mirrors_when_source_event_disappears(self) -> None:
        settings = self.make_settings()
        starts_at, ends_at = self.in_window_times()
        user = self.repository.create_user("sync@example.com", "hash")
        exchange_connection = self.repository.create_connection(
            int(user["id"]),
            provider="exchange",
            display_name="Work Exchange",
            sync_mode="full",
            blocked_title="Blocked",
            settings={
                "exchange_tenant_id": "tenant",
                "exchange_client_id": "client",
                "exchange_client_secret": "secret",
                "exchange_user": "sync@example.com",
            },
        )
        icloud_connection = self.repository.create_connection(
            int(user["id"]),
            provider="icloud",
            display_name="Private iCloud",
            sync_mode="full",
            blocked_title="Blocked",
            settings={
                "icloud_user": "me@example.com",
                "icloud_app_pw": "app-password",
                "icloud_principal_path": "/dav/principal/",
            },
        )
        event = self.repository.create_internal_event(
            int(user["id"]),
            title="Source Event",
            starts_at=starts_at,
            ends_at=ends_at,
            source_provider="exchange",
            source_connection_id=int(exchange_connection["id"]),
            sync_id="sync-delete-1",
        )
        self.repository.upsert_event_link(
            int(user["id"]),
            int(event["id"]),
            int(exchange_connection["id"]),
            external_event_id="exchange-1",
            sync_id="sync-delete-1",
            source="exchange",
            mode="full",
            fingerprint="fp-exchange",
            last_seen_at=starts_at,
            last_synced_at=starts_at,
            provider_payload={"id": "exchange-1"},
        )
        self.repository.upsert_event_link(
            int(user["id"]),
            int(event["id"]),
            int(icloud_connection["id"]),
            external_event_id="icloud-1",
            sync_id="sync-delete-1",
            source="webapp",
            mode="full",
            fingerprint="fp-icloud",
            last_seen_at=starts_at,
            last_synced_at=starts_at,
            provider_payload={"href": "/calendars/icloud-1.ics"},
        )

        icloud_remote = SyncEvent(
            provider="icloud",
            provider_id="icloud-1",
            title="Source Event",
            description="Mirror copy",
            location="",
            start={"all_day": False, "dateTime": starts_at},
            end={"all_day": False, "dateTime": ends_at},
            sync_id="sync-delete-1",
            source="webapp",
            mode="full",
            raw={"href": "/calendars/icloud-1.ics"},
        )

        exchange_adapter = FakeConnectionAdapter(exchange_connection, object(), [])
        icloud_adapter = FakeConnectionAdapter(icloud_connection, object(), [icloud_remote])
        service = FakeSyncService(
            self.repository,
            settings,
            {
                int(exchange_connection["id"]): exchange_adapter,
                int(icloud_connection["id"]): icloud_adapter,
            },
        )

        job = self.repository.create_sync_job(int(user["id"]), "test", "Delete propagation test")
        logger = SyncJobLogger(self.repository, int(job["id"]))
        service._run_user_sync(int(user["id"]), logger)

        deleted_event = self.repository.get_internal_event(int(user["id"]), int(event["id"]))
        self.assertIsNotNone(deleted_event)
        self.assertIsNotNone(deleted_event["deleted_at"])

        exchange_link = self.repository.get_link_by_connection_and_external_id(int(exchange_connection["id"]), "exchange-1")
        icloud_link = self.repository.get_link_by_connection_and_external_id(int(icloud_connection["id"]), "icloud-1")
        self.assertIsNotNone(exchange_link)
        self.assertIsNotNone(icloud_link)
        self.assertIsNotNone(exchange_link["deleted_at"])
        self.assertIsNotNone(icloud_link["deleted_at"])
        self.assertEqual(icloud_adapter.deleted_provider_ids, ["icloud-1"])
        self.assertEqual(exchange_adapter.deleted_provider_ids, [])

    def test_sync_service_keeps_empty_external_uid_when_remote_event_has_no_uid(self) -> None:
        settings = self.make_settings()
        user = self.repository.create_user("uidless@example.com", "hash")
        exchange_connection = self.repository.create_connection(
            int(user["id"]),
            provider="exchange",
            display_name="Work Exchange",
            sync_mode="full",
            blocked_title="Blocked",
            settings={
                "exchange_tenant_id": "tenant",
                "exchange_client_id": "client",
                "exchange_client_secret": "secret",
                "exchange_user": "uidless@example.com",
            },
        )
        event = self.repository.create_internal_event(
            int(user["id"]),
            title="UID-less Remote",
            starts_at="2026-03-08T09:00:00Z",
            ends_at="2026-03-08T10:00:00Z",
            source_provider="webapp",
            sync_id="sync-uidless-1",
        )
        self.repository.upsert_event_link(
            int(user["id"]),
            int(event["id"]),
            int(exchange_connection["id"]),
            external_event_id="exchange-1",
            external_uid="",
            sync_id="sync-uidless-1",
            source="webapp",
            mode="full",
            fingerprint="fp-exchange",
            last_seen_at="2026-03-08T09:00:00Z",
            last_synced_at="2026-03-08T09:00:00Z",
            provider_payload={"id": "exchange-1"},
        )

        remote_event = SyncEvent(
            provider="exchange",
            provider_id="exchange-1",
            title="UID-less Remote",
            description="",
            location="",
            start={"all_day": False, "dateTime": "2026-03-08T09:00:00Z"},
            end={"all_day": False, "dateTime": "2026-03-08T10:00:00Z"},
            sync_id="sync-uidless-1",
            source="webapp",
            mode="full",
            uid=None,
            raw={"id": "exchange-1"},
        )

        exchange_adapter = FakeConnectionAdapter(exchange_connection, object(), [remote_event])
        service = FakeSyncService(
            self.repository,
            settings,
            {int(exchange_connection["id"]): exchange_adapter},
        )

        job = self.repository.create_sync_job(int(user["id"]), "test", "UID-less export test")
        logger = SyncJobLogger(self.repository, int(job["id"]))
        service._run_user_sync(int(user["id"]), logger)

        link = self.repository.get_link_by_connection_and_external_id(int(exchange_connection["id"]), "exchange-1")
        self.assertIsNotNone(link)
        self.assertEqual(link["external_uid"], "")

    def test_sync_service_links_existing_google_blocked_mirror_without_creating_duplicate(self) -> None:
        settings = self.make_settings()
        user = self.repository.create_user("google-blocked@example.com", "hash")
        google_connection = self.repository.create_connection(
            int(user["id"]),
            provider="google",
            display_name="Google",
            sync_mode="blocked",
            blocked_title="Blocked",
            settings={
                "google_calendar_id": "primary",
                "google_oauth_client_id": "client",
                "google_oauth_client_secret": "secret",
                "google_oauth_refresh_token": "refresh",
            },
        )
        event = self.repository.create_internal_event(
            int(user["id"]),
            title="Private Appointment",
            starts_at="2026-03-08T09:00:00Z",
            ends_at="2026-03-08T10:00:00Z",
            source_provider="exchange",
            sync_id="sync-google-blocked-1",
        )
        remote_event = SyncEvent(
            provider="google",
            provider_id="google-1",
            title="Blocked",
            description="",
            location="",
            start={"all_day": False, "dateTime": "2026-03-08T09:00:00Z"},
            end={"all_day": False, "dateTime": "2026-03-08T10:00:00Z"},
            sync_id="sync-google-blocked-1",
            source="exchange",
            mode="blocked",
            raw={"id": "google-1", "extendedProperties": {"private": {"aetherSyncId": "sync-google-blocked-1"}}},
        )

        google_adapter = FakeConnectionAdapter(google_connection, object(), [remote_event])
        service = FakeSyncService(
            self.repository,
            settings,
            {int(google_connection["id"]): google_adapter},
        )

        job = self.repository.create_sync_job(int(user["id"]), "test", "Google blocked relink test")
        logger = SyncJobLogger(self.repository, int(job["id"]))
        service._run_user_sync(int(user["id"]), logger)

        link = self.repository.get_link_by_connection_and_external_id(int(google_connection["id"]), "google-1")
        self.assertIsNotNone(link)
        self.assertEqual(link["event_id"], event["id"])
        self.assertEqual(link["external_event_id"], "google-1")

    def test_sync_service_exports_exchange_origin_events_to_google_as_blocked(self) -> None:
        settings = self.make_settings()
        starts_at, ends_at = self.in_window_times()
        user = self.repository.create_user("exchange-origin@example.com", "hash")
        exchange_connection = self.repository.create_connection(
            int(user["id"]),
            provider="exchange",
            display_name="Work Exchange",
            sync_mode="full",
            blocked_title="Blocked",
            settings={
                "exchange_tenant_id": "tenant",
                "exchange_client_id": "client",
                "exchange_client_secret": "secret",
                "exchange_user": "exchange-origin@example.com",
            },
        )
        google_connection = self.repository.create_connection(
            int(user["id"]),
            provider="google",
            display_name="Google",
            sync_mode="blocked",
            blocked_title="Blocked",
            settings={
                "google_calendar_id": "primary",
                "google_oauth_client_id": "client",
                "google_oauth_client_secret": "secret",
                "google_oauth_refresh_token": "refresh",
            },
        )
        exchange_remote = SyncEvent(
            provider="exchange",
            provider_id="exchange-1",
            title="Board Meeting",
            description="Private agenda",
            location="Room 1",
            start={"all_day": False, "dateTime": starts_at},
            end={"all_day": False, "dateTime": ends_at},
            sync_id="sync-policy-1",
            source="exchange",
            mode="full",
            raw={"id": "exchange-1"},
        )

        exchange_adapter = FakeConnectionAdapter(exchange_connection, object(), [exchange_remote])
        google_adapter = FakeConnectionAdapter(google_connection, object(), [])
        service = FakeSyncService(
            self.repository,
            settings,
            {
                int(exchange_connection["id"]): exchange_adapter,
                int(google_connection["id"]): google_adapter,
            },
        )

        job = self.repository.create_sync_job(int(user["id"]), "test", "Policy blocked test")
        logger = SyncJobLogger(self.repository, int(job["id"]))
        service._run_user_sync(int(user["id"]), logger)

        self.assertEqual(len(google_adapter.upsert_calls), 1)
        self.assertEqual(google_adapter.upsert_calls[0]["mode"], "blocked")

        google_links = self.repository.list_links_for_connection(int(google_connection["id"]))
        self.assertEqual(len(google_links), 1)
        self.assertEqual(google_links[0]["mode"], "blocked")

    def test_sync_service_exports_google_origin_events_full_to_exchange_and_icloud(self) -> None:
        settings = self.make_settings()
        starts_at, ends_at = self.in_window_times(start_offset_hours=4)
        user = self.repository.create_user("google-origin@example.com", "hash")
        google_connection = self.repository.create_connection(
            int(user["id"]),
            provider="google",
            display_name="Google",
            sync_mode="blocked",
            blocked_title="Blocked",
            settings={
                "google_calendar_id": "primary",
                "google_oauth_client_id": "client",
                "google_oauth_client_secret": "secret",
                "google_oauth_refresh_token": "refresh",
            },
        )
        exchange_connection = self.repository.create_connection(
            int(user["id"]),
            provider="exchange",
            display_name="Work Exchange",
            sync_mode="full",
            blocked_title="Blocked",
            settings={
                "exchange_tenant_id": "tenant",
                "exchange_client_id": "client",
                "exchange_client_secret": "secret",
                "exchange_user": "google-origin@example.com",
            },
        )
        icloud_connection = self.repository.create_connection(
            int(user["id"]),
            provider="icloud",
            display_name="Private iCloud",
            sync_mode="full",
            blocked_title="Blocked",
            settings={
                "icloud_user": "me@example.com",
                "icloud_app_pw": "app-password",
                "icloud_principal_path": "/dav/principal/",
            },
        )
        google_remote = SyncEvent(
            provider="google",
            provider_id="google-native-1",
            title="Doctor Appointment",
            description="Check-up",
            location="Clinic",
            start={"all_day": False, "dateTime": starts_at},
            end={"all_day": False, "dateTime": ends_at},
            sync_id="sync-policy-2",
            source="google",
            mode="full",
            raw={"id": "google-native-1"},
        )

        google_adapter = FakeConnectionAdapter(google_connection, object(), [google_remote])
        exchange_adapter = FakeConnectionAdapter(exchange_connection, object(), [])
        icloud_adapter = FakeConnectionAdapter(icloud_connection, object(), [])
        service = FakeSyncService(
            self.repository,
            settings,
            {
                int(google_connection["id"]): google_adapter,
                int(exchange_connection["id"]): exchange_adapter,
                int(icloud_connection["id"]): icloud_adapter,
            },
        )

        job = self.repository.create_sync_job(int(user["id"]), "test", "Policy full test")
        logger = SyncJobLogger(self.repository, int(job["id"]))
        service._run_user_sync(int(user["id"]), logger)

        self.assertEqual(len(exchange_adapter.upsert_calls), 1)
        self.assertEqual(exchange_adapter.upsert_calls[0]["mode"], "full")
        self.assertEqual(len(icloud_adapter.upsert_calls), 1)
        self.assertEqual(icloud_adapter.upsert_calls[0]["mode"], "full")

        google_links = self.repository.list_links_for_connection(int(google_connection["id"]))
        self.assertEqual(len(google_links), 1)
        self.assertEqual(google_links[0]["mode"], "full")

    def test_sync_service_import_relinks_existing_event_without_connection_link(self) -> None:
        settings = self.make_settings()
        user = self.repository.create_user("relink@example.com", "hash")
        exchange_connection = self.repository.create_connection(
            int(user["id"]),
            provider="exchange",
            display_name="Exchange",
            sync_mode="full",
            blocked_title="Blocked",
            settings={
                "exchange_tenant_id": "tenant",
                "exchange_client_id": "client",
                "exchange_client_secret": "secret",
                "exchange_user": "relink@example.com",
            },
        )
        event = self.repository.create_internal_event(
            int(user["id"]),
            title="Existing Internal",
            starts_at="2026-03-08T09:00:00Z",
            ends_at="2026-03-08T10:00:00Z",
            source_provider="webapp",
            sync_id="sync-relink-1",
        )
        remote_event = SyncEvent(
            provider="exchange",
            provider_id="exchange-new-1",
            title="Existing Internal",
            description="",
            location="",
            start={"all_day": False, "dateTime": "2026-03-08T09:00:00Z"},
            end={"all_day": False, "dateTime": "2026-03-08T10:00:00Z"},
            sync_id="sync-relink-1",
            source="exchange",
            mode="full",
            raw={"id": "exchange-new-1"},
        )

        exchange_adapter = FakeConnectionAdapter(exchange_connection, object(), [remote_event])
        service = FakeSyncService(
            self.repository,
            settings,
            {int(exchange_connection["id"]): exchange_adapter},
        )

        job = self.repository.create_sync_job(int(user["id"]), "test", "Relink existing event test")
        logger = SyncJobLogger(self.repository, int(job["id"]))
        service._run_user_sync(int(user["id"]), logger)

        link = self.repository.get_link_by_connection_and_external_id(int(exchange_connection["id"]), "exchange-new-1")
        self.assertIsNotNone(link)
        self.assertEqual(int(link["event_id"]), int(event["id"]))

    def test_sync_logs_capture_before_after_changes_for_imported_update(self) -> None:
        settings = self.make_settings()
        user = self.repository.create_user("diff@example.com", "hash")
        exchange_connection = self.repository.create_connection(
            int(user["id"]),
            provider="exchange",
            display_name="Exchange",
            sync_mode="full",
            blocked_title="Blocked",
            settings={
                "exchange_tenant_id": "tenant",
                "exchange_client_id": "client",
                "exchange_client_secret": "secret",
                "exchange_user": "diff@example.com",
            },
        )
        event = self.repository.create_internal_event(
            int(user["id"]),
            title="Alt",
            description="Vorher",
            starts_at="2026-03-08T09:00:00Z",
            ends_at="2026-03-08T10:00:00Z",
            source_provider="webapp",
            sync_id="sync-diff-1",
        )
        self.repository.upsert_event_link(
            int(user["id"]),
            int(event["id"]),
            int(exchange_connection["id"]),
            external_event_id="exchange-diff-1",
            sync_id="sync-diff-1",
            source="exchange",
            mode="full",
            fingerprint="fp-before",
            last_seen_at="2026-03-08T09:00:00Z",
            last_synced_at=None,
            provider_payload={"id": "exchange-diff-1"},
        )
        remote_event = SyncEvent(
            provider="exchange",
            provider_id="exchange-diff-1",
            title="Neu",
            description="Nachher",
            location="Raum 2",
            start={"all_day": False, "dateTime": "2026-03-08T09:30:00Z"},
            end={"all_day": False, "dateTime": "2026-03-08T10:30:00Z"},
            sync_id="sync-diff-1",
            source="exchange",
            mode="full",
            raw={"id": "exchange-diff-1"},
        )

        exchange_adapter = FakeConnectionAdapter(exchange_connection, object(), [remote_event])
        service = FakeSyncService(
            self.repository,
            settings,
            {int(exchange_connection["id"]): exchange_adapter},
        )

        job = self.repository.create_sync_job(int(user["id"]), "test", "Diff capture test")
        logger = SyncJobLogger(self.repository, int(job["id"]))
        service._run_user_sync(int(user["id"]), logger)

        logs = self.repository.list_sync_log_entries(int(user["id"]), 50)
        updated = next(
            entry
            for entry in logs
            if entry["provider"] == "exchange" and entry["action"] == "updated" and entry["message"] == "imported-into-webapp"
        )
        labels = [change["label"] for change in updated["payload"]["changes"]]
        self.assertIn("Titel", labels)
        self.assertIn("Start", labels)
        self.assertIn("Beschreibung", labels)

    def test_sync_service_uses_origin_connection_for_source_deletes(self) -> None:
        settings = self.make_settings()
        starts_at, ends_at = self.in_window_times()
        user = self.repository.create_user("origin-delete@example.com", "hash")
        google_connection = self.repository.create_connection(
            int(user["id"]),
            provider="google",
            display_name="Google",
            sync_mode="blocked",
            blocked_title="Blocked",
            settings={
                "google_calendar_id": "primary",
                "google_oauth_client_id": "client",
                "google_oauth_client_secret": "secret",
                "google_oauth_refresh_token": "refresh",
            },
        )
        exchange_connection = self.repository.create_connection(
            int(user["id"]),
            provider="exchange",
            display_name="Exchange",
            sync_mode="full",
            blocked_title="Blocked",
            settings={
                "exchange_tenant_id": "tenant",
                "exchange_client_id": "client",
                "exchange_client_secret": "secret",
                "exchange_user": "origin-delete@example.com",
            },
        )
        event = self.repository.create_internal_event(
            int(user["id"]),
            title="Google Native",
            starts_at=starts_at,
            ends_at=ends_at,
            source_provider="exchange",
            source_connection_id=int(exchange_connection["id"]),
            origin_provider="google",
            origin_connection_id=int(google_connection["id"]),
            sync_id="sync-origin-delete-1",
        )
        self.repository.upsert_event_link(
            int(user["id"]),
            int(event["id"]),
            int(google_connection["id"]),
            external_event_id="google-native-1",
            sync_id="sync-origin-delete-1",
            source="google",
            mode="full",
            fingerprint="fp-google",
            last_seen_at=starts_at,
            last_synced_at=starts_at,
            provider_payload={"id": "google-native-1"},
        )
        self.repository.upsert_event_link(
            int(user["id"]),
            int(event["id"]),
            int(exchange_connection["id"]),
            external_event_id="exchange-1",
            sync_id="sync-origin-delete-1",
            source="webapp",
            mode="full",
            fingerprint="fp-exchange",
            last_seen_at=starts_at,
            last_synced_at=starts_at,
            provider_payload={"id": "exchange-1"},
        )
        exchange_remote = SyncEvent(
            provider="exchange",
            provider_id="exchange-1",
            title="Google Native",
            description="",
            location="",
            start={"all_day": False, "dateTime": starts_at},
            end={"all_day": False, "dateTime": ends_at},
            sync_id="sync-origin-delete-1",
            source="webapp",
            mode="full",
            raw={"id": "exchange-1"},
        )

        google_adapter = FakeConnectionAdapter(google_connection, object(), [])
        exchange_adapter = FakeConnectionAdapter(exchange_connection, object(), [exchange_remote])
        service = FakeSyncService(
            self.repository,
            settings,
            {
                int(google_connection["id"]): google_adapter,
                int(exchange_connection["id"]): exchange_adapter,
            },
        )

        job = self.repository.create_sync_job(int(user["id"]), "test", "Origin delete test")
        logger = SyncJobLogger(self.repository, int(job["id"]))
        service._run_user_sync(int(user["id"]), logger)

        deleted_event = self.repository.get_internal_event(int(user["id"]), int(event["id"]))
        self.assertIsNotNone(deleted_event)
        self.assertIsNotNone(deleted_event["deleted_at"])
        self.assertEqual(exchange_adapter.deleted_provider_ids, ["exchange-1"])

    def test_sync_service_ignores_missing_remote_links_for_events_outside_window(self) -> None:
        settings = self.make_settings(sync_window_days=1)
        user = self.repository.create_user("outside-window@example.com", "hash")
        exchange_connection = self.repository.create_connection(
            int(user["id"]),
            provider="exchange",
            display_name="Work Exchange",
            sync_mode="full",
            blocked_title="Blocked",
            settings={
                "exchange_tenant_id": "tenant",
                "exchange_client_id": "client",
                "exchange_client_secret": "secret",
                "exchange_user": "outside-window@example.com",
            },
        )
        event = self.repository.create_internal_event(
            int(user["id"]),
            title="Past Event",
            starts_at="2026-03-01T09:00:00Z",
            ends_at="2026-03-01T10:00:00Z",
            source_provider="exchange",
            source_connection_id=int(exchange_connection["id"]),
            sync_id="sync-outside-window-1",
        )
        self.repository.upsert_event_link(
            int(user["id"]),
            int(event["id"]),
            int(exchange_connection["id"]),
            external_event_id="exchange-old-1",
            external_uid="",
            sync_id="sync-outside-window-1",
            source="exchange",
            mode="full",
            fingerprint="fp-old",
            last_seen_at="2026-03-01T09:00:00Z",
            last_synced_at="2026-03-01T09:00:00Z",
            provider_payload={"id": "exchange-old-1"},
        )

        exchange_adapter = FakeConnectionAdapter(exchange_connection, object(), [])
        service = FakeSyncService(
            self.repository,
            settings,
            {int(exchange_connection["id"]): exchange_adapter},
        )

        job = self.repository.create_sync_job(int(user["id"]), "test", "Outside window link test")
        logger = SyncJobLogger(self.repository, int(job["id"]))
        service._run_user_sync(int(user["id"]), logger)

        link = self.repository.get_link_by_connection_and_external_id(int(exchange_connection["id"]), "exchange-old-1")
        self.assertIsNotNone(link)
        self.assertIsNone(link["deleted_at"])
        self.assertEqual(exchange_adapter.deleted_provider_ids, [])
        self.assertEqual(exchange_adapter.upserted_provider_ids, [])

    def test_run_sync_job_completes_with_errors_when_single_export_fails(self) -> None:
        settings = self.make_settings()
        starts_at, ends_at = self.in_window_times()
        user = self.repository.create_user("partial@example.com", "hash")
        exchange_connection = self.repository.create_connection(
            int(user["id"]),
            provider="exchange",
            display_name="Work Exchange",
            sync_mode="full",
            blocked_title="Blocked",
            settings={
                "exchange_tenant_id": "tenant",
                "exchange_client_id": "client",
                "exchange_client_secret": "secret",
                "exchange_user": "partial@example.com",
            },
        )
        self.repository.create_internal_event(
            int(user["id"]),
            title="Export Failure",
            starts_at=starts_at,
            ends_at=ends_at,
            source_provider="webapp",
            sync_id="sync-export-error-1",
        )

        service = FakeSyncService(
            self.repository,
            settings,
            {int(exchange_connection["id"]): FailingConnectionAdapter(exchange_connection, object(), [])},
        )

        job = self.repository.create_sync_job(int(user["id"]), "test", "Partial failure test")
        finished = service.run_sync_job(int(user["id"]), int(job["id"]))

        self.assertEqual(finished["status"], "completed_with_errors")
        errors = self.repository.list_sync_log_entries(int(user["id"]), 50)
        self.assertTrue(any(entry["message"] == "provider_export_event_failed" for entry in errors))

    def test_sync_service_prevents_duplicate_running_jobs(self) -> None:
        settings = self.make_settings()
        user = self.repository.create_user("lock@example.com", "hash")
        service = SyncService(self.repository, settings)

        first_job, started = service.start_user_sync(int(user["id"]), "lock@example.com")
        self.assertTrue(started)
        self.assertIsNotNone(first_job)

        second_job, second_started = service.start_user_sync(int(user["id"]), "lock@example.com")
        self.assertFalse(second_started)
        self.assertIsNotNone(second_job)
        self.assertEqual(second_job["id"], first_job["id"])

    def test_sync_service_expires_stale_running_job_before_restart(self) -> None:
        settings = self.make_settings(sync_job_stale_minutes=5)
        user = self.repository.create_user("stale@example.com", "hash")
        stale_job = self.repository.create_sync_job(int(user["id"]), "stale@example.com", "Old sync", status="running")
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE sync_jobs SET started_at = ?, created_at = ? WHERE id = ?",
                ("2026-03-01T00:00:00Z", "2026-03-01T00:00:00Z", int(stale_job["id"])),
            )

        service = SyncService(self.repository, settings)
        new_job, started = service.start_user_sync(int(user["id"]), "stale@example.com")

        self.assertTrue(started)
        self.assertIsNotNone(new_job)
        self.assertNotEqual(new_job["id"], stale_job["id"])

        recovered_job = self.repository.get_sync_job(int(stale_job["id"]))
        self.assertIsNotNone(recovered_job)
        self.assertEqual(recovered_job["status"], "abandoned")
        self.assertIn("Recovered stale sync job", recovered_job["message"])

    @unittest.skipUnless(FASTAPI_AVAILABLE and CRYPTOGRAPHY_AVAILABLE, "webapp dependencies are not installed")
    def test_http_setup_login_and_calendar_flow(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-webapp.sqlite3"
        settings = self.make_settings(database_path=database_path)
        client = TestClient(create_app(settings))

        response = client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/setup")

        response = client.get("/setup")
        self.assertEqual(response.status_code, 200)
        response = client.post(
            "/setup",
            data={
                "_csrf": self.csrf_token(client),
                "email": "owner@example.com",
                "password": "very-long-secret-pass",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/app/dashboard")

        response = client.get("/app/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Interner Hauptkalender", response.text)
        self.assertEqual(response.headers.get("content-security-policy"), "default-src 'self'; style-src 'self' https://fonts.googleapis.com; img-src 'self' data:; script-src 'self'; connect-src 'self'; font-src 'self' https://fonts.gstatic.com data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")

        response = client.post(
            "/app/events",
            data={
                "_csrf": self.csrf_token(client),
                "title": "Webapp Planning",
                "starts_at": "2026-03-09T09:00",
                "ends_at": "2026-03-09T10:00",
                "description": "Created from integration test",
                "location": "Remote",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/app/calendar?notice=saved")

        response = client.get("/app/calendar")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Webapp Planning", response.text)
        self.assertIn("Created from integration test", response.text)

    @unittest.skipUnless(FASTAPI_AVAILABLE and CRYPTOGRAPHY_AVAILABLE, "webapp dependencies are not installed")
    def test_http_dashboard_can_update_auto_sync_interval(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-autosync.sqlite3"
        settings = self.make_settings(database_path=database_path, auto_sync_worker_enabled=False)
        client = TestClient(create_app(settings))

        client.get("/setup")
        client.post(
            "/setup",
            data={
                "_csrf": self.csrf_token(client),
                "email": "owner@example.com",
                "password": "very-long-secret-pass",
            },
            follow_redirects=False,
        )

        response = client.post(
            "/app/settings/autosync",
            data={
                "_csrf": self.csrf_token(client),
                "auto_sync_interval_minutes": "15",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/app/dashboard?notice=autosync-updated")

        response = client.get("/app/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn("alle 15 Minuten", response.text)

    @unittest.skipUnless(FASTAPI_AVAILABLE and CRYPTOGRAPHY_AVAILABLE, "webapp dependencies are not installed")
    def test_http_logout_clears_secure_host_session_cookie(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-logout.sqlite3"
        settings = self.make_settings(
            database_path=database_path,
            secure_cookies=True,
            force_https=True,
            session_cookie_name="__Host-aether_session",
            session_cookie_domain=None,
        )
        client = TestClient(create_app(settings), base_url="https://testserver")

        client.get("/setup")
        setup_response = client.post(
            "/setup",
            data={
                "_csrf": self.csrf_token(client),
                "email": "owner@example.com",
                "password": "very-long-secret-pass",
            },
            follow_redirects=False,
        )
        self.assertEqual(setup_response.status_code, 303)
        self.assertIn("__Host-aether_session", client.cookies)

        logout_response = client.post(
            "/logout",
            data={"_csrf": self.csrf_token(client)},
            follow_redirects=False,
        )
        self.assertEqual(logout_response.status_code, 303)
        self.assertEqual(logout_response.headers["location"], "/login")
        self.assertNotIn("__Host-aether_session", client.cookies)

        dashboard_response = client.get("/app/dashboard", follow_redirects=False)
        self.assertEqual(dashboard_response.status_code, 303)
        self.assertEqual(dashboard_response.headers["location"], "/login")

    @unittest.skipUnless(FASTAPI_AVAILABLE and CRYPTOGRAPHY_AVAILABLE, "webapp dependencies are not installed")
    def test_http_calendar_month_view_and_logs_show_structured_changes(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-calendar-logs.sqlite3"
        settings = self.make_settings(database_path=database_path, auto_sync_worker_enabled=False)
        client = TestClient(create_app(settings))

        client.get("/setup")
        client.post(
            "/setup",
            data={
                "_csrf": self.csrf_token(client),
                "email": "owner@example.com",
                "password": "very-long-secret-pass",
            },
            follow_redirects=False,
        )

        client.post(
            "/app/events",
            data={
                "_csrf": self.csrf_token(client),
                "title": "Kalenderansicht Test",
                "starts_at": "2026-03-09T09:00",
                "ends_at": "2026-03-09T10:00",
                "description": "Monatsansicht",
                "location": "Remote",
            },
            follow_redirects=False,
        )

        repo = AppRepository(Database(database_path), SecretBox(TEST_DATA_KEY))
        user = repo.get_user_by_email("owner@example.com")
        self.assertIsNotNone(user)
        job = repo.create_sync_job(int(user["id"]), "test", "HTTP log render")
        repo.add_sync_log(
            int(job["id"]),
            level="info",
            provider="exchange",
            action="updated",
            sync_id="sync-http-log-1",
            message="imported-into-webapp",
            payload={
                "detail": "imported-into-webapp",
                "changes": [
                    {"label": "Titel", "before": "Alt", "after": "Neu"},
                    {"label": "Ort", "before": "", "after": "Remote"},
                ],
            },
        )

        response = client.get("/app/calendar?month=2026-03")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Monatsansicht", response.text)
        self.assertIn("Kalenderansicht Test", response.text)
        self.assertIn("2026-03", response.text)

        response = client.get("/app/logs")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Vorher", response.text)
        self.assertIn("Nachher", response.text)
        self.assertIn("Titel", response.text)
        self.assertIn("Alt", response.text)
        self.assertIn("Neu", response.text)

    @unittest.skipUnless(FASTAPI_AVAILABLE and CRYPTOGRAPHY_AVAILABLE, "webapp dependencies are not installed")
    def test_http_connection_profiles_can_export_and_import(self) -> None:
        source_db = Path(tempfile.mkdtemp()) / "http-profile-source.sqlite3"
        source_settings = self.make_settings(database_path=source_db, auto_sync_worker_enabled=False)
        source_client = TestClient(create_app(source_settings))

        source_client.get("/setup")
        source_client.post(
            "/setup",
            data={
                "_csrf": self.csrf_token(source_client),
                "email": "source@example.com",
                "password": "very-long-secret-pass",
            },
            follow_redirects=False,
        )
        create_response = source_client.post(
            "/app/connections",
            data={
                "_csrf": self.csrf_token(source_client),
                "provider": "exchange",
                "display_name": "Work Exchange",
                "blocked_title": "Blocked",
                "timeout_sec": "45",
                "exchange_tenant_id": "tenant-id",
                "exchange_client_id": "client-id",
                "exchange_client_secret": "secret-value",
                "exchange_user": "info@example.com",
            },
            follow_redirects=False,
        )
        self.assertEqual(create_response.status_code, 303)

        export_response = source_client.get("/app/connections/export")
        self.assertEqual(export_response.status_code, 200)
        self.assertEqual(export_response.headers["content-type"].split(";")[0], "application/json")
        self.assertIn("attachment; filename=", export_response.headers["content-disposition"])
        exported_payload = export_response.json()
        self.assertEqual(exported_payload["kind"], "aether-calendar-connection-profile")
        self.assertEqual(len(exported_payload["connections"]), 1)
        self.assertEqual(exported_payload["connections"][0]["settings"]["exchange_user"], "info@example.com")

        target_db = Path(tempfile.mkdtemp()) / "http-profile-target.sqlite3"
        target_settings = self.make_settings(database_path=target_db, auto_sync_worker_enabled=False)
        target_client = TestClient(create_app(target_settings))

        target_client.get("/setup")
        target_client.post(
            "/setup",
            data={
                "_csrf": self.csrf_token(target_client),
                "email": "target@example.com",
                "password": "very-long-secret-pass",
            },
            follow_redirects=False,
        )
        import_response = target_client.post(
            "/app/connections/import",
            data={"_csrf": self.csrf_token(target_client)},
            files={"profile_file": ("connections.json", export_response.content, "application/json")},
            follow_redirects=False,
        )
        self.assertEqual(import_response.status_code, 303)
        self.assertEqual(import_response.headers["location"], "/app/connections?notice=profile-imported&created=1&updated=0")

        target_repo = AppRepository(Database(target_db), SecretBox(TEST_DATA_KEY))
        target_user = target_repo.get_user_by_email("target@example.com")
        self.assertIsNotNone(target_user)
        assert target_user is not None
        connections = target_repo.list_connections(int(target_user["id"]))
        self.assertEqual(len(connections), 1)
        self.assertEqual(connections[0]["display_name"], "Work Exchange")
        self.assertEqual(connections[0]["settings"]["exchange_user"], "info@example.com")
        self.assertEqual(connections[0]["settings"]["timeout_sec"], "45")

        second_import = target_client.post(
            "/app/connections/import",
            data={"_csrf": self.csrf_token(target_client)},
            files={"profile_file": ("connections.json", export_response.content, "application/json")},
            follow_redirects=False,
        )
        self.assertEqual(second_import.status_code, 303)
        self.assertEqual(second_import.headers["location"], "/app/connections?notice=profile-imported&created=0&updated=1")

    @unittest.skipUnless(FASTAPI_AVAILABLE and CRYPTOGRAPHY_AVAILABLE, "webapp dependencies are not installed")
    def test_http_requires_csrf_and_rate_limits_login(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-security.sqlite3"
        settings = self.make_settings(
            database_path=database_path,
            login_rate_limit_attempts=3,
            login_rate_limit_window_minutes=60,
        )
        client = TestClient(create_app(settings))

        client.get("/setup")
        client.post(
            "/setup",
            data={
                "_csrf": self.csrf_token(client),
                "email": "owner@example.com",
                "password": "very-long-secret-pass",
            },
            follow_redirects=False,
        )

        response = client.post(
            "/app/events",
            data={
                "title": "No CSRF",
                "starts_at": "2026-03-09T09:00",
                "ends_at": "2026-03-09T10:00",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/app/calendar?error=security")

        bad_client = TestClient(create_app(settings))
        bad_client.get("/login")
        for _ in range(3):
            bad_client.post(
                "/login",
                data={
                    "_csrf": self.csrf_token(bad_client),
                    "email": "owner@example.com",
                    "password": "wrong-password",
                },
                follow_redirects=False,
            )
        blocked = bad_client.post(
            "/login",
            data={
                "_csrf": self.csrf_token(bad_client),
                "email": "owner@example.com",
                "password": "wrong-password",
            },
            follow_redirects=False,
        )
        self.assertEqual(blocked.status_code, 303)
        self.assertEqual(blocked.headers["location"], "/login?error=rate-limit")


if __name__ == "__main__":
    unittest.main()
