import base64
import tempfile
import unittest
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List
from unittest import mock
from urllib.parse import parse_qs, urlparse

from sync_exchange_icloud_calendar import SyncEvent
from webapp.config import AppSettings
from webapp.database import Database
from webapp.repository import AppRepository
from webapp.security import (
    CRYPTOGRAPHY_AVAILABLE,
    PasswordHasher,
    SecretBox,
    SessionManager,
    TotpManager,
    validate_password_policy,
)
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


class FailingFetchConnectionAdapter(FakeConnectionAdapter):
    def list_events(self, start: Any, end: Any, log: SyncJobLogger) -> List[SyncEvent]:
        raise RuntimeError("transient fetch failure")


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
            "public_base_url": "",
            "display_timezone": "Europe/Berlin",
            "database_path": database_path or self.database.path,
            "backup_directory": (database_path or self.database.path).parent / "backups",
            "legal_brand_name": "Webdesign Becker",
            "legal_business_name": "TB Media UG (haftungsbeschränkt)",
            "legal_representative_name": "Tom Becker",
            "legal_street": "Siempelkampstraße 78",
            "legal_postal_city": "47803 Krefeld",
            "legal_email": "info@tb-media.net",
            "legal_phone": "02151 9288541",
            "legal_whatsapp": "01525 8530929",
            "legal_vat_id": "DE366883061",
            "legal_website_url": "https://webdesign-becker.de",
            "google_oauth_client_id": "",
            "google_oauth_client_secret": "",
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

        totp = TotpManager()
        secret = totp.generate_secret()
        code = totp.generate_code(secret, at_time=datetime(2026, 3, 9, 12, 0, tzinfo=UTC))
        self.assertTrue(totp.verify_code(secret, code, at_time=datetime(2026, 3, 9, 12, 0, 10, tzinfo=UTC)))
        self.assertFalse(totp.verify_code(secret, "000000", at_time=datetime(2026, 3, 9, 12, 0, 10, tzinfo=UTC)))
        self.assertIn("otpauth://totp/", totp.provisioning_uri(secret, "owner@example.com", "Test Calendar Console"))

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
        self.assertEqual(self.repository.count_internal_events(int(user["id"])), 1)
        self.assertEqual(self.repository.count_event_links(int(user["id"])), 1)
        job = self.repository.create_sync_job(int(user["id"]), "test", "Test job")
        self.assertIsNotNone(job)
        self.assertEqual(self.repository.count_sync_jobs(int(user["id"])), 1)
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

    def test_sync_service_propagates_delete_when_mirror_provider_event_is_removed(self) -> None:
        settings = self.make_settings()
        starts_at, ends_at = self.in_window_times()
        user = self.repository.create_user("mirror-delete@example.com", "hash")
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
                "exchange_user": "mirror-delete@example.com",
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
            title="Mirror Delete",
            starts_at=starts_at,
            ends_at=ends_at,
            source_provider="exchange",
            source_connection_id=int(exchange_connection["id"]),
            origin_provider="exchange",
            origin_connection_id=int(exchange_connection["id"]),
            sync_id="sync-mirror-delete-1",
        )
        self.repository.upsert_event_link(
            int(user["id"]),
            int(event["id"]),
            int(exchange_connection["id"]),
            external_event_id="exchange-1",
            sync_id="sync-mirror-delete-1",
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
            sync_id="sync-mirror-delete-1",
            source="webapp",
            mode="full",
            fingerprint="fp-icloud",
            last_seen_at=starts_at,
            last_synced_at=starts_at,
            provider_payload={"href": "/calendars/icloud-1.ics"},
        )

        remote_modified = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
        exchange_remote = SyncEvent(
            provider="exchange",
            provider_id="exchange-1",
            title="Mirror Delete",
            description="",
            location="",
            start={"all_day": False, "dateTime": starts_at},
            end={"all_day": False, "dateTime": ends_at},
            sync_id="sync-mirror-delete-1",
            source="exchange",
            mode="full",
            modified_at=remote_modified,
            raw={"id": "exchange-1"},
        )

        exchange_adapter = FakeConnectionAdapter(exchange_connection, object(), [exchange_remote])
        icloud_adapter = FakeConnectionAdapter(icloud_connection, object(), [])
        service = FakeSyncService(
            self.repository,
            settings,
            {
                int(exchange_connection["id"]): exchange_adapter,
                int(icloud_connection["id"]): icloud_adapter,
            },
        )

        job = self.repository.create_sync_job(int(user["id"]), "test", "Mirror delete propagation test")
        logger = SyncJobLogger(self.repository, int(job["id"]))
        service._run_user_sync(int(user["id"]), logger)

        deleted_event = self.repository.get_internal_event(int(user["id"]), int(event["id"]))
        self.assertIsNotNone(deleted_event)
        self.assertIsNotNone(deleted_event["deleted_at"])
        self.assertEqual(exchange_adapter.deleted_provider_ids, ["exchange-1"])
        self.assertEqual(icloud_adapter.deleted_provider_ids, [])

    def test_sync_service_preserves_event_when_missing_provider_is_older_than_newer_change(self) -> None:
        settings = self.make_settings()
        starts_at, ends_at = self.in_window_times()
        user = self.repository.create_user("preserve-missing@example.com", "hash")
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
                "exchange_user": "preserve-missing@example.com",
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
            title="Preserve Missing Mirror",
            starts_at=starts_at,
            ends_at=ends_at,
            source_provider="exchange",
            source_connection_id=int(exchange_connection["id"]),
            origin_provider="exchange",
            origin_connection_id=int(exchange_connection["id"]),
            sync_id="sync-preserve-missing-1",
        )
        self.repository.upsert_event_link(
            int(user["id"]),
            int(event["id"]),
            int(exchange_connection["id"]),
            external_event_id="exchange-1",
            sync_id="sync-preserve-missing-1",
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
            sync_id="sync-preserve-missing-1",
            source="webapp",
            mode="full",
            fingerprint="fp-icloud",
            last_seen_at=starts_at,
            last_synced_at=starts_at,
            provider_payload={"href": "/calendars/icloud-1.ics"},
        )
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE internal_events SET updated_at = ? WHERE id = ?",
                (ends_at, int(event["id"])),
            )

        remote_modified = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
        exchange_remote = SyncEvent(
            provider="exchange",
            provider_id="exchange-1",
            title="Preserve Missing Mirror",
            description="",
            location="",
            start={"all_day": False, "dateTime": starts_at},
            end={"all_day": False, "dateTime": ends_at},
            sync_id="sync-preserve-missing-1",
            source="exchange",
            mode="full",
            modified_at=remote_modified,
            raw={"id": "exchange-1"},
        )
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE event_links
                SET fingerprint = ?
                WHERE connection_id = ? AND external_event_id = ?
                """,
                (
                    exchange_remote.fingerprint("full", "Blocked"),
                    int(exchange_connection["id"]),
                    "exchange-1",
                ),
            )

        exchange_adapter = FakeConnectionAdapter(exchange_connection, object(), [exchange_remote])
        icloud_adapter = FakeConnectionAdapter(icloud_connection, object(), [])
        service = FakeSyncService(
            self.repository,
            settings,
            {
                int(exchange_connection["id"]): exchange_adapter,
                int(icloud_connection["id"]): icloud_adapter,
            },
        )

        job = self.repository.create_sync_job(int(user["id"]), "test", "Preserve newer change test")
        logger = SyncJobLogger(self.repository, int(job["id"]))
        service._run_user_sync(int(user["id"]), logger)

        preserved_event = self.repository.get_internal_event(int(user["id"]), int(event["id"]))
        self.assertIsNotNone(preserved_event)
        self.assertIsNone(preserved_event["deleted_at"])
        self.assertEqual(exchange_adapter.deleted_provider_ids, [])
        self.assertEqual(len(icloud_adapter.upsert_calls), 1)

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

    def test_sync_service_does_not_duplicate_google_events_when_same_event_exists_natively(self) -> None:
        settings = self.make_settings()
        starts_at, ends_at = self.in_window_times()
        user = self.repository.create_user("google-dedup@example.com", "hash")
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
                "exchange_user": "google-dedup@example.com",
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
        # Same real-world event exists natively in both Exchange and Google
        exchange_remote = SyncEvent(
            provider="exchange",
            provider_id="exchange-native-1",
            title="Team Standup",
            description="Daily standup",
            location="Room A",
            start={"all_day": False, "dateTime": starts_at},
            end={"all_day": False, "dateTime": ends_at},
            sync_id="dedup-test-1",
            source="exchange",
            mode="full",
            modified_at=datetime.now(UTC),
            raw={"id": "exchange-native-1"},
        )
        google_remote = SyncEvent(
            provider="google",
            provider_id="google-native-1",
            title="Team Standup",
            description="Daily standup",
            location="Room A",
            start={"all_day": False, "dateTime": starts_at},
            end={"all_day": False, "dateTime": ends_at},
            raw={"id": "google-native-1"},
        )

        exchange_adapter = FakeConnectionAdapter(exchange_connection, object(), [exchange_remote])
        google_adapter = FakeConnectionAdapter(google_connection, object(), [google_remote])
        service = FakeSyncService(
            self.repository,
            settings,
            {
                int(exchange_connection["id"]): exchange_adapter,
                int(google_connection["id"]): google_adapter,
            },
        )

        job = self.repository.create_sync_job(int(user["id"]), "test", "Google dedup test")
        logger = SyncJobLogger(self.repository, int(job["id"]))
        service._run_user_sync(int(user["id"]), logger)

        # The exchange-origin event should be skipped because the same time
        # slot is already covered by the google-origin event's link.
        # Only the google-origin event should be patched (existing != None).
        self.assertEqual(len(google_adapter.upsert_calls), 1)
        self.assertEqual(google_adapter.upsert_calls[0]["existing_provider_id"], "google-native-1")
        # No duplicate creates
        creates = [call for call in google_adapter.upsert_calls if call["existing_provider_id"] is None]
        self.assertEqual(len(creates), 0, "No new events should be created in Google")
        google_links = self.repository.list_links_for_connection(int(google_connection["id"]))
        self.assertEqual(len(google_links), 1)
        self.assertEqual(google_links[0]["external_event_id"], "google-native-1")

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

    def test_run_sync_job_continues_when_single_provider_fetch_fails(self) -> None:
        settings = self.make_settings()
        starts_at, ends_at = self.in_window_times()
        user = self.repository.create_user("fetchpartial@example.com", "hash")
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
                "exchange_user": "fetchpartial@example.com",
            },
        )
        icloud_connection = self.repository.create_connection(
            int(user["id"]),
            provider="icloud",
            display_name="iCloud",
            sync_mode="full",
            blocked_title="Blocked",
            settings={
                "icloud_user": "icloud@example.com",
                "icloud_app_pw": "pw",
                "icloud_principal_path": "/principal/",
            },
        )
        remote_event = SyncEvent(
            provider="exchange",
            provider_id="exchange-remote-1",
            title="Fetched Exchange Event",
            start={"dateTime": starts_at, "timeZone": "UTC", "all_day": False},
            end={"dateTime": ends_at, "timeZone": "UTC", "all_day": False},
            description="From exchange",
            location="HQ",
            recurrence=[],
            sync_origin="exchange",
            source="exchange",
            mode="full",
            modified_at=datetime.now(UTC),
            uid="exchange-uid-1",
            raw={"id": "exchange-remote-1"},
        )

        service = FakeSyncService(
            self.repository,
            settings,
            {
                int(exchange_connection["id"]): FakeConnectionAdapter(exchange_connection, object(), [remote_event]),
                int(icloud_connection["id"]): FailingFetchConnectionAdapter(icloud_connection, object(), []),
            },
        )

        job = self.repository.create_sync_job(int(user["id"]), "test", "Fetch partial failure test")
        finished = service.run_sync_job(int(user["id"]), int(job["id"]))

        self.assertEqual(finished["status"], "completed_with_errors")
        logs = self.repository.list_sync_log_entries(int(user["id"]), 50)
        self.assertTrue(any(entry["message"] == "provider_fetch_failed" for entry in logs))
        self.assertFalse(any(entry["message"] == "sync_failed" for entry in logs))
        events = self.repository.list_internal_events(int(user["id"]))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["title"], "Fetched Exchange Event")

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
        self.assertIn("Master-Ereignisse", response.text)
        self.assertIn("Provider-Spiegel", response.text)
        self.assertIn("/static/app.css?v=", response.text)
        self.assertEqual(response.headers.get("content-security-policy"), "default-src 'self'; style-src 'self' https://fonts.googleapis.com; img-src 'self' data:; script-src 'self'; connect-src 'self'; font-src 'self' https://fonts.gstatic.com data:; object-src 'none'; base-uri 'self'; form-action 'self' https://accounts.google.com; frame-ancestors 'none'")

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
    def test_public_legal_pages_are_accessible_without_login(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-legal.sqlite3"
        settings = self.make_settings(database_path=database_path)
        client = TestClient(create_app(settings))

        imprint_response = client.get("/impressum")
        self.assertEqual(imprint_response.status_code, 200)
        self.assertIn("TB Media UG (haftungsbeschränkt)", imprint_response.text)
        self.assertIn("DE366883061", imprint_response.text)
        self.assertIn("Tom Becker", imprint_response.text)

        privacy_response = client.get("/datenschutz")
        self.assertEqual(privacy_response.status_code, 200)
        self.assertIn("ausschließlich der internen Verwaltung", privacy_response.text)
        self.assertIn("Microsoft Exchange", privacy_response.text)
        self.assertIn("Google Calendar", privacy_response.text)

        terms_response = client.get("/nutzungsbedingungen")
        self.assertEqual(terms_response.status_code, 200)
        self.assertIn("ausschließlich für den internen Gebrauch", terms_response.text)
        self.assertIn("Serverstandort in Europa", terms_response.text)

        login_response = client.get("/login")
        self.assertIn("/impressum", login_response.text)
        self.assertIn("/datenschutz", login_response.text)
        self.assertIn("/nutzungsbedingungen", login_response.text)

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
    def test_http_dashboard_shows_recent_error_details(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-dashboard-errors.sqlite3"
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

        repository = AppRepository(Database(database_path), SecretBox(TEST_DATA_KEY))
        user = repository.get_user_by_email("owner@example.com")
        self.assertIsNotNone(user)
        assert user is not None
        job = repository.create_sync_job(int(user["id"]), "owner@example.com", "Sync failed", status="failed")
        repository.add_sync_log(
            int(job["id"]),
            level="error",
            provider="google",
            action="provider_fetch_failed",
            sync_id="sync-google-error",
            message="provider_fetch_failed",
            payload={
                "detail": "Token-Refresh gegen Google ist fehlgeschlagen.",
                "error": "400 Client Error: invalid_grant",
                "endpoint": "https://oauth2.googleapis.com/token",
                "response": {"error": "invalid_grant"},
            },
        )

        response = client.get("/app/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Letzte Fehler", response.text)
        self.assertIn("provider_fetch_failed", response.text)
        self.assertIn("Token-Refresh gegen Google ist fehlgeschlagen.", response.text)
        self.assertIn("400 Client Error: invalid_grant", response.text)
        self.assertIn("https://oauth2.googleapis.com/token", response.text)

    @unittest.skipUnless(FASTAPI_AVAILABLE and CRYPTOGRAPHY_AVAILABLE, "webapp dependencies are not installed")
    def test_http_dashboard_shows_only_real_changes_not_no_change_logs(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-dashboard-changes.sqlite3"
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

        repository = AppRepository(Database(database_path), SecretBox(TEST_DATA_KEY))
        user = repository.get_user_by_email("owner@example.com")
        self.assertIsNotNone(user)
        assert user is not None
        job = repository.create_sync_job(int(user["id"]), "owner@example.com", "Sync completed", status="completed")
        repository.add_sync_log(
            int(job["id"]),
            level="info",
            provider="exchange",
            action="updated",
            sync_id="sync-change-1",
            message="imported-into-webapp",
            payload={
                "detail": "imported-into-webapp",
                "changes": [
                    {"label": "Start", "before": "2026-03-13 09:00 UTC", "after": "2026-03-13 10:00 UTC"},
                    {"label": "Titel", "before": "Alt", "after": "Neu"},
                ],
            },
        )
        repository.add_sync_log(
            int(job["id"]),
            level="info",
            provider="google",
            action="skipped",
            sync_id="sync-change-2",
            message="no-change",
            payload={
                "detail": "no-change",
                "changes": [],
            },
        )

        response = client.get("/app/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Letzte Änderungen", response.text)
        self.assertIn("imported-into-webapp", response.text)
        self.assertIn("Geändert: Start, Titel", response.text)
        self.assertNotIn("no-change", response.text)

    @unittest.skipUnless(FASTAPI_AVAILABLE and CRYPTOGRAPHY_AVAILABLE, "webapp dependencies are not installed")
    def test_http_google_connect_workflow_creates_connection(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-google-connect.sqlite3"
        settings = self.make_settings(
            database_path=database_path,
            auto_sync_worker_enabled=False,
            google_oauth_client_id="google-client-id",
            google_oauth_client_secret="google-client-secret",
            public_base_url="https://calendar.example.com",
            allowed_hosts=("127.0.0.1", "localhost", "::1", "testserver", "calendar.example.com"),
        )
        client = TestClient(create_app(settings), base_url="https://calendar.example.com")

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

        connect_response = client.post(
            "/app/connections/google/connect",
            data={
                "_csrf": self.csrf_token(client),
                "provider": "google",
                "display_name": "Google Primary",
                "blocked_title": "Blocked",
                "timeout_sec": "45",
                "google_calendar_id": "primary",
            },
            follow_redirects=False,
        )
        self.assertEqual(connect_response.status_code, 303)
        location = connect_response.headers["location"]
        self.assertIn("accounts.google.com/o/oauth2/v2/auth", location)
        query = parse_qs(urlparse(location).query)
        self.assertEqual(query["client_id"][0], "google-client-id")
        self.assertEqual(query["scope"][0], "https://www.googleapis.com/auth/calendar.events")
        self.assertEqual(query["redirect_uri"][0], "https://calendar.example.com/app/connections/google/callback")
        state = query["state"][0]

        mock_response = mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "access-token",
            "refresh_token": "refresh-token-value",
            "scope": "https://www.googleapis.com/auth/calendar.events",
            "token_type": "Bearer",
        }
        with mock.patch("webapp.main.requests.post", return_value=mock_response) as mocked_post:
            callback_response = client.get(
                f"/app/connections/google/callback?state={state}&code=oauth-code-value",
                follow_redirects=False,
            )
        self.assertEqual(callback_response.status_code, 303)
        self.assertEqual(callback_response.headers["location"], "/app/connections?provider=google&notice=google-connected")
        mocked_post.assert_called_once()
        posted_data = mocked_post.call_args.kwargs["data"]
        self.assertEqual(posted_data["client_id"], "google-client-id")
        self.assertEqual(posted_data["client_secret"], "google-client-secret")
        self.assertEqual(posted_data["redirect_uri"], "https://calendar.example.com/app/connections/google/callback")

        repository = AppRepository(Database(database_path), SecretBox(TEST_DATA_KEY))
        user = repository.get_user_by_email("owner@example.com")
        self.assertIsNotNone(user)
        assert user is not None
        connection = repository.find_connection_by_provider_and_name(int(user["id"]), "google", "Google Primary")
        self.assertIsNotNone(connection)
        assert connection is not None
        self.assertEqual(connection["settings"]["google_oauth_refresh_token"], "refresh-token-value")
        self.assertEqual(connection["settings"]["google_oauth_client_id"], "google-client-id")
        self.assertEqual(connection["settings"]["timeout_sec"], "45")

    @unittest.skipUnless(FASTAPI_AVAILABLE and CRYPTOGRAPHY_AVAILABLE, "webapp dependencies are not installed")
    def test_http_connections_form_tracks_selected_provider(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-connections-provider.sqlite3"
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

        exchange_response = client.get("/app/connections?provider=exchange")
        self.assertEqual(exchange_response.status_code, 200)
        self.assertIn("Schritt 1: Provider wählen.", exchange_response.text)
        self.assertIn("Tenant ID", exchange_response.text)
        self.assertNotIn("iCloud User", exchange_response.text)
        self.assertNotIn("OAuth Refresh Token", exchange_response.text)

        icloud_response = client.get("/app/connections?provider=icloud")
        self.assertEqual(icloud_response.status_code, 200)
        self.assertIn("iCloud User", icloud_response.text)
        self.assertNotIn("Tenant ID", icloud_response.text)
        self.assertNotIn("OAuth Refresh Token", icloud_response.text)

        google_response = client.get("/app/connections?provider=google")
        self.assertEqual(google_response.status_code, 200)
        self.assertIn("Connect with Google", google_response.text)
        self.assertIn("Mit Google verbinden", google_response.text)
        self.assertNotIn("Tenant ID", google_response.text)
        self.assertNotIn("iCloud User", google_response.text)

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
    def test_http_user_settings_can_enable_two_factor_login(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-2fa.sqlite3"
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

        dashboard = client.get("/app/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("Benutzereinstellungen", dashboard.text)

        start_setup = client.post(
            "/app/settings/two-factor/setup",
            data={"_csrf": self.csrf_token(client)},
            follow_redirects=False,
        )
        self.assertEqual(start_setup.status_code, 303)
        self.assertEqual(start_setup.headers["location"], "/app/settings?notice=two-factor-setup-started")

        setup_page = client.get("/app/settings")
        self.assertEqual(setup_page.status_code, 200)
        self.assertIn("QR-Code", setup_page.text)
        self.assertIn("data:image/svg+xml;base64,", setup_page.text)

        repo = AppRepository(Database(database_path), SecretBox(TEST_DATA_KEY))
        user = repo.get_user_by_email("owner@example.com")
        self.assertIsNotNone(user)
        assert user is not None
        pending_secret = str(user["two_factor_pending_secret"])
        self.assertTrue(pending_secret)

        totp = TotpManager()
        enable_code = totp.generate_code(pending_secret)
        enable_response = client.post(
            "/app/settings/two-factor/enable",
            data={
                "_csrf": self.csrf_token(client),
                "current_password": "very-long-secret-pass",
                "code": enable_code,
            },
            follow_redirects=False,
        )
        self.assertEqual(enable_response.status_code, 303)
        self.assertEqual(enable_response.headers["location"], "/app/settings?notice=two-factor-enabled")

        user = repo.get_user_by_email("owner@example.com")
        self.assertIsNotNone(user)
        assert user is not None
        self.assertTrue(user["two_factor_enabled"])
        self.assertTrue(str(user["two_factor_secret"]))
        self.assertEqual(str(user["two_factor_pending_secret"]), "")

        logout_response = client.post(
            "/logout",
            data={"_csrf": self.csrf_token(client)},
            follow_redirects=False,
        )
        self.assertEqual(logout_response.status_code, 303)
        self.assertEqual(logout_response.headers["location"], "/login")
        client.get("/login")

        login_response = client.post(
            "/login",
            data={
                "_csrf": self.csrf_token(client),
                "email": "owner@example.com",
                "password": "very-long-secret-pass",
            },
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 303)
        self.assertEqual(login_response.headers["location"], "/login/2fa")
        self.assertIn("aether_pending_2fa", client.cookies)

        bad_code_response = client.post(
            "/login/2fa",
            data={
                "_csrf": self.csrf_token(client),
                "code": "000000",
            },
            follow_redirects=False,
        )
        self.assertEqual(bad_code_response.status_code, 303)
        self.assertEqual(bad_code_response.headers["location"], "/login/2fa?error=auth")

        current_user = repo.get_user_by_email("owner@example.com")
        self.assertIsNotNone(current_user)
        assert current_user is not None
        login_code = totp.generate_code(str(current_user["two_factor_secret"]))
        second_factor_response = client.post(
            "/login/2fa",
            data={
                "_csrf": self.csrf_token(client),
                "code": login_code,
            },
            follow_redirects=False,
        )
        self.assertEqual(second_factor_response.status_code, 303)
        self.assertEqual(second_factor_response.headers["location"], "/app/dashboard")
        self.assertNotIn("aether_pending_2fa", client.cookies)

        settings_page = client.get("/app/settings")
        self.assertEqual(settings_page.status_code, 200)
        self.assertIn("2FA deaktivieren", settings_page.text)
        self.assertIn("Zwei-Faktor-Authentifizierung", settings_page.text)

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
    def test_http_logs_can_filter_search_and_sort(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-log-filter.sqlite3"
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

        repo = AppRepository(Database(database_path), SecretBox(TEST_DATA_KEY))
        user = repo.get_user_by_email("owner@example.com")
        self.assertIsNotNone(user)
        assert user is not None
        old_job = repo.create_sync_job(int(user["id"]), "test", "Older job")
        repo.finish_sync_job(int(old_job["id"]), "completed", "Older job done")
        new_job = repo.create_sync_job(int(user["id"]), "test", "Newer job")
        repo.finish_sync_job(int(new_job["id"]), "completed", "Newer job done")

        repo.add_sync_log(
            int(old_job["id"]),
            level="warn",
            provider="exchange",
            action="deleted",
            sync_id="sync-log-filter-1",
            message="deleted-match-older",
            payload={"detail": "deleted-match-older"},
        )
        repo.add_sync_log(
            int(new_job["id"]),
            level="warn",
            provider="exchange",
            action="deleted",
            sync_id="sync-log-filter-2",
            message="deleted-match-newer",
            payload={"detail": "deleted-match-newer"},
        )
        repo.add_sync_log(
            int(new_job["id"]),
            level="info",
            provider="google",
            action="updated",
            sync_id="sync-log-filter-3",
            message="updated-google",
            payload={"detail": "updated-google"},
        )
        with Database(database_path).connect() as connection:
            connection.execute(
                "UPDATE sync_log_entries SET created_at = ? WHERE message = ?",
                ("2026-03-01T09:00:00Z", "deleted-match-older"),
            )
            connection.execute(
                "UPDATE sync_log_entries SET created_at = ? WHERE message = ?",
                ("2026-03-02T09:00:00Z", "deleted-match-newer"),
            )
            connection.execute(
                "UPDATE sync_log_entries SET created_at = ? WHERE message = ?",
                ("2026-03-03T09:00:00Z", "updated-google"),
            )

        response = client.get("/app/logs?q=deleted&provider=exchange&action=deleted&sort=oldest")
        self.assertEqual(response.status_code, 200)
        self.assertIn("2 von 3 Einträgen", response.text)
        self.assertIn("deleted-match-older", response.text)
        self.assertIn("deleted-match-newer", response.text)
        self.assertNotIn("updated-google", response.text)
        self.assertLess(response.text.find("deleted-match-older"), response.text.find("deleted-match-newer"))

        response = client.get(f"/app/logs?job_id={old_job['id']}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("deleted-match-older", response.text)
        self.assertNotIn("deleted-match-newer", response.text)
        self.assertIn("Nur diesen Job", response.text)

    @unittest.skipUnless(FASTAPI_AVAILABLE and CRYPTOGRAPHY_AVAILABLE, "webapp dependencies are not installed")
    def test_http_logs_live_feed_returns_recent_entries_and_running_job(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-log-live.sqlite3"
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

        repo = AppRepository(Database(database_path), SecretBox(TEST_DATA_KEY))
        user = repo.get_user_by_email("owner@example.com")
        self.assertIsNotNone(user)
        assert user is not None
        job = repo.create_sync_job(int(user["id"]), "owner@example.com", "Live sync", status="running")
        repo.add_sync_log(
            int(job["id"]),
            level="info",
            provider="exchange",
            action="updated",
            sync_id="sync-live-1",
            message="imported-into-webapp",
            payload={"detail": "imported-into-webapp"},
        )

        response = client.get("/app/logs/live?limit=10")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["running_job"]["id"], int(job["id"]))
        self.assertEqual(payload["log_count"], 1)
        self.assertEqual(payload["log_entries"][0]["message"], "imported-into-webapp")
        self.assertEqual(payload["log_entries"][0]["sync_id"], "sync-live-1")

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
    def test_http_connections_can_delete_profile(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-delete-connection.sqlite3"
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

        create_response = client.post(
            "/app/connections",
            data={
                "_csrf": self.csrf_token(client),
                "provider": "exchange",
                "display_name": "Delete Exchange",
                "blocked_title": "Blocked",
                "timeout_sec": "30",
                "exchange_tenant_id": "tenant-id",
                "exchange_client_id": "client-id",
                "exchange_client_secret": "secret-value",
                "exchange_user": "info@example.com",
            },
            follow_redirects=False,
        )
        self.assertEqual(create_response.status_code, 303)

        repository = AppRepository(Database(database_path), SecretBox(TEST_DATA_KEY))
        user = repository.get_user_by_email("owner@example.com")
        self.assertIsNotNone(user)
        assert user is not None
        connection = repository.find_connection_by_provider_and_name(int(user["id"]), "exchange", "Delete Exchange")
        self.assertIsNotNone(connection)
        assert connection is not None

        delete_response = client.post(
            f"/app/connections/{connection['id']}/delete",
            data={"_csrf": self.csrf_token(client)},
            follow_redirects=False,
        )
        self.assertEqual(delete_response.status_code, 303)
        self.assertEqual(delete_response.headers["location"], "/app/connections?provider=exchange&notice=deleted")
        self.assertIsNone(repository.get_connection(int(user["id"]), int(connection["id"])))

        connections_page = client.get(delete_response.headers["location"])
        self.assertEqual(connections_page.status_code, 200)
        self.assertNotIn("Delete Exchange", connections_page.text)
        self.assertIn("Eintrag gelöscht.", connections_page.text)

    @unittest.skipUnless(FASTAPI_AVAILABLE and CRYPTOGRAPHY_AVAILABLE, "webapp dependencies are not installed")
    def test_http_backup_manager_can_create_restore_download_and_delete_backups(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-backups.sqlite3"
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

        repository = AppRepository(Database(database_path))
        user = repository.get_user_by_email("owner@example.com")
        self.assertIsNotNone(user)
        assert user is not None
        repository.create_internal_event(
            int(user["id"]),
            title="Before Backup",
            starts_at="2026-03-10T09:00:00Z",
            ends_at="2026-03-10T10:00:00Z",
            description="seed event",
        )

        create_response = client.post(
            "/app/backups/create",
            data={"_csrf": self.csrf_token(client)},
            follow_redirects=False,
        )
        self.assertEqual(create_response.status_code, 303)
        self.assertIn("/app/backups?notice=backup-created", create_response.headers["location"])

        backup_files = sorted(settings.backup_directory.glob("*.zip"))
        self.assertEqual(len(backup_files), 1)
        backup_name = backup_files[0].name

        download_response = client.get(f"/app/backups/{backup_name}/download")
        self.assertEqual(download_response.status_code, 200)
        self.assertEqual(download_response.headers["content-type"], "application/zip")
        archive_path = Path(tempfile.mkdtemp()) / backup_name
        archive_path.write_bytes(download_response.content)
        with zipfile.ZipFile(archive_path, "r") as archive:
            names = set(archive.namelist())
        self.assertIn("manifest.json", names)
        self.assertIn("database.sqlite3", names)
        self.assertIn("connections-profile.json", names)

        repository.create_internal_event(
            int(user["id"]),
            title="After Backup",
            starts_at="2026-03-11T09:00:00Z",
            ends_at="2026-03-11T10:00:00Z",
            description="should disappear after restore",
        )
        self.assertEqual(repository.count_internal_events(int(user["id"])), 2)

        restore_response = client.post(
            f"/app/backups/{backup_name}/restore",
            data={
                "_csrf": self.csrf_token(client),
                "current_password": "very-long-secret-pass",
            },
            follow_redirects=False,
        )
        self.assertEqual(restore_response.status_code, 303)
        self.assertEqual(restore_response.headers["location"], "/app/backups?notice=backup-restored")

        restored_repository = AppRepository(Database(database_path))
        restored_events = restored_repository.list_internal_events(int(user["id"]))
        self.assertEqual(len(restored_events), 1)
        self.assertEqual(restored_events[0]["title"], "Before Backup")

        delete_response = client.post(
            f"/app/backups/{backup_name}/delete",
            data={"_csrf": self.csrf_token(client)},
            follow_redirects=False,
        )
        self.assertEqual(delete_response.status_code, 303)
        self.assertEqual(delete_response.headers["location"], "/app/backups?notice=backup-deleted")
        self.assertFalse((settings.backup_directory / backup_name).exists())

    @unittest.skipUnless(FASTAPI_AVAILABLE and CRYPTOGRAPHY_AVAILABLE, "webapp dependencies are not installed")
    def test_http_status_page_and_health_endpoints(self) -> None:
        database_path = Path(tempfile.mkdtemp()) / "http-status.sqlite3"
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

        health_response = client.get("/healthz")
        self.assertEqual(health_response.status_code, 200)
        self.assertIn(health_response.json()["status"], {"ok", "degraded"})
        self.assertTrue(any(item["label"] == "Datenbank" for item in health_response.json()["checks"]))

        ready_response = client.get("/readyz")
        self.assertEqual(ready_response.status_code, 200)
        self.assertEqual(ready_response.json()["status"], "ready")

        status_response = client.get("/app/status")
        self.assertEqual(status_response.status_code, 200)
        self.assertIn("Status-Monitor", status_response.text)
        self.assertIn("Datenbank", status_response.text)
        self.assertIn("Backup-Verzeichnis", status_response.text)
        self.assertIn("/healthz", status_response.text)
        self.assertIn("/readyz", status_response.text)

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
