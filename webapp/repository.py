from __future__ import annotations

import json
import uuid
from typing import Any, Dict, Iterable, List, Optional

from .database import Database
from .security import SecretBox, iso_z, now_utc


USER_SELECT_FIELDS = """
    id,
    email,
    password_hash,
    auto_sync_interval_minutes,
    two_factor_enabled,
    two_factor_secret,
    two_factor_pending_secret,
    created_at
"""


def _row_to_dict(row: Any) -> Dict[str, Any]:
    return dict(row) if row is not None else {}


class AppRepository:
    def __init__(self, database: Database, secret_box: Optional[SecretBox] = None):
        self.database = database
        self.secret_box = secret_box

    def count_users(self) -> int:
        with self.database.connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()
        return int(row["count"] if row else 0)

    def create_user(self, email: str, password_hash: str) -> Dict[str, Any]:
        created_at = iso_z(now_utc())
        with self.database.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO users (email, password_hash, auto_sync_interval_minutes, created_at) VALUES (?, ?, 0, ?)",
                (email.strip().lower(), password_hash, created_at),
            )
            user_id = int(cursor.lastrowid)
        return self.get_user(user_id)

    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            row = connection.execute(
                f"SELECT {USER_SELECT_FIELDS} FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        return self._user_row(row) if row else None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            row = connection.execute(
                f"SELECT {USER_SELECT_FIELDS} FROM users WHERE email = ?",
                (email.strip().lower(),),
            ).fetchone()
        return self._user_row(row) if row else None

    def update_user_password(self, user_id: int, password_hash: str) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, user_id),
            )
        return self.get_user(user_id)

    def update_user_auto_sync_interval(self, user_id: int, minutes: int) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE users SET auto_sync_interval_minutes = ? WHERE id = ?",
                (max(0, int(minutes)), user_id),
            )
        return self.get_user(user_id)

    def begin_user_two_factor_setup(self, user_id: int, pending_secret: str) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE users SET two_factor_pending_secret = ? WHERE id = ?",
                (self._encode_user_secret(pending_secret), user_id),
            )
        return self.get_user(user_id)

    def clear_user_two_factor_pending_secret(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE users SET two_factor_pending_secret = '' WHERE id = ?",
                (user_id,),
            )
        return self.get_user(user_id)

    def enable_user_two_factor(self, user_id: int, secret: str) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE users
                SET two_factor_enabled = 1,
                    two_factor_secret = ?,
                    two_factor_pending_secret = ''
                WHERE id = ?
                """,
                (self._encode_user_secret(secret), user_id),
            )
        return self.get_user(user_id)

    def disable_user_two_factor(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE users
                SET two_factor_enabled = 0,
                    two_factor_secret = '',
                    two_factor_pending_secret = ''
                WHERE id = ?
                """,
                (user_id,),
            )
        return self.get_user(user_id)

    def list_users_with_auto_sync(self) -> List[Dict[str, Any]]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    email,
                    password_hash,
                    auto_sync_interval_minutes,
                    two_factor_enabled,
                    two_factor_secret,
                    two_factor_pending_secret,
                    created_at
                FROM users
                WHERE auto_sync_interval_minutes > 0
                ORDER BY id ASC
                """
            ).fetchall()
        return [self._user_row(row) for row in rows]

    def get_latest_sync_job_for_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM sync_jobs
                WHERE user_id = ?
                ORDER BY started_at DESC, id DESC
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()
        return _row_to_dict(row) if row else None

    def record_login_attempt(self, email: str, ip_address: str, was_success: bool) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO auth_login_attempts (email, ip_address, was_success, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (email.strip().lower(), ip_address.strip(), 1 if was_success else 0, iso_z(now_utc())),
            )

    def recent_failed_login_attempts(self, email: str, ip_address: str, since: str) -> Dict[str, int]:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    COALESCE(SUM(CASE WHEN email = ? THEN 1 ELSE 0 END), 0) AS email_failures,
                    COALESCE(SUM(CASE WHEN ip_address = ? THEN 1 ELSE 0 END), 0) AS ip_failures
                FROM auth_login_attempts
                WHERE was_success = 0 AND created_at >= ?
                """,
                (email.strip().lower(), ip_address.strip(), since),
            ).fetchone()
        return {
            "email_failures": int(row["email_failures"] if row else 0),
            "ip_failures": int(row["ip_failures"] if row else 0),
        }

    def clear_login_attempts(self, email: str, ip_address: str) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                DELETE FROM auth_login_attempts
                WHERE email = ? AND ip_address = ?
                """,
                (email.strip().lower(), ip_address.strip()),
            )

    def list_internal_events(self, user_id: int, include_deleted: bool = False) -> List[Dict[str, Any]]:
        sql = """
            SELECT *
            FROM internal_events
            WHERE user_id = ?
        """
        params: List[Any] = [user_id]
        if not include_deleted:
            sql += " AND deleted_at IS NULL"
        sql += " ORDER BY starts_at ASC, id ASC"
        with self.database.connect() as connection:
            rows = connection.execute(sql, params).fetchall()
        return [self._event_row(row) for row in rows]

    def get_internal_event(self, user_id: int, event_id: int) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM internal_events WHERE user_id = ? AND id = ?",
                (user_id, event_id),
            ).fetchone()
        return self._event_row(row) if row else None

    def find_internal_event_by_sync_id(self, user_id: int, sync_id: str) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM internal_events WHERE user_id = ? AND sync_id = ?",
                (user_id, sync_id),
            ).fetchone()
        return self._event_row(row) if row else None

    def create_internal_event(
        self,
        user_id: int,
        *,
        title: str,
        starts_at: str,
        ends_at: str,
        description: str = "",
        location: str = "",
        is_all_day: bool = False,
        recurrence_rule: str = "",
        source_provider: str = "webapp",
        source_connection_id: Optional[int] = None,
        origin_provider: Optional[str] = None,
        origin_connection_id: Optional[int] = None,
        sync_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        created_at = iso_z(now_utc())
        sync_id_value = sync_id or f"webapp-{uuid.uuid4().hex}"
        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO internal_events (
                    user_id, sync_id, title, description, location, starts_at, ends_at,
                    is_all_day, recurrence_rule, source_provider, source_connection_id,
                    origin_provider, origin_connection_id, created_at, updated_at, deleted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    user_id,
                    sync_id_value,
                    title.strip() or "(ohne Betreff)",
                    description.strip(),
                    location.strip(),
                    starts_at,
                    ends_at,
                    1 if is_all_day else 0,
                    recurrence_rule.strip(),
                    source_provider,
                    source_connection_id,
                    (origin_provider or source_provider or "webapp").strip() or "webapp",
                    origin_connection_id if origin_connection_id is not None else source_connection_id,
                    created_at,
                    created_at,
                ),
            )
            event_id = int(cursor.lastrowid)
        return self.get_internal_event(user_id, event_id) or {}

    def update_internal_event(self, user_id: int, event_id: int, **fields: Any) -> Optional[Dict[str, Any]]:
        allowed = {
            "title",
            "description",
            "location",
            "starts_at",
            "ends_at",
            "is_all_day",
            "recurrence_rule",
            "source_provider",
            "source_connection_id",
            "origin_provider",
            "origin_connection_id",
            "deleted_at",
        }
        updates = {key: value for key, value in fields.items() if key in allowed}
        if not updates:
            return self.get_internal_event(user_id, event_id)

        assignments: List[str] = []
        params: List[Any] = []
        for key, value in updates.items():
            assignments.append(f"{key} = ?")
            if key == "is_all_day":
                params.append(1 if bool(value) else 0)
            else:
                params.append(value)
        assignments.append("updated_at = ?")
        params.append(iso_z(now_utc()))
        params.extend([user_id, event_id])

        with self.database.connect() as connection:
            connection.execute(
                f"UPDATE internal_events SET {', '.join(assignments)} WHERE user_id = ? AND id = ?",
                params,
            )
        return self.get_internal_event(user_id, event_id)

    def soft_delete_internal_event(self, user_id: int, event_id: int) -> Optional[Dict[str, Any]]:
        return self.update_internal_event(user_id, event_id, deleted_at=iso_z(now_utc()))

    def list_connections(self, user_id: int) -> List[Dict[str, Any]]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM calendar_connections
                WHERE user_id = ?
                ORDER BY created_at ASC, id ASC
                """,
                (user_id,),
            ).fetchall()
        return [self._connection_row(row) for row in rows]

    def list_active_connections(self, user_id: int) -> List[Dict[str, Any]]:
        return [row for row in self.list_connections(user_id) if row["is_active"]]

    def get_connection(self, user_id: int, connection_id: int) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM calendar_connections WHERE user_id = ? AND id = ?",
                (user_id, connection_id),
            ).fetchone()
        return self._connection_row(row) if row else None

    def find_connection_by_provider_and_name(self, user_id: int, provider: str, display_name: str) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM calendar_connections
                WHERE user_id = ? AND provider = ? AND display_name = ?
                ORDER BY id ASC
                LIMIT 1
                """,
                (user_id, provider.strip().lower(), display_name.strip()),
            ).fetchone()
        return self._connection_row(row) if row else None

    def create_connection(
        self,
        user_id: int,
        *,
        provider: str,
        display_name: str,
        sync_mode: str,
        blocked_title: str,
        settings: Dict[str, Any],
    ) -> Dict[str, Any]:
        created_at = iso_z(now_utc())
        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO calendar_connections (
                    user_id, provider, display_name, sync_mode, blocked_title,
                    is_active, settings_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    user_id,
                    provider,
                    display_name.strip(),
                    sync_mode,
                    blocked_title.strip() or "Blocked",
                    self._encode_settings(settings),
                    created_at,
                    created_at,
                ),
            )
            connection_id = int(cursor.lastrowid)
        return self.get_connection(user_id, connection_id) or {}

    def update_connection(
        self,
        user_id: int,
        connection_id: int,
        *,
        display_name: str,
        sync_mode: str,
        blocked_title: str,
        settings: Dict[str, Any],
        is_active: Optional[bool] = None,
    ) -> Optional[Dict[str, Any]]:
        updates = [
            "display_name = ?",
            "sync_mode = ?",
            "blocked_title = ?",
            "settings_json = ?",
            "updated_at = ?",
        ]
        params: List[Any] = [
            display_name.strip(),
            sync_mode.strip(),
            blocked_title.strip() or "Blocked",
            self._encode_settings(settings),
            iso_z(now_utc()),
        ]
        if is_active is not None:
            updates.insert(3, "is_active = ?")
            params.insert(3, 1 if is_active else 0)
        params.extend([user_id, connection_id])
        with self.database.connect() as connection:
            connection.execute(
                f"""
                UPDATE calendar_connections
                SET {', '.join(updates)}
                WHERE user_id = ? AND id = ?
                """,
                params,
            )
        return self.get_connection(user_id, connection_id)

    def reencrypt_legacy_connection_settings(self) -> int:
        if not self.secret_box:
            return 0
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT id, settings_json FROM calendar_connections ORDER BY id ASC"
            ).fetchall()
            updated = 0
            for row in rows:
                raw = str(row["settings_json"] or "")
                if self.secret_box.is_encrypted(raw):
                    continue
                decoded = self._decode_settings(raw)
                connection.execute(
                    "UPDATE calendar_connections SET settings_json = ? WHERE id = ?",
                    (self._encode_settings(decoded), int(row["id"])),
                )
                updated += 1
        return updated

    def toggle_connection(self, user_id: int, connection_id: int) -> Optional[Dict[str, Any]]:
        connection = self.get_connection(user_id, connection_id)
        if not connection:
            return None
        updated_at = iso_z(now_utc())
        with self.database.connect() as db:
            db.execute(
                """
                UPDATE calendar_connections
                SET is_active = ?, updated_at = ?
                WHERE user_id = ? AND id = ?
                """,
                (0 if connection["is_active"] else 1, updated_at, user_id, connection_id),
            )
        return self.get_connection(user_id, connection_id)

    def create_sync_job(self, user_id: int, triggered_by: str, message: str = "", status: str = "running") -> Dict[str, Any]:
        created_at = iso_z(now_utc())
        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO sync_jobs (user_id, status, triggered_by, message, created_at, started_at, finished_at)
                VALUES (?, ?, ?, ?, ?, ?, NULL)
                """,
                (user_id, status, triggered_by, message, created_at, created_at),
            )
            job_id = int(cursor.lastrowid)
        return self.get_sync_job(job_id) or {}

    def get_sync_job(self, job_id: int) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM sync_jobs WHERE id = ?", (job_id,)).fetchone()
        return _row_to_dict(row) if row else None

    def get_running_sync_job(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM sync_jobs
                WHERE user_id = ? AND status = 'running'
                ORDER BY started_at DESC, id DESC
                LIMIT 1
                """,
                (user_id,),
            ).fetchone()
        return _row_to_dict(row) if row else None

    def expire_stale_running_sync_jobs(self, user_id: int, stale_before: str, message: str) -> int:
        finished_at = iso_z(now_utc())
        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE sync_jobs
                SET status = 'abandoned', message = ?, finished_at = ?
                WHERE user_id = ? AND status = 'running' AND started_at < ?
                """,
                (message, finished_at, user_id, stale_before),
            )
        return int(cursor.rowcount or 0)

    def finish_sync_job(self, job_id: int, status: str, message: str = "") -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE sync_jobs
                SET status = ?, message = ?, finished_at = ?
                WHERE id = ?
                """,
                (status, message, iso_z(now_utc()), job_id),
            )
        return self.get_sync_job(job_id)

    def add_sync_log(
        self,
        job_id: int,
        *,
        level: str,
        message: str,
        provider: str = "",
        action: str = "",
        sync_id: str = "",
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO sync_log_entries (
                    job_id, level, provider, action, sync_id, message, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    level,
                    provider,
                    action,
                    sync_id,
                    message,
                    json.dumps(payload or {}, ensure_ascii=False),
                    iso_z(now_utc()),
                ),
            )

    def list_sync_jobs(self, user_id: int, limit: int = 20) -> List[Dict[str, Any]]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM sync_jobs
                WHERE user_id = ?
                ORDER BY started_at DESC, id DESC
                LIMIT ?
                """,
                (user_id, limit),
            ).fetchall()
        return [_row_to_dict(row) for row in rows]

    def list_sync_log_entries(self, user_id: int, limit: int = 200) -> List[Dict[str, Any]]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT logs.*, jobs.triggered_by
                FROM sync_log_entries AS logs
                JOIN sync_jobs AS jobs ON jobs.id = logs.job_id
                WHERE jobs.user_id = ?
                ORDER BY logs.created_at DESC, logs.id DESC
                LIMIT ?
                """,
                (user_id, limit),
            ).fetchall()
        return [self._sync_log_row(row) for row in rows]

    def get_link_by_connection_and_external_id(self, connection_id: int, external_event_id: str) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM event_links WHERE connection_id = ? AND external_event_id = ?",
                (connection_id, external_event_id),
            ).fetchone()
        return self._link_row(row) if row else None

    def get_link_by_event_and_connection(self, event_id: int, connection_id: int) -> Optional[Dict[str, Any]]:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM event_links WHERE event_id = ? AND connection_id = ? ORDER BY id DESC LIMIT 1",
                (event_id, connection_id),
            ).fetchone()
        return self._link_row(row) if row else None

    def list_links_for_connection(self, connection_id: int, include_deleted: bool = False) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM event_links WHERE connection_id = ?"
        params: List[Any] = [connection_id]
        if not include_deleted:
            sql += " AND deleted_at IS NULL"
        sql += " ORDER BY id ASC"
        with self.database.connect() as connection:
            rows = connection.execute(sql, params).fetchall()
        return [self._link_row(row) for row in rows]

    def list_links_for_event(self, event_id: int) -> List[Dict[str, Any]]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM event_links WHERE event_id = ? ORDER BY id ASC",
                (event_id,),
            ).fetchall()
        return [self._link_row(row) for row in rows]

    def upsert_event_link(
        self,
        user_id: int,
        event_id: int,
        connection_id: int,
        *,
        external_event_id: str,
        external_uid: str = "",
        sync_id: str,
        source: str = "",
        mode: str = "full",
        fingerprint: str = "",
        last_seen_at: Optional[str] = None,
        last_synced_at: Optional[str] = None,
        deleted_at: Optional[str] = None,
        provider_payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        existing = self.get_link_by_connection_and_external_id(connection_id, external_event_id)
        payload_json = json.dumps(provider_payload or {}, ensure_ascii=False)
        if existing:
            with self.database.connect() as connection:
                connection.execute(
                    """
                    UPDATE event_links
                    SET user_id = ?, event_id = ?, external_uid = ?, sync_id = ?, source = ?, mode = ?,
                        fingerprint = ?, last_seen_at = ?, last_synced_at = ?, deleted_at = ?, provider_payload_json = ?
                    WHERE id = ?
                    """,
                    (
                        user_id,
                        event_id,
                        external_uid,
                        sync_id,
                        source,
                        mode,
                        fingerprint,
                        last_seen_at,
                        last_synced_at,
                        deleted_at,
                        payload_json,
                        existing["id"],
                    ),
                )
            return self.get_link_by_connection_and_external_id(connection_id, external_event_id) or {}

        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO event_links (
                    user_id, event_id, connection_id, external_event_id, external_uid,
                    sync_id, source, mode, fingerprint, last_seen_at, last_synced_at,
                    deleted_at, provider_payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    event_id,
                    connection_id,
                    external_event_id,
                    external_uid,
                    sync_id,
                    source,
                    mode,
                    fingerprint,
                    last_seen_at,
                    last_synced_at,
                    deleted_at,
                    payload_json,
                ),
            )
            link_id = int(cursor.lastrowid)
        with self.database.connect() as connection:
            row = connection.execute("SELECT * FROM event_links WHERE id = ?", (link_id,)).fetchone()
        return self._link_row(row) if row else {}

    def mark_link_deleted(self, link_id: int) -> Optional[Dict[str, Any]]:
        deleted_at = iso_z(now_utc())
        with self.database.connect() as connection:
            connection.execute("UPDATE event_links SET deleted_at = ? WHERE id = ?", (deleted_at, link_id))
            row = connection.execute("SELECT * FROM event_links WHERE id = ?", (link_id,)).fetchone()
        return self._link_row(row) if row else None

    def _event_row(self, row: Any) -> Dict[str, Any]:
        data = _row_to_dict(row)
        if not data:
            return data
        data["is_all_day"] = bool(data["is_all_day"])
        return data

    def _user_row(self, row: Any) -> Dict[str, Any]:
        data = _row_to_dict(row)
        if not data:
            return data
        data["two_factor_enabled"] = bool(data.get("two_factor_enabled"))
        data["two_factor_secret"] = self._decode_user_secret(str(data.get("two_factor_secret") or ""))
        data["two_factor_pending_secret"] = self._decode_user_secret(str(data.get("two_factor_pending_secret") or ""))
        return data

    def _connection_row(self, row: Any) -> Dict[str, Any]:
        data = _row_to_dict(row)
        if not data:
            return data
        data["is_active"] = bool(data["is_active"])
        data["settings"] = self._decode_settings(data.pop("settings_json") or "{}")
        return data

    def _link_row(self, row: Any) -> Dict[str, Any]:
        data = _row_to_dict(row)
        if not data:
            return data
        data["provider_payload"] = json.loads(data.pop("provider_payload_json") or "{}")
        return data

    def _sync_log_row(self, row: Any) -> Dict[str, Any]:
        data = _row_to_dict(row)
        if not data:
            return data
        data["payload"] = json.loads(data.pop("payload_json") or "{}")
        return data

    def _encode_settings(self, settings: Dict[str, Any]) -> str:
        if self.secret_box:
            return self.secret_box.encrypt_mapping(settings)
        return json.dumps(settings, ensure_ascii=False)

    def _decode_settings(self, raw: str) -> Dict[str, Any]:
        if self.secret_box:
            return self.secret_box.decrypt_mapping(raw)
        value = (raw or "").strip()
        if value.startswith(SecretBox.prefix):
            raise RuntimeError("encrypted provider settings require CAL_WEBAPP_DATA_KEY")
        decoded = json.loads(value or "{}")
        return decoded if isinstance(decoded, dict) else {}

    def _encode_user_secret(self, value: str) -> str:
        if not value:
            return ""
        if self.secret_box:
            return self.secret_box.encrypt_text(value)
        return value

    def _decode_user_secret(self, raw: str) -> str:
        value = (raw or "").strip()
        if not value:
            return ""
        if self.secret_box:
            return self.secret_box.decrypt_text(value)
        if value.startswith(SecretBox.prefix):
            raise RuntimeError("encrypted user settings require CAL_WEBAPP_DATA_KEY")
        return value
