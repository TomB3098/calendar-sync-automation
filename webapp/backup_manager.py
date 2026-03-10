from __future__ import annotations

import json
import re
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .security import iso_z, now_utc


BACKUP_KIND = "aether-calendar-backup"
BACKUP_VERSION = 1
BACKUP_DB_FILENAME = "database.sqlite3"
BACKUP_MANIFEST_FILENAME = "manifest.json"
BACKUP_CONNECTIONS_FILENAME = "connections-profile.json"
BACKUP_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+\.zip$")


class BackupManager:
    def __init__(self, database_path: Path, backup_directory: Path, app_name: str):
        self.database_path = database_path
        self.backup_directory = backup_directory
        self.app_name = app_name

    def ensure_directory(self) -> None:
        self.backup_directory.mkdir(parents=True, exist_ok=True)

    def create_backup(
        self,
        *,
        created_by: str,
        connections_profile: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self.ensure_directory()
        created_at = iso_z(now_utc())
        backup_name = f"aether-backup-{created_at.replace(':', '').replace('-', '')}.zip"
        backup_path = self.backup_directory / backup_name

        with tempfile.TemporaryDirectory(prefix="aether-backup-") as tmpdir:
            snapshot_path = Path(tmpdir) / BACKUP_DB_FILENAME
            self._snapshot_database(snapshot_path)
            manifest = self._build_manifest(snapshot_path, created_at, created_by, connections_profile is not None)
            with zipfile.ZipFile(backup_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.write(snapshot_path, arcname=BACKUP_DB_FILENAME)
                archive.writestr(BACKUP_MANIFEST_FILENAME, json.dumps(manifest, ensure_ascii=False, indent=2))
                if connections_profile is not None:
                    archive.writestr(
                        BACKUP_CONNECTIONS_FILENAME,
                        json.dumps(connections_profile, ensure_ascii=False, indent=2),
                    )

        return self.get_backup_info(backup_name) or {}

    def list_backups(self) -> List[Dict[str, Any]]:
        self.ensure_directory()
        backups: List[Dict[str, Any]] = []
        for path in sorted(self.backup_directory.glob("*.zip"), key=lambda item: item.name, reverse=True):
            info = self._read_backup(path)
            if info:
                backups.append(info)
        return backups

    def get_backup_info(self, backup_name: str) -> Optional[Dict[str, Any]]:
        return self._read_backup(self._resolve_backup_path(backup_name))

    def get_backup_path(self, backup_name: str) -> Path:
        return self._resolve_backup_path(backup_name)

    def restore_backup(self, backup_name: str) -> Dict[str, Any]:
        backup_path = self._resolve_backup_path(backup_name)
        info = self._read_backup(backup_path)
        if not info:
            raise FileNotFoundError("Backup nicht gefunden.")
        with tempfile.TemporaryDirectory(prefix="aether-restore-") as tmpdir:
            extracted_path = Path(tmpdir) / BACKUP_DB_FILENAME
            with zipfile.ZipFile(backup_path, "r") as archive:
                with archive.open(BACKUP_DB_FILENAME, "r") as source, extracted_path.open("wb") as target:
                    target.write(source.read())
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            source_db = sqlite3.connect(extracted_path)
            target_db = sqlite3.connect(self.database_path)
            try:
                source_db.backup(target_db)
            finally:
                target_db.close()
                source_db.close()
        return info

    def delete_backup(self, backup_name: str) -> None:
        backup_path = self._resolve_backup_path(backup_name)
        backup_path.unlink(missing_ok=False)

    def _resolve_backup_path(self, backup_name: str) -> Path:
        normalized = backup_name.strip()
        if not BACKUP_NAME_RE.match(normalized):
            raise ValueError("Ungültiger Backup-Dateiname.")
        path = (self.backup_directory / normalized).resolve()
        backup_root = self.backup_directory.resolve()
        if backup_root not in path.parents and path != backup_root:
            raise ValueError("Ungültiger Backup-Dateiname.")
        return path

    def _snapshot_database(self, snapshot_path: Path) -> None:
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        source_db = sqlite3.connect(self.database_path)
        snapshot_db = sqlite3.connect(snapshot_path)
        try:
            source_db.backup(snapshot_db)
        finally:
            snapshot_db.close()
            source_db.close()

    def _build_manifest(
        self,
        snapshot_path: Path,
        created_at: str,
        created_by: str,
        includes_connections_profile: bool,
    ) -> Dict[str, Any]:
        counts = self._snapshot_counts(snapshot_path)
        return {
            "kind": BACKUP_KIND,
            "version": BACKUP_VERSION,
            "created_at": created_at,
            "created_by": created_by,
            "app_name": self.app_name,
            "database_file": self.database_path.name,
            "database_size_bytes": snapshot_path.stat().st_size,
            "includes_connections_profile": includes_connections_profile,
            "counts": counts,
        }

    def _snapshot_counts(self, snapshot_path: Path) -> Dict[str, int]:
        tables = (
            "users",
            "calendar_connections",
            "internal_events",
            "event_links",
            "sync_jobs",
            "sync_log_entries",
        )
        counts: Dict[str, int] = {}
        connection = sqlite3.connect(snapshot_path)
        try:
            connection.row_factory = sqlite3.Row
            for table in tables:
                row = connection.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
                counts[table] = int(row["count"] if row else 0)
        finally:
            connection.close()
        return counts

    def _read_backup(self, backup_path: Path) -> Optional[Dict[str, Any]]:
        if not backup_path.exists() or not backup_path.is_file():
            return None
        try:
            with zipfile.ZipFile(backup_path, "r") as archive:
                manifest = json.loads(archive.read(BACKUP_MANIFEST_FILENAME).decode("utf-8"))
        except Exception:
            manifest = {
                "kind": BACKUP_KIND,
                "version": BACKUP_VERSION,
                "created_at": "",
                "created_by": "",
                "app_name": self.app_name,
                "database_file": self.database_path.name,
                "database_size_bytes": backup_path.stat().st_size,
                "includes_connections_profile": False,
                "counts": {},
                "invalid": True,
            }
        counts = manifest.get("counts") if isinstance(manifest.get("counts"), dict) else {}
        return {
            "name": backup_path.name,
            "created_at": str(manifest.get("created_at") or ""),
            "created_by": str(manifest.get("created_by") or ""),
            "app_name": str(manifest.get("app_name") or self.app_name),
            "database_file": str(manifest.get("database_file") or self.database_path.name),
            "database_size_bytes": int(manifest.get("database_size_bytes") or backup_path.stat().st_size),
            "includes_connections_profile": bool(manifest.get("includes_connections_profile")),
            "counts": {key: int(value) for key, value in counts.items() if str(value).isdigit() or isinstance(value, int)},
            "invalid": bool(manifest.get("invalid")),
        }
