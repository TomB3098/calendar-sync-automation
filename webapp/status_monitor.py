from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .security import now_utc


class StatusMonitor:
    def __init__(self, database_path: Path, backup_directory: Path, app_name: str):
        self.database_path = database_path
        self.backup_directory = backup_directory
        self.app_name = app_name

    def service_snapshot(
        self,
        *,
        repository: Any,
        auto_sync_worker: Any,
        user: Optional[Dict[str, Any]] = None,
        backup_count: int = 0,
    ) -> Dict[str, Any]:
        checks = [
            self._database_check(),
            self._backup_directory_check(),
            self._autosync_check(auto_sync_worker),
        ]
        latest_job = repository.get_latest_sync_job_for_user(int(user["id"])) if user else None
        running_job = repository.get_running_sync_job(int(user["id"])) if user else None
        active_connections = len(repository.list_active_connections(int(user["id"]))) if user else 0
        total_connections = len(repository.list_connections(int(user["id"]))) if user else 0

        overall = "ok"
        if any(check["status"] == "error" for check in checks):
            overall = "error"
        elif any(check["status"] == "warn" for check in checks):
            overall = "degraded"

        if latest_job and str(latest_job.get("status") or "").strip().lower() in {"failed", "completed_with_errors", "abandoned"}:
            if overall == "ok":
                overall = "degraded"

        return {
            "timestamp": now_utc().isoformat().replace("+00:00", "Z"),
            "app_name": self.app_name,
            "overall_status": overall,
            "checks": checks,
            "database_path": str(self.database_path),
            "backup_directory": str(self.backup_directory),
            "backup_count": backup_count,
            "latest_job": latest_job,
            "running_job": running_job,
            "active_connection_count": active_connections,
            "connection_count": total_connections,
        }

    def health_payload(self, *, repository: Any, auto_sync_worker: Any) -> Dict[str, Any]:
        checks = [
            self._database_check(),
            self._backup_directory_check(),
            self._autosync_check(auto_sync_worker),
        ]
        status = "ok"
        if any(check["status"] == "error" for check in checks):
            status = "error"
        elif any(check["status"] == "warn" for check in checks):
            status = "degraded"
        return {
            "status": status,
            "timestamp": now_utc().isoformat().replace("+00:00", "Z"),
            "app_name": self.app_name,
            "checks": checks,
        }

    def readiness_payload(self) -> Dict[str, Any]:
        database_check = self._database_check()
        ready = database_check["status"] == "ok"
        return {
            "status": "ready" if ready else "not-ready",
            "timestamp": now_utc().isoformat().replace("+00:00", "Z"),
            "app_name": self.app_name,
            "checks": [database_check],
        }

    def _database_check(self) -> Dict[str, str]:
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.database_path)
            try:
                connection.execute("SELECT 1").fetchone()
            finally:
                connection.close()
            return {
                "label": "Datenbank",
                "status": "ok",
                "detail": str(self.database_path),
            }
        except Exception as exc:
            return {
                "label": "Datenbank",
                "status": "error",
                "detail": str(exc),
            }

    def _backup_directory_check(self) -> Dict[str, str]:
        try:
            self.backup_directory.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=self.backup_directory, prefix=".backup-probe-", delete=True) as handle:
                handle.write(b"ok")
                handle.flush()
                os.fsync(handle.fileno())
            return {
                "label": "Backup-Verzeichnis",
                "status": "ok",
                "detail": str(self.backup_directory),
            }
        except Exception as exc:
            return {
                "label": "Backup-Verzeichnis",
                "status": "warn",
                "detail": str(exc),
            }

    def _autosync_check(self, auto_sync_worker: Any) -> Dict[str, str]:
        if auto_sync_worker is None:
            return {
                "label": "Auto-Sync-Worker",
                "status": "ok",
                "detail": "Deaktiviert per Konfiguration",
            }
        thread = getattr(auto_sync_worker, "_thread", None)
        if thread is not None and getattr(thread, "is_alive", None) and thread.is_alive():
            return {
                "label": "Auto-Sync-Worker",
                "status": "ok",
                "detail": "Aktiv",
            }
        return {
            "label": "Auto-Sync-Worker",
            "status": "warn",
            "detail": "Gestartet, aber aktuell nicht aktiv",
        }
