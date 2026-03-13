from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_csv(name: str, default: str) -> Tuple[str, ...]:
    raw = os.getenv(name, default)
    parts = [item.strip() for item in raw.split(",")]
    return tuple(item for item in parts if item)


@dataclass(frozen=True)
class AppSettings:
    app_name: str
    public_base_url: str
    database_path: Path
    backup_directory: Path
    legal_brand_name: str
    legal_business_name: str
    legal_representative_name: str
    legal_street: str
    legal_postal_city: str
    legal_email: str
    legal_phone: str
    legal_whatsapp: str
    legal_vat_id: str
    legal_website_url: str
    google_oauth_client_id: str
    google_oauth_client_secret: str
    app_secret: str
    data_encryption_key: str
    session_cookie_name: str
    session_cookie_domain: str | None
    session_cookie_samesite: str
    csrf_cookie_name: str
    session_ttl_hours: int
    sync_window_days: int
    provider_timeout_sec: int
    sync_job_stale_minutes: int
    auto_sync_poll_seconds: int
    auto_sync_worker_enabled: bool
    secure_cookies: bool
    force_https: bool
    allowed_hosts: Tuple[str, ...]
    login_rate_limit_attempts: int
    login_rate_limit_window_minutes: int
    hsts_seconds: int

    @classmethod
    def from_env(cls) -> "AppSettings":
        force_https = _env_bool("CAL_WEBAPP_FORCE_HTTPS", False)
        secure_cookies = _env_bool("CAL_WEBAPP_SECURE_COOKIES", force_https)
        same_site = os.getenv("CAL_WEBAPP_SESSION_COOKIE_SAMESITE", "lax").strip().lower() or "lax"
        if same_site not in {"lax", "strict", "none"}:
            same_site = "lax"
        database_path = Path(os.getenv("CAL_WEBAPP_DB_PATH", "data/calendar_webapp.sqlite3"))
        backup_directory = Path(os.getenv("CAL_WEBAPP_BACKUP_DIR", str(database_path.parent / "backups")))
        return cls(
            app_name=os.getenv("CAL_WEBAPP_NAME", "Aether Calendar Console"),
            public_base_url=os.getenv("CAL_WEBAPP_PUBLIC_BASE_URL", "").strip().rstrip("/"),
            database_path=database_path,
            backup_directory=backup_directory,
            legal_brand_name=os.getenv("CAL_WEBAPP_LEGAL_BRAND_NAME", "Webdesign Becker"),
            legal_business_name=os.getenv("CAL_WEBAPP_LEGAL_BUSINESS_NAME", "TB Media UG (haftungsbeschränkt)"),
            legal_representative_name=os.getenv("CAL_WEBAPP_LEGAL_REPRESENTATIVE_NAME", "Tom Becker"),
            legal_street=os.getenv("CAL_WEBAPP_LEGAL_STREET", "Siempelkampstraße 78"),
            legal_postal_city=os.getenv("CAL_WEBAPP_LEGAL_POSTAL_CITY", "47803 Krefeld"),
            legal_email=os.getenv("CAL_WEBAPP_LEGAL_EMAIL", "info@tb-media.net"),
            legal_phone=os.getenv("CAL_WEBAPP_LEGAL_PHONE", "02151 9288541"),
            legal_whatsapp=os.getenv("CAL_WEBAPP_LEGAL_WHATSAPP", "01525 8530929"),
            legal_vat_id=os.getenv("CAL_WEBAPP_LEGAL_VAT_ID", "DE366883061"),
            legal_website_url=os.getenv("CAL_WEBAPP_LEGAL_WEBSITE_URL", "https://webdesign-becker.de"),
            google_oauth_client_id=os.getenv("CAL_WEBAPP_GOOGLE_OAUTH_CLIENT_ID", "").strip(),
            google_oauth_client_secret=os.getenv("CAL_WEBAPP_GOOGLE_OAUTH_CLIENT_SECRET", "").strip(),
            app_secret=os.getenv("CAL_WEBAPP_SECRET", ""),
            data_encryption_key=os.getenv("CAL_WEBAPP_DATA_KEY", ""),
            session_cookie_name=os.getenv("CAL_WEBAPP_SESSION_COOKIE", "aether_session"),
            session_cookie_domain=os.getenv("CAL_WEBAPP_SESSION_COOKIE_DOMAIN", "").strip() or None,
            session_cookie_samesite=same_site,
            csrf_cookie_name=os.getenv("CAL_WEBAPP_CSRF_COOKIE", "aether_csrf"),
            session_ttl_hours=max(1, int(os.getenv("CAL_WEBAPP_SESSION_TTL_HOURS", "12"))),
            sync_window_days=max(1, int(os.getenv("CAL_WEBAPP_SYNC_WINDOW_DAYS", "90"))),
            provider_timeout_sec=max(5, int(os.getenv("CAL_WEBAPP_PROVIDER_TIMEOUT_SEC", "30"))),
            sync_job_stale_minutes=max(5, int(os.getenv("CAL_WEBAPP_SYNC_JOB_STALE_MINUTES", "120"))),
            auto_sync_poll_seconds=max(5, int(os.getenv("CAL_WEBAPP_AUTOSYNC_POLL_SECONDS", "30"))),
            auto_sync_worker_enabled=_env_bool("CAL_WEBAPP_ENABLE_AUTOSYNC_WORKER", True),
            secure_cookies=secure_cookies,
            force_https=force_https,
            allowed_hosts=_env_csv("CAL_WEBAPP_ALLOWED_HOSTS", "127.0.0.1,localhost,::1,testserver"),
            login_rate_limit_attempts=max(3, int(os.getenv("CAL_WEBAPP_LOGIN_RATE_LIMIT_ATTEMPTS", "5"))),
            login_rate_limit_window_minutes=max(1, int(os.getenv("CAL_WEBAPP_LOGIN_RATE_LIMIT_WINDOW_MINUTES", "15"))),
            hsts_seconds=max(0, int(os.getenv("CAL_WEBAPP_HSTS_SECONDS", "31536000" if force_https else "0"))),
        )
