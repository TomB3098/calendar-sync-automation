from __future__ import annotations

import base64
import calendar as monthcalendar
import io
import json
import threading
from contextlib import asynccontextmanager
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sync_exchange_icloud_calendar import normalize_calendar_description, normalize_singleline_text
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

try:
    import qrcode
    from qrcode.image.svg import SvgPathImage

    QRCODE_AVAILABLE = True
except ModuleNotFoundError:
    qrcode = None
    SvgPathImage = None
    QRCODE_AVAILABLE = False

from .config import AppSettings
from .database import Database
from .repository import AppRepository
from .security import (
    CsrfManager,
    PendingLoginData,
    PendingLoginManager,
    PasswordHasher,
    SecretBox,
    SessionData,
    SessionManager,
    TotpManager,
    iso_z,
    mask_secret,
    now_utc,
    parse_utc,
    validate_password_policy,
)
from .sync_service import SOURCE_WEBAPP, SyncService


BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))
VALID_PROVIDERS = {"google", "exchange", "icloud"}
CONNECTION_PROFILE_KIND = "aether-calendar-connection-profile"
CONNECTION_PROFILE_VERSION = 1
PENDING_LOGIN_COOKIE_NAME = "aether_pending_2fa"
KNOWN_CONNECTION_SETTING_FIELDS = [
    "timeout_sec",
    "exchange_tenant_id",
    "exchange_client_id",
    "exchange_client_secret",
    "exchange_user",
    "icloud_user",
    "icloud_app_pw",
    "icloud_principal_path",
    "icloud_target_calendar_display",
    "google_calendar_id",
    "google_oauth_client_id",
    "google_oauth_client_secret",
    "google_oauth_refresh_token",
    "google_service_account_json",
    "google_impersonate_user",
]


class AutoSyncWorker:
    def __init__(self, repository: AppRepository, sync_service: SyncService, settings: AppSettings):
        self.repository = repository
        self.sync_service = sync_service
        self.settings = settings
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name="auto-sync-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def wake(self) -> None:
        self._run_once()

    def _run_loop(self) -> None:
        while not self._stop_event.wait(self.settings.auto_sync_poll_seconds):
            self._run_once()

    def _run_once(self) -> None:
        for user in self.repository.list_users_with_auto_sync():
            if self._stop_event.is_set():
                return
            user_id = int(user["id"])
            if self.repository.get_running_sync_job(user_id):
                continue
            interval_minutes = max(0, int(user.get("auto_sync_interval_minutes") or 0))
            if interval_minutes <= 0:
                continue
            latest_job = self.repository.get_latest_sync_job_for_user(user_id)
            latest_started = parse_utc(str(latest_job.get("started_at") or "")) if latest_job else None
            if latest_started and latest_started > now_utc() - timedelta(minutes=interval_minutes):
                continue
            job, started = self.sync_service.start_user_sync(user_id, "auto-sync")
            if job and started:
                _start_sync_thread(self.sync_service, user_id, int(job["id"]))


def create_app(settings: Optional[AppSettings] = None) -> FastAPI:
    settings = settings or AppSettings.from_env()
    _validate_security_settings(settings)

    database = Database(settings.database_path)
    database.initialize()
    secret_box = SecretBox(settings.data_encryption_key)
    repository = AppRepository(database, secret_box)
    repository.reencrypt_legacy_connection_settings()
    passwords = PasswordHasher()
    sessions = SessionManager(settings.app_secret, settings.session_ttl_hours)
    pending_logins = PendingLoginManager(settings.app_secret, ttl_minutes=10)
    csrf = CsrfManager(settings.app_secret, settings.session_ttl_hours)
    totp = TotpManager()
    sync_service = SyncService(repository, settings)
    auto_sync_worker = AutoSyncWorker(repository, sync_service, settings) if settings.auto_sync_worker_enabled else None

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> Any:
        if auto_sync_worker:
            auto_sync_worker.start()
        try:
            yield
        finally:
            if auto_sync_worker:
                auto_sync_worker.stop()

    app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.settings = settings
    app.state.database = database
    app.state.repository = repository
    app.state.passwords = passwords
    app.state.sessions = sessions
    app.state.pending_logins = pending_logins
    app.state.csrf = csrf
    app.state.totp = totp
    app.state.sync_service = sync_service
    app.state.auto_sync_worker = auto_sync_worker

    if settings.allowed_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
    if settings.force_https:
        app.add_middleware(HTTPSRedirectMiddleware)
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        response = await call_next(request)
        _apply_security_headers(response, request, settings)
        return response

    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request) -> RedirectResponse:
        if repository.count_users() == 0:
            return _redirect("/setup")
        user = _current_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/login")
        return _redirect("/app/dashboard")

    @app.get("/setup", response_class=HTMLResponse)
    async def setup_page(request: Request) -> Any:
        if repository.count_users() > 0:
            return _redirect("/login")
        return _render_template(
            request,
            settings,
            csrf,
            "setup.html",
            {
                "title": "Ersten Zugang anlegen",
                "app_name": settings.app_name,
                "error_message": _setup_error_message(request),
            },
        )

    @app.post("/setup")
    async def setup_submit(request: Request) -> RedirectResponse:
        if repository.count_users() > 0:
            return _redirect("/login")
        form = await _validated_form(request, csrf, settings)
        if form is None:
            return _redirect("/setup?error=security")
        email = str(form.get("email") or "").strip().lower()
        password = str(form.get("password") or "")
        if not email or "@" not in email:
            return _redirect("/setup?error=email")
        password_error = validate_password_policy(password)
        if password_error:
            return _redirect("/setup?error=password")
        user = repository.create_user(email, passwords.hash_password(password))
        response = _redirect("/app/dashboard")
        _set_session_cookie(response, settings, sessions.create(int(user["id"])))
        _set_csrf_cookie(response, settings, csrf.issue(None))
        return response

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Any:
        if repository.count_users() == 0:
            return _redirect("/setup")
        if _current_user(request, repository, sessions, settings):
            return _redirect("/app/dashboard")
        if _pending_two_factor_user(request, repository, pending_logins):
            return _redirect("/login/2fa")
        return _render_template(
            request,
            settings,
            csrf,
            "login.html",
            {
                "title": "Anmelden",
                "app_name": settings.app_name,
                "error_message": _login_error_message(request),
            },
        )

    @app.post("/login")
    async def login_submit(request: Request) -> RedirectResponse:
        if repository.count_users() == 0:
            return _redirect("/setup")
        form = await _validated_form(request, csrf, settings)
        if form is None:
            return _redirect("/login?error=security")
        email = str(form.get("email") or "").strip().lower()
        password = str(form.get("password") or "")
        client_ip = _client_ip(request)
        if _login_rate_limited(repository, settings, email, client_ip):
            return _redirect("/login?error=rate-limit")

        user = repository.get_user_by_email(email)
        if not user or not passwords.verify_password(password, str(user["password_hash"])):
            repository.record_login_attempt(email, client_ip, False)
            return _redirect("/login?error=auth")

        if passwords.needs_rehash(str(user["password_hash"])):
            updated = repository.update_user_password(int(user["id"]), passwords.hash_password(password))
            if updated:
                user = updated

        if bool(user.get("two_factor_enabled")):
            response = _redirect("/login/2fa")
            _clear_session_cookie(response, settings)
            _set_pending_login_cookie(response, settings, pending_logins.create(int(user["id"])))
            _set_csrf_cookie(response, settings, csrf.issue(None))
            return response

        repository.record_login_attempt(email, client_ip, True)
        repository.clear_login_attempts(email, client_ip)
        response = _redirect("/app/dashboard")
        _clear_pending_login_cookie(response, settings)
        _set_session_cookie(response, settings, sessions.create(int(user["id"])))
        _set_csrf_cookie(response, settings, csrf.issue(None))
        return response

    @app.get("/login/2fa", response_class=HTMLResponse)
    async def login_two_factor_page(request: Request) -> Any:
        if repository.count_users() == 0:
            return _redirect("/setup")
        if _current_user(request, repository, sessions, settings):
            return _redirect("/app/dashboard")
        user = _pending_two_factor_user(request, repository, pending_logins)
        if not user:
            response = _redirect("/login?error=two-factor-expired")
            _clear_pending_login_cookie(response, settings)
            return response
        return _render_template(
            request,
            settings,
            csrf,
            "login_2fa.html",
            {
                "title": "Zwei-Faktor-Bestaetigung",
                "app_name": settings.app_name,
                "pending_email": str(user["email"]),
                "error_message": _two_factor_login_error_message(request),
            },
        )

    @app.post("/login/2fa")
    async def login_two_factor_submit(request: Request) -> RedirectResponse:
        if repository.count_users() == 0:
            return _redirect("/setup")
        form = await _validated_form(request, csrf, settings)
        if form is None:
            return _redirect("/login/2fa?error=security")
        pending = _current_pending_login(request, pending_logins)
        if not pending:
            response = _redirect("/login?error=two-factor-expired")
            _clear_pending_login_cookie(response, settings)
            return response
        user = repository.get_user(pending.user_id)
        if not user or not bool(user.get("two_factor_enabled")) or not str(user.get("two_factor_secret") or "").strip():
            response = _redirect("/login?error=two-factor-expired")
            _clear_pending_login_cookie(response, settings)
            return response

        client_ip = _client_ip(request)
        if _login_rate_limited(repository, settings, str(user["email"]), client_ip):
            return _redirect("/login/2fa?error=rate-limit")

        code = str(form.get("code") or "").strip()
        if not totp.verify_code(str(user["two_factor_secret"]), code):
            repository.record_login_attempt(str(user["email"]), client_ip, False)
            return _redirect("/login/2fa?error=auth")

        repository.record_login_attempt(str(user["email"]), client_ip, True)
        repository.clear_login_attempts(str(user["email"]), client_ip)
        response = _redirect("/app/dashboard")
        _clear_pending_login_cookie(response, settings)
        _set_session_cookie(response, settings, sessions.create(int(user["id"])))
        _set_csrf_cookie(response, settings, csrf.issue(None))
        return response

    @app.post("/logout")
    async def logout(request: Request) -> RedirectResponse:
        form = await _validated_form(request, csrf, settings)
        response = _redirect("/login")
        _clear_auth_cookies(response, settings)
        if form is None:
            return response
        return response

    @app.get("/app/dashboard", response_class=HTMLResponse)
    async def dashboard(request: Request) -> Any:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        connections = repository.list_connections(int(user["id"]))
        events = repository.list_internal_events(int(user["id"]))
        jobs = repository.list_sync_jobs(int(user["id"]), 8)
        running_job = repository.get_running_sync_job(int(user["id"]))
        context = _base_context(request, settings, user, "Dashboard")
        context.update(
            {
                "connection_count": len(connections),
                "active_connection_count": len([row for row in connections if row["is_active"]]),
                "event_count": len(events),
                "job_count": len(jobs),
                "jobs": jobs,
                "running_job": running_job,
                "auto_sync_interval_minutes": int(user.get("auto_sync_interval_minutes") or 0),
                "auto_sync_status": _auto_sync_status(user),
                "page_notice": _page_notice(request),
            }
        )
        return _render_template(request, settings, csrf, "dashboard.html", context)

    @app.get("/app/calendar", response_class=HTMLResponse)
    async def calendar_view(request: Request) -> Any:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        raw_events = repository.list_internal_events(int(user["id"]))
        events = [_event_for_template(event) for event in raw_events]
        edit_id = request.query_params.get("edit")
        edit_event = repository.get_internal_event(int(user["id"]), int(edit_id)) if edit_id and edit_id.isdigit() else None
        month_anchor = _parse_calendar_month(str(request.query_params.get("month") or ""))
        calendar_view_data = _build_calendar_month(events, month_anchor)
        context = _base_context(request, settings, user, "Kalender")
        context.update(
            {
                "events": events,
                "calendar_month": calendar_view_data,
                "edit_event": _event_for_template(edit_event) if edit_event else None,
                "page_notice": _page_notice(request),
            }
        )
        return _render_template(request, settings, csrf, "calendar.html", context)

    @app.post("/app/events")
    async def save_event(request: Request) -> RedirectResponse:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        form = await _validated_form(request, csrf, settings)
        if form is None:
            return _redirect("/app/calendar?error=security")
        event_id = str(form.get("event_id") or "").strip()
        title = normalize_singleline_text(str(form.get("title") or ""))
        starts_at = _normalise_form_datetime(str(form.get("starts_at") or ""))
        ends_at = _normalise_form_datetime(str(form.get("ends_at") or ""))
        description = normalize_calendar_description(str(form.get("description") or ""), source_format="auto")
        location = normalize_singleline_text(str(form.get("location") or ""))
        recurrence_rule = str(form.get("recurrence_rule") or "").strip()
        if not title or not starts_at or not ends_at or len(title) > 200 or len(description) > 5000 or len(location) > 300:
            return _redirect("/app/calendar?error=validation")
        starts_at_dt = parse_utc(starts_at)
        ends_at_dt = parse_utc(ends_at)
        if not starts_at_dt or not ends_at_dt or ends_at_dt <= starts_at_dt:
            return _redirect("/app/calendar?error=validation")

        fields = {
            "title": title,
            "description": description,
            "location": location,
            "starts_at": starts_at,
            "ends_at": ends_at,
            "is_all_day": False,
            "recurrence_rule": recurrence_rule,
            "source_provider": SOURCE_WEBAPP,
            "source_connection_id": None,
            "deleted_at": None,
        }
        if event_id.isdigit():
            repository.update_internal_event(int(user["id"]), int(event_id), **fields)
        else:
            create_fields = dict(fields)
            create_fields.pop("deleted_at", None)
            repository.create_internal_event(int(user["id"]), **create_fields)
        return _redirect("/app/calendar?notice=saved")

    @app.post("/app/events/{event_id}/delete")
    async def delete_event(request: Request, event_id: int) -> RedirectResponse:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        form = await _validated_form(request, csrf, settings)
        if form is None:
            return _redirect("/app/calendar?error=security")
        repository.soft_delete_internal_event(int(user["id"]), event_id)
        return _redirect("/app/calendar?notice=deleted")

    @app.get("/app/connections", response_class=HTMLResponse)
    async def connections_view(request: Request) -> Any:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        connections = [_connection_for_template(connection) for connection in repository.list_connections(int(user["id"]))]
        context = _base_context(request, settings, user, "Verbindungen")
        context.update({"connections": connections, "page_notice": _page_notice(request)})
        return _render_template(request, settings, csrf, "connections.html", context)

    @app.post("/app/connections")
    async def create_connection(request: Request) -> RedirectResponse:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        form = await _validated_form(request, csrf, settings)
        if form is None:
            return _redirect("/app/connections?error=security")
        provider = str(form.get("provider") or "").strip().lower()
        display_name = str(form.get("display_name") or "").strip()
        blocked_title = str(form.get("blocked_title") or "Blocked").strip() or "Blocked"
        if provider not in VALID_PROVIDERS or not display_name or len(display_name) > 120:
            return _redirect("/app/connections?error=validation")
        settings_payload = _extract_connection_settings(form)
        repository.create_connection(
            int(user["id"]),
            provider=provider,
            display_name=display_name,
            sync_mode=_default_sync_mode_for_provider(provider),
            blocked_title=blocked_title,
            settings=settings_payload,
        )
        return _redirect("/app/connections?notice=saved")

    @app.post("/app/connections/import")
    async def import_connections(request: Request) -> RedirectResponse:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        form = await _validated_form(request, csrf, settings)
        if form is None:
            return _redirect("/app/connections?error=security")
        upload = form.get("profile_file")
        if upload is None or not hasattr(upload, "read"):
            return _redirect("/app/connections?error=validation")
        try:
            raw_bytes = await upload.read()
            profile = _parse_connection_profile(raw_bytes.decode("utf-8"))
        except Exception:
            return _redirect("/app/connections?error=profile")
        finally:
            close_upload = getattr(upload, "close", None)
            if callable(close_upload):
                await close_upload()

        created_count = 0
        updated_count = 0
        for entry in profile["connections"]:
            existing = repository.find_connection_by_provider_and_name(
                int(user["id"]),
                str(entry["provider"]),
                str(entry["display_name"]),
            )
            sync_mode = str(entry.get("sync_mode") or _default_sync_mode_for_provider(str(entry["provider"])))
            if existing:
                repository.update_connection(
                    int(user["id"]),
                    int(existing["id"]),
                    display_name=str(entry["display_name"]),
                    sync_mode=sync_mode,
                    blocked_title=str(entry.get("blocked_title") or "Blocked"),
                    settings=dict(entry.get("settings") or {}),
                    is_active=bool(entry.get("is_active", True)),
                )
                updated_count += 1
            else:
                repository.create_connection(
                    int(user["id"]),
                    provider=str(entry["provider"]),
                    display_name=str(entry["display_name"]),
                    sync_mode=sync_mode,
                    blocked_title=str(entry.get("blocked_title") or "Blocked"),
                    settings=dict(entry.get("settings") or {}),
                )
                if not bool(entry.get("is_active", True)):
                    created = repository.find_connection_by_provider_and_name(
                        int(user["id"]),
                        str(entry["provider"]),
                        str(entry["display_name"]),
                    )
                    if created:
                        repository.update_connection(
                            int(user["id"]),
                            int(created["id"]),
                            display_name=str(entry["display_name"]),
                            sync_mode=sync_mode,
                            blocked_title=str(entry.get("blocked_title") or "Blocked"),
                            settings=dict(entry.get("settings") or {}),
                            is_active=False,
                        )
                created_count += 1
        return _redirect(f"/app/connections?notice=profile-imported&created={created_count}&updated={updated_count}")

    @app.get("/app/connections/export")
    async def export_all_connections(request: Request) -> Response:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        payload = _build_connection_profile_payload(repository.list_connections(int(user["id"])))
        return _json_download("aether-connections-profile.json", payload)

    @app.get("/app/connections/{connection_id}/export")
    async def export_connection(request: Request, connection_id: int) -> Response:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        connection = repository.get_connection(int(user["id"]), connection_id)
        if not connection:
            return _redirect("/app/connections?error=validation")
        payload = _build_connection_profile_payload([connection])
        filename = f"aether-connection-{connection_id}.json"
        return _json_download(filename, payload)

    @app.post("/app/connections/{connection_id}/toggle")
    async def toggle_connection(request: Request, connection_id: int) -> RedirectResponse:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        form = await _validated_form(request, csrf, settings)
        if form is None:
            return _redirect("/app/connections?error=security")
        repository.toggle_connection(int(user["id"]), connection_id)
        return _redirect("/app/connections?notice=updated")

    @app.get("/app/settings", response_class=HTMLResponse)
    async def settings_view(request: Request) -> Any:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        pending_secret = str(user.get("two_factor_pending_secret") or "").strip()
        provisioning_uri = (
            totp.provisioning_uri(pending_secret, str(user["email"]), settings.app_name)
            if pending_secret
            else ""
        )
        context = _base_context(request, settings, user, "Benutzereinstellungen")
        context.update(
            {
                "page_notice": _page_notice(request),
                "two_factor_enabled": bool(user.get("two_factor_enabled")),
                "two_factor_pending": bool(pending_secret),
                "two_factor_setup_secret": _format_two_factor_secret(pending_secret),
                "two_factor_setup_uri": provisioning_uri,
                "two_factor_qr_data_uri": _totp_qr_data_uri(provisioning_uri),
                "two_factor_account_name": str(user["email"]),
            }
        )
        return _render_template(request, settings, csrf, "settings.html", context)

    @app.post("/app/settings/two-factor/setup")
    async def begin_two_factor_setup(request: Request) -> RedirectResponse:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        form = await _validated_form(request, csrf, settings)
        if form is None:
            return _redirect("/app/settings?error=security")
        if bool(user.get("two_factor_enabled")):
            return _redirect("/app/settings?error=two-factor")
        repository.begin_user_two_factor_setup(int(user["id"]), totp.generate_secret())
        return _redirect("/app/settings?notice=two-factor-setup-started")

    @app.post("/app/settings/two-factor/cancel")
    async def cancel_two_factor_setup(request: Request) -> RedirectResponse:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        form = await _validated_form(request, csrf, settings)
        if form is None:
            return _redirect("/app/settings?error=security")
        repository.clear_user_two_factor_pending_secret(int(user["id"]))
        return _redirect("/app/settings?notice=two-factor-setup-cancelled")

    @app.post("/app/settings/two-factor/enable")
    async def enable_two_factor(request: Request) -> RedirectResponse:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        form = await _validated_form(request, csrf, settings)
        if form is None:
            return _redirect("/app/settings?error=security")
        current_password = str(form.get("current_password") or "")
        code = str(form.get("code") or "").strip()
        pending_secret = str(user.get("two_factor_pending_secret") or "").strip()
        if (
            not pending_secret
            or not passwords.verify_password(current_password, str(user["password_hash"]))
            or not totp.verify_code(pending_secret, code)
        ):
            return _redirect("/app/settings?error=two-factor")
        repository.enable_user_two_factor(int(user["id"]), pending_secret)
        return _redirect("/app/settings?notice=two-factor-enabled")

    @app.post("/app/settings/two-factor/disable")
    async def disable_two_factor(request: Request) -> RedirectResponse:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        form = await _validated_form(request, csrf, settings)
        if form is None:
            return _redirect("/app/settings?error=security")
        current_password = str(form.get("current_password") or "")
        code = str(form.get("code") or "").strip()
        secret = str(user.get("two_factor_secret") or "").strip()
        if (
            not bool(user.get("two_factor_enabled"))
            or not secret
            or not passwords.verify_password(current_password, str(user["password_hash"]))
            or not totp.verify_code(secret, code)
        ):
            return _redirect("/app/settings?error=two-factor")
        repository.disable_user_two_factor(int(user["id"]))
        response = _redirect("/app/settings?notice=two-factor-disabled")
        _clear_pending_login_cookie(response, settings)
        return response

    @app.post("/app/settings/autosync")
    async def update_auto_sync(request: Request) -> RedirectResponse:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        form = await _validated_form(request, csrf, settings)
        if form is None:
            return _redirect("/app/dashboard?error=security")
        raw_value = str(form.get("auto_sync_interval_minutes") or "").strip()
        if not raw_value.isdigit():
            return _redirect("/app/dashboard?error=validation")
        minutes = int(raw_value)
        if minutes < 0 or minutes > 1440:
            return _redirect("/app/dashboard?error=validation")
        repository.update_user_auto_sync_interval(int(user["id"]), minutes)
        if auto_sync_worker and minutes > 0:
            auto_sync_worker.wake()
        return _redirect("/app/dashboard?notice=autosync-updated")

    @app.post("/app/sync")
    async def run_sync(request: Request) -> RedirectResponse:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        form = await _validated_form(request, csrf, settings)
        if form is None:
            return _redirect("/app/logs?error=security")
        job, started = sync_service.start_user_sync(int(user["id"]), str(user["email"]))
        if not job:
            return _redirect("/app/logs?sync=failed")
        if not started:
            return _redirect(f"/app/logs?sync=already-running&job_id={job['id']}")
        try:
            _start_sync_thread(sync_service, int(user["id"]), int(job["id"]))
        except Exception as exc:
            repository.finish_sync_job(int(job["id"]), "failed", f"Background start failed: {exc}")
            return _redirect(f"/app/logs?sync=failed&job_id={job['id']}")
        return _redirect(f"/app/logs?sync=started&job_id={job['id']}")

    @app.get("/app/logs", response_class=HTMLResponse)
    async def logs_view(request: Request) -> Any:
        user = _require_user(request, repository, sessions, settings)
        if not user:
            return _redirect("/setup" if repository.count_users() == 0 else "/login")
        running_job = repository.get_running_sync_job(int(user["id"]))
        context = _base_context(request, settings, user, "Sync-Logs")
        context.update(
            {
                "jobs": repository.list_sync_jobs(int(user["id"]), 25),
                "log_entries": [_log_entry_for_template(entry) for entry in repository.list_sync_log_entries(int(user["id"]), 250)],
                "running_job": running_job,
                "sync_notice": _sync_notice(request),
                "page_notice": _page_notice(request),
            }
        )
        return _render_template(request, settings, csrf, "logs.html", context)

    return app


def _validate_security_settings(settings: AppSettings) -> None:
    issues = []
    if not settings.app_secret or settings.app_secret == "change-me-in-production":
        issues.append("CAL_WEBAPP_SECRET must be set to a strong random value")
    if not settings.data_encryption_key:
        issues.append("CAL_WEBAPP_DATA_KEY must be set to a Fernet-compatible key")
    if settings.force_https and not settings.secure_cookies:
        issues.append("CAL_WEBAPP_SECURE_COOKIES must stay enabled when CAL_WEBAPP_FORCE_HTTPS=true")
    if settings.session_cookie_samesite == "none" and not settings.secure_cookies:
        issues.append("SameSite=None requires secure cookies")
    if settings.session_cookie_name.startswith("__Host-"):
        if not settings.secure_cookies:
            issues.append("__Host- cookies require CAL_WEBAPP_SECURE_COOKIES=true")
        if settings.session_cookie_domain:
            issues.append("__Host- cookies must not set CAL_WEBAPP_SESSION_COOKIE_DOMAIN")
    if settings.session_cookie_name.startswith("__Secure-") and not settings.secure_cookies:
        issues.append("__Secure- cookies require CAL_WEBAPP_SECURE_COOKIES=true")
    if not settings.allowed_hosts:
        issues.append("CAL_WEBAPP_ALLOWED_HOSTS must not be empty")
    if issues:
        raise RuntimeError("Invalid security configuration: " + "; ".join(issues))


def _apply_security_headers(response: Response, request: Request, settings: AppSettings) -> None:
    csp_parts = [
        "default-src 'self'",
        "style-src 'self' https://fonts.googleapis.com",
        "img-src 'self' data:",
        "script-src 'self'",
        "connect-src 'self'",
        "font-src 'self' https://fonts.gstatic.com data:",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
    if settings.force_https:
        csp_parts.append("upgrade-insecure-requests")
    response.headers.setdefault("Content-Security-Policy", "; ".join(csp_parts))
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    if settings.hsts_seconds > 0 and (settings.force_https or request.url.scheme == "https"):
        response.headers.setdefault("Strict-Transport-Security", f"max-age={settings.hsts_seconds}; includeSubDomains")
    if response.headers.get("content-type", "").startswith("text/html"):
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Pragma", "no-cache")


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _render_template(
    request: Request,
    settings: AppSettings,
    csrf: CsrfManager,
    template_name: str,
    context: Dict[str, Any],
) -> HTMLResponse:
    token = csrf.issue(request.cookies.get(settings.csrf_cookie_name))
    payload = {"request": request, "csrf_token": token}
    payload.update(context)
    response = TEMPLATES.TemplateResponse(request, template_name, payload)
    _set_csrf_cookie(response, settings, token)
    return response


def _set_session_cookie(response: Response, settings: AppSettings, token: str) -> None:
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=settings.secure_cookies,
        samesite=settings.session_cookie_samesite,
        max_age=settings.session_ttl_hours * 3600,
        path="/",
        domain=settings.session_cookie_domain,
    )


def _set_pending_login_cookie(response: Response, settings: AppSettings, token: str) -> None:
    response.set_cookie(
        PENDING_LOGIN_COOKIE_NAME,
        token,
        httponly=True,
        secure=settings.secure_cookies,
        samesite=settings.session_cookie_samesite,
        max_age=10 * 60,
        path="/",
        domain=settings.session_cookie_domain,
    )


def _set_csrf_cookie(response: Response, settings: AppSettings, token: str) -> None:
    response.set_cookie(
        settings.csrf_cookie_name,
        token,
        httponly=False,
        secure=settings.secure_cookies,
        samesite=settings.session_cookie_samesite,
        max_age=settings.session_ttl_hours * 3600,
        path="/",
        domain=settings.session_cookie_domain,
    )


def _clear_session_cookie(response: Response, settings: AppSettings) -> None:
    response.delete_cookie(
        settings.session_cookie_name,
        path="/",
        domain=settings.session_cookie_domain,
        secure=settings.secure_cookies,
        httponly=True,
        samesite=settings.session_cookie_samesite,
    )


def _clear_pending_login_cookie(response: Response, settings: AppSettings) -> None:
    response.delete_cookie(
        PENDING_LOGIN_COOKIE_NAME,
        path="/",
        domain=settings.session_cookie_domain,
        secure=settings.secure_cookies,
        httponly=True,
        samesite=settings.session_cookie_samesite,
    )


def _clear_auth_cookies(response: Response, settings: AppSettings) -> None:
    _clear_session_cookie(response, settings)
    _clear_pending_login_cookie(response, settings)
    response.delete_cookie(
        settings.csrf_cookie_name,
        path="/",
        domain=settings.session_cookie_domain,
        secure=settings.secure_cookies,
        httponly=False,
        samesite=settings.session_cookie_samesite,
    )


async def _validated_form(request: Request, csrf: CsrfManager, settings: AppSettings) -> Optional[Any]:
    form = await request.form()
    submitted = str(form.get("_csrf") or "")
    cookie = request.cookies.get(settings.csrf_cookie_name)
    if not csrf.validate(cookie, submitted):
        return None
    return form


def _current_session(request: Request, sessions: SessionManager, settings: AppSettings) -> Optional[SessionData]:
    return sessions.parse(request.cookies.get(settings.session_cookie_name))


def _current_pending_login(request: Request, pending_logins: PendingLoginManager) -> Optional[PendingLoginData]:
    return pending_logins.parse(request.cookies.get(PENDING_LOGIN_COOKIE_NAME))


def _current_user(
    request: Request,
    repository: AppRepository,
    sessions: SessionManager,
    settings: AppSettings,
) -> Optional[Dict[str, Any]]:
    session = _current_session(request, sessions, settings)
    if not session:
        return None
    return repository.get_user(session.user_id)


def _require_user(
    request: Request,
    repository: AppRepository,
    sessions: SessionManager,
    settings: AppSettings,
) -> Optional[Dict[str, Any]]:
    if repository.count_users() == 0:
        return None
    return _current_user(request, repository, sessions, settings)


def _pending_two_factor_user(
    request: Request,
    repository: AppRepository,
    pending_logins: PendingLoginManager,
) -> Optional[Dict[str, Any]]:
    pending = _current_pending_login(request, pending_logins)
    if not pending:
        return None
    user = repository.get_user(pending.user_id)
    if not user or not bool(user.get("two_factor_enabled")):
        return None
    return user


def _base_context(request: Request, settings: AppSettings, user: Dict[str, Any], title: str) -> Dict[str, Any]:
    return {
        "request": request,
        "title": title,
        "app_name": settings.app_name,
        "user": user,
        "now": now_utc(),
    }


def _client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return str(request.client.host)
    return "unknown"


def _login_rate_limited(repository: AppRepository, settings: AppSettings, email: str, client_ip: str) -> bool:
    since = iso_z(now_utc() - timedelta(minutes=settings.login_rate_limit_window_minutes))
    counters = repository.recent_failed_login_attempts(email, client_ip, since)
    return max(counters["email_failures"], counters["ip_failures"]) >= settings.login_rate_limit_attempts


def _page_notice(request: Request) -> Optional[str]:
    error = str(request.query_params.get("error") or "").strip().lower()
    notice = str(request.query_params.get("notice") or "").strip().lower()
    if notice == "saved":
        return "Aenderung gespeichert."
    if notice == "autosync-updated":
        return "Auto-Sync-Intervall gespeichert."
    if notice == "two-factor-setup-started":
        return "Einrichtungsschluessel erzeugt. Bitte in deiner Authenticator-App eintragen und mit Code bestaetigen."
    if notice == "two-factor-setup-cancelled":
        return "Die offene Zwei-Faktor-Einrichtung wurde verworfen."
    if notice == "two-factor-enabled":
        return "Zwei-Faktor-Authentifizierung wurde aktiviert."
    if notice == "two-factor-disabled":
        return "Zwei-Faktor-Authentifizierung wurde deaktiviert."
    if notice == "deleted":
        return "Eintrag geloescht."
    if notice == "updated":
        return "Status aktualisiert."
    if notice == "profile-imported":
        created = str(request.query_params.get("created") or "0")
        updated = str(request.query_params.get("updated") or "0")
        return f"Profil importiert. Neu: {created}, aktualisiert: {updated}."
    if error == "security":
        return "Die Anfrage wurde aus Sicherheitsgruenden abgelehnt."
    if error == "validation":
        return "Die Eingaben sind ungueltig oder unvollstaendig."
    if error == "profile":
        return "Die Profildatei ist ungueltig oder konnte nicht gelesen werden."
    if error == "two-factor":
        return "Die Zwei-Faktor-Aktion konnte nicht bestaetigt werden. Bitte Passwort und Code pruefen."
    return None


def _login_error_message(request: Request) -> Optional[str]:
    error = str(request.query_params.get("error") or "").strip().lower()
    if error == "security":
        return "Die Anfrage konnte nicht verifiziert werden. Bitte die Seite neu laden."
    if error == "rate-limit":
        return "Zu viele fehlgeschlagene Anmeldeversuche. Bitte spaeter erneut versuchen."
    if error == "auth":
        return "Anmeldung fehlgeschlagen."
    if error == "two-factor-expired":
        return "Die Zwei-Faktor-Bestaetigung ist abgelaufen. Bitte erneut anmelden."
    return None


def _two_factor_login_error_message(request: Request) -> Optional[str]:
    error = str(request.query_params.get("error") or "").strip().lower()
    if error == "security":
        return "Die Anfrage konnte nicht verifiziert werden. Bitte die Seite neu laden."
    if error == "rate-limit":
        return "Zu viele fehlgeschlagene Anmeldeversuche. Bitte spaeter erneut versuchen."
    if error == "auth":
        return "Der Zwei-Faktor-Code ist ungueltig."
    return None


def _setup_error_message(request: Request) -> Optional[str]:
    error = str(request.query_params.get("error") or "").strip().lower()
    if error == "security":
        return "Die Anfrage konnte nicht verifiziert werden. Bitte die Seite neu laden."
    if error == "email":
        return "Bitte eine gueltige E-Mail-Adresse angeben."
    if error == "password":
        return "Bitte ein ausreichend langes Passwort verwenden."
    return None


def _normalise_form_datetime(value: str) -> Optional[str]:
    raw = value.strip()
    if not raw:
        return None
    if len(raw) == 16:
        raw = raw + ":00"
    if raw.endswith("Z") or "+" in raw[10:]:
        parsed = parse_utc(raw)
    else:
        parsed = parse_utc(raw + "Z")
    return parsed.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z") if parsed else None


def _format_datetime_for_input(raw: str) -> str:
    parsed = parse_utc(raw)
    if not parsed:
        return ""
    return parsed.strftime("%Y-%m-%dT%H:%M")


def _format_datetime_for_humans(raw: str) -> str:
    parsed = parse_utc(raw)
    if not parsed:
        return raw
    return parsed.strftime("%Y-%m-%d %H:%M UTC")


def _format_two_factor_secret(secret: str) -> str:
    value = "".join(str(secret).strip().upper().split())
    if not value:
        return ""
    return " ".join(value[index : index + 4] for index in range(0, len(value), 4))


def _totp_qr_data_uri(provisioning_uri: str) -> str:
    if not provisioning_uri or not QRCODE_AVAILABLE or qrcode is None or SvgPathImage is None:
        return ""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
        image_factory=SvgPathImage,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    image = qr.make_image()
    buffer = io.BytesIO()
    image.save(buffer)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{encoded}"


def _format_time_badge(event: Dict[str, Any]) -> str:
    if bool(event.get("is_all_day")):
        return "Ganztag"
    starts_at = parse_utc(str(event.get("starts_at") or ""))
    ends_at = parse_utc(str(event.get("ends_at") or ""))
    if not starts_at or not ends_at:
        return ""
    if starts_at.date() == ends_at.date():
        return f"{starts_at.strftime('%H:%M')} - {ends_at.strftime('%H:%M')} UTC"
    return f"{starts_at.strftime('%d.%m %H:%M')} - {ends_at.strftime('%d.%m %H:%M')} UTC"


def _event_for_template(event: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not event:
        return None
    enriched = dict(event)
    enriched["title"] = normalize_singleline_text(str(event["title"]))
    enriched["description"] = normalize_calendar_description(str(event.get("description") or ""), source_format="auto")
    enriched["location"] = normalize_singleline_text(str(event.get("location") or ""))
    enriched["starts_at_input"] = _format_datetime_for_input(event["starts_at"])
    enriched["ends_at_input"] = _format_datetime_for_input(event["ends_at"])
    enriched["starts_at_human"] = _format_datetime_for_humans(event["starts_at"])
    enriched["ends_at_human"] = _format_datetime_for_humans(event["ends_at"])
    enriched["source_label"] = event["source_provider"] or "webapp"
    enriched["source_slug"] = str(event.get("source_provider") or "webapp").strip().lower()
    enriched["time_badge"] = _format_time_badge(event)
    return enriched


def _parse_calendar_month(raw: str) -> date:
    value = raw.strip()
    if len(value) == 7 and value[4] == "-":
        try:
            return date(int(value[:4]), int(value[5:7]), 1)
        except ValueError:
            pass
    today = now_utc().date()
    return date(today.year, today.month, 1)


def _shift_calendar_month(anchor: date, delta: int) -> date:
    year = anchor.year + ((anchor.month - 1 + delta) // 12)
    month = ((anchor.month - 1 + delta) % 12) + 1
    return date(year, month, 1)


def _calendar_month_label(anchor: date) -> str:
    month_names = [
        "Januar",
        "Februar",
        "Maerz",
        "April",
        "Mai",
        "Juni",
        "Juli",
        "August",
        "September",
        "Oktober",
        "November",
        "Dezember",
    ]
    return f"{month_names[anchor.month - 1]} {anchor.year}"


def _event_dates_for_calendar(event: Dict[str, Any], view_start: date, view_end: date) -> List[date]:
    starts_at = parse_utc(str(event.get("starts_at") or ""))
    ends_at = parse_utc(str(event.get("ends_at") or ""))
    if not starts_at:
        return []
    if not ends_at or ends_at < starts_at:
        ends_at = starts_at

    start_day = starts_at.date()
    if bool(event.get("is_all_day")):
        end_exclusive = ends_at.date()
        if end_exclusive <= start_day:
            end_exclusive = start_day + timedelta(days=1)
        end_day = end_exclusive - timedelta(days=1)
    else:
        end_day = (ends_at - timedelta(seconds=1)).date() if ends_at > starts_at else starts_at.date()
        if end_day < start_day:
            end_day = start_day

    clipped_start = max(start_day, view_start)
    clipped_end = min(end_day, view_end)
    if clipped_end < clipped_start:
        return []

    return [clipped_start + timedelta(days=index) for index in range((clipped_end - clipped_start).days + 1)]


def _calendar_chip_for_event(event: Dict[str, Any], day: date) -> Dict[str, Any]:
    starts_at = parse_utc(str(event.get("starts_at") or ""))
    ends_at = parse_utc(str(event.get("ends_at") or ""))
    is_first_day = bool(starts_at and starts_at.date() == day)
    is_last_day = bool(ends_at and ((ends_at - timedelta(seconds=1)).date() if ends_at > starts_at else ends_at.date()) == day)
    if bool(event.get("is_all_day")):
        badge = "Ganztag"
    elif starts_at and ends_at and starts_at.date() == day and ends_at.date() == day:
        badge = f"{starts_at.strftime('%H:%M')}"
    elif starts_at and starts_at.date() == day:
        badge = f"Start {starts_at.strftime('%H:%M')}"
    elif ends_at and is_last_day:
        badge = f"Bis {ends_at.strftime('%H:%M')}"
    else:
        badge = "Fortlaufend"
    return {
        "id": int(event["id"]),
        "title": str(event["title"]),
        "href": f"/app/calendar?month={day.strftime('%Y-%m')}&edit={int(event['id'])}",
        "time_badge": badge,
        "source_label": str(event.get("source_label") or "webapp"),
        "source_slug": str(event.get("source_slug") or "webapp"),
        "description": str(event.get("description") or ""),
        "starts_at_human": str(event.get("starts_at_human") or ""),
        "ends_at_human": str(event.get("ends_at_human") or ""),
        "continues_before": not is_first_day,
        "continues_after": not is_last_day,
    }


def _build_calendar_month(events: List[Dict[str, Any]], month_anchor: date) -> Dict[str, Any]:
    month_cal = monthcalendar.Calendar(firstweekday=0)
    weeks = month_cal.monthdatescalendar(month_anchor.year, month_anchor.month)
    view_start = weeks[0][0]
    view_end = weeks[-1][-1]
    event_map: Dict[date, List[Dict[str, Any]]] = {}

    visible_events: List[Dict[str, Any]] = []
    for event in events:
        active_days = _event_dates_for_calendar(event, view_start, view_end)
        if not active_days:
            continue
        visible_events.append(event)
        for day in active_days:
            event_map.setdefault(day, []).append(_calendar_chip_for_event(event, day))

    for day_events in event_map.values():
        day_events.sort(key=lambda item: (item["time_badge"] == "Ganztag", item["time_badge"], item["title"]))

    week_rows: List[List[Dict[str, Any]]] = []
    today = now_utc().date()
    for week in weeks:
        row: List[Dict[str, Any]] = []
        for day in week:
            day_events = event_map.get(day, [])
            row.append(
                {
                    "date_iso": day.isoformat(),
                    "day_number": day.day,
                    "weekday_label": ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"][day.weekday()],
                    "is_current_month": day.month == month_anchor.month,
                    "is_today": day == today,
                    "events": day_events[:5],
                    "overflow_count": max(0, len(day_events) - 5),
                }
            )
        week_rows.append(row)

    month_events = sorted(
        visible_events,
        key=lambda item: (str(item.get("starts_at") or ""), int(item.get("id") or 0)),
    )
    return {
        "label": _calendar_month_label(month_anchor),
        "value": month_anchor.strftime("%Y-%m"),
        "prev_value": _shift_calendar_month(month_anchor, -1).strftime("%Y-%m"),
        "next_value": _shift_calendar_month(month_anchor, 1).strftime("%Y-%m"),
        "weekday_labels": ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"],
        "weeks": week_rows,
        "events": month_events,
        "event_count": len(month_events),
    }


def _display_log_value(value: Any) -> str:
    if value in (None, ""):
        return "leer"
    if isinstance(value, bool):
        return "Ja" if value else "Nein"
    if isinstance(value, list):
        joined = "\n".join(str(item) for item in value if str(item).strip())
        return joined or "leer"
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value)


def _log_entry_for_template(entry: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(entry)
    payload = dict(entry.get("payload") or {})
    changes = []
    for change in payload.get("changes") or []:
        changes.append(
            {
                "label": str(change.get("label") or change.get("field") or ""),
                "before": _display_log_value(change.get("before")),
                "after": _display_log_value(change.get("after")),
            }
        )
    enriched["detail_line"] = str(payload.get("detail") or "")
    enriched["changes"] = changes
    enriched["change_summary"] = ", ".join(change["label"] for change in changes)
    enriched["error_text"] = str(payload.get("error") or "")
    preview_payload = {
        key: value
        for key, value in payload.items()
        if key not in {"before", "after", "changes", "detail", "error"}
    }
    enriched["payload_preview"] = (
        json.dumps(preview_payload, ensure_ascii=False, indent=2) if preview_payload else ""
    )
    return enriched


def _connection_for_template(connection: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(connection)
    enriched["masked_settings"] = {
        key: (mask_secret(str(value)) if "secret" in key or "token" in key or key.endswith("_pw") else value)
        for key, value in connection["settings"].items()
    }
    enriched["settings_pretty"] = json.dumps(enriched["masked_settings"], indent=2, ensure_ascii=False)
    enriched["policy_label"] = _provider_policy_label(str(connection["provider"]))
    return enriched


def _extract_connection_settings(form: Any) -> Dict[str, Any]:
    known_fields = KNOWN_CONNECTION_SETTING_FIELDS
    settings: Dict[str, Any] = {}
    for field in known_fields:
        value = str(form.get(field) or "").strip()
        if value:
            settings[field] = value
    return settings


def _filter_connection_settings(raw_settings: Dict[str, Any]) -> Dict[str, Any]:
    settings: Dict[str, Any] = {}
    for field in KNOWN_CONNECTION_SETTING_FIELDS:
        value = raw_settings.get(field)
        if value is None:
            continue
        rendered = str(value).strip()
        if rendered:
            settings[field] = rendered
    return settings


def _build_connection_profile_payload(connections: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "kind": CONNECTION_PROFILE_KIND,
        "version": CONNECTION_PROFILE_VERSION,
        "exported_at": iso_z(now_utc()),
        "connections": [
            {
                "provider": str(connection["provider"]),
                "display_name": str(connection["display_name"]),
                "sync_mode": str(connection.get("sync_mode") or _default_sync_mode_for_provider(str(connection["provider"]))),
                "blocked_title": str(connection.get("blocked_title") or "Blocked"),
                "is_active": bool(connection.get("is_active")),
                "settings": dict(connection.get("settings") or {}),
            }
            for connection in connections
        ],
    }


def _parse_connection_profile(raw_text: str) -> Dict[str, Any]:
    payload = json.loads(raw_text)
    if not isinstance(payload, dict):
        raise ValueError("profile payload must be an object")
    if str(payload.get("kind") or "").strip() != CONNECTION_PROFILE_KIND:
        raise ValueError("profile kind is invalid")
    if int(payload.get("version") or 0) != CONNECTION_PROFILE_VERSION:
        raise ValueError("profile version is invalid")
    connections = payload.get("connections")
    if not isinstance(connections, list) or not connections:
        raise ValueError("connections must be a non-empty list")

    normalized_connections: List[Dict[str, Any]] = []
    for item in connections:
        if not isinstance(item, dict):
            raise ValueError("connection entry must be an object")
        provider = str(item.get("provider") or "").strip().lower()
        display_name = str(item.get("display_name") or "").strip()
        blocked_title = str(item.get("blocked_title") or "Blocked").strip() or "Blocked"
        sync_mode = str(item.get("sync_mode") or _default_sync_mode_for_provider(provider)).strip().lower()
        raw_settings = item.get("settings") if isinstance(item.get("settings"), dict) else {}
        settings = _filter_connection_settings(dict(raw_settings))
        if provider not in VALID_PROVIDERS or not display_name:
            raise ValueError("connection entry is invalid")
        if sync_mode not in {"full", "blocked"}:
            sync_mode = _default_sync_mode_for_provider(provider)
        normalized_connections.append(
            {
                "provider": provider,
                "display_name": display_name,
                "sync_mode": sync_mode,
                "blocked_title": blocked_title,
                "is_active": bool(item.get("is_active", True)),
                "settings": settings,
            }
        )
    return {"connections": normalized_connections}


def _json_download(filename: str, payload: Dict[str, Any]) -> Response:
    response = Response(json.dumps(payload, ensure_ascii=False, indent=2), media_type="application/json")
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def _default_sync_mode_for_provider(provider: str) -> str:
    return "blocked" if provider == "google" else "full"


def _provider_policy_label(provider: str) -> str:
    if provider == "google":
        return "Native Google-Termine bleiben voll, Spiegel aus Exchange/iCloud werden als Blocked geschrieben."
    if provider == "exchange":
        return "Alle Termine werden mit vollen Details nach Exchange synchronisiert."
    if provider == "icloud":
        return "Alle Termine werden mit vollen Details nach iCloud synchronisiert."
    return "Standard-Synchronisation"


def _auto_sync_status(user: Dict[str, Any]) -> str:
    interval = int(user.get("auto_sync_interval_minutes") or 0)
    if interval <= 0:
        return "Auto-Sync ist deaktiviert."
    return f"Auto-Sync startet alle {interval} Minuten."


def _start_sync_thread(
    sync_service: SyncService,
    user_id: int,
    job_id: int,
) -> threading.Thread:
    thread = threading.Thread(
        target=sync_service.run_sync_job,
        args=(user_id, job_id),
        name=f"sync-job-{job_id}",
        daemon=True,
    )
    thread.start()
    return thread


def _sync_notice(request: Request) -> Optional[str]:
    sync_state = str(request.query_params.get("sync") or "").strip().lower()
    job_id = str(request.query_params.get("job_id") or "").strip()
    suffix = f" (Job {job_id})" if job_id.isdigit() else ""
    if sync_state == "started":
        return "Synchronisierung im Hintergrund gestartet" + suffix
    if sync_state == "already-running":
        return "Es laeuft bereits eine Synchronisierung" + suffix
    if sync_state == "failed":
        return "Synchronisierung konnte nicht gestartet werden" + suffix
    return None
