#!/usr/bin/env python3
"""
3-Wege-Kalender-Sync: Exchange <-> iCloud + Google (optional).

Verhalten:
- Exchange <-> iCloud: bidirektional mit Detaildaten.
- Exchange/iCloud -> Google: als "Blocked" (busy) ohne private Details.
- Google -> Exchange/iCloud: mit Detaildaten.

Schutz gegen Loops/Duplikate:
- Stabile Sync-ID pro Event.
- Metadaten je Provider:
  - Exchange: singleValueExtendedProperties
  - iCloud: X-AETHER-SYNC-* in ICS
  - Google: extendedProperties.private
- Zusätzlich lokaler State als Fallback/Resync-Hilfe.

Dry-Run:
- --dry-run oder SYNC_DRY_RUN=true: keine Writes, nur Logs.
"""

from __future__ import annotations

import argparse
import html
import hashlib
import json
import os
import re
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, urljoin
from zoneinfo import ZoneInfo

import requests
from requests.auth import HTTPBasicAuth


# ===== Constants =====
MARKER_PREFIX = "AETHER_SYNC"
SYNC_VERSION = 4

GRAPH_PROP_SYNC_ID = "String {66f5a359-4659-4830-9070-000000000001} Name AetherSyncId"
GRAPH_PROP_SOURCE = "String {66f5a359-4659-4830-9070-000000000001} Name AetherSyncSource"
GRAPH_PROP_MODE = "String {66f5a359-4659-4830-9070-000000000001} Name AetherSyncMode"

GOOGLE_META_SYNC_ID = "aetherSyncId"
GOOGLE_META_SOURCE = "aetherSyncSource"
GOOGLE_META_MODE = "aetherSyncMode"

ICLOUD_META_SYNC_ID = "X-AETHER-SYNC-ID"
ICLOUD_META_SOURCE = "X-AETHER-SYNC-SOURCE"
ICLOUD_META_MODE = "X-AETHER-SYNC-MODE"

SOURCE_EXCHANGE = "exchange"
SOURCE_ICLOUD = "icloud"
SOURCE_GOOGLE = "google"
MODE_FULL = "full"
MODE_BLOCKED = "blocked"

SYNC_ORIGIN_METADATA = "metadata"
SYNC_ORIGIN_STATE = "state"
SYNC_ORIGIN_STABLE = "stable"
SYNC_ORIGIN_MATCHED = "matched"
TRANSIENT_HTTP_STATUS_CODES = {408, 423, 429, 500, 502, 503, 504}
ICLOUD_RETRY_ATTEMPTS = 4
ICLOUD_RETRY_BASE_SECONDS = 1.0
ICLOUD_RETRY_MAX_SECONDS = 8.0


# ===== Utility =====
def now_utc() -> datetime:
    return datetime.now(UTC)


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def mask_for_log(value: Optional[str]) -> str:
    if not value:
        return ""
    if len(value) <= 6:
        return "***"
    return value[:3] + "***" + value[-2:]


def iso_z(dt: datetime) -> str:
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def clean_tz_name(name: Optional[str]) -> str:
    if not name:
        return ""
    value = str(name).strip().strip('"')
    if "/" in value and value.startswith("/"):
        return value.split("/", 1)[1]
    return value


def tzinfo_from_name(name: Optional[str]) -> Optional[ZoneInfo]:
    cleaned = clean_tz_name(name)
    if not cleaned:
        return None
    candidates = [cleaned]
    if " " in cleaned:
        candidates.append(cleaned.replace(" ", "_"))
    for candidate in candidates:
        try:
            return ZoneInfo(candidate)
        except Exception:
            continue
    return None


def parse_any_datetime(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    value = str(raw).strip()
    if not value:
        return None

    if re.fullmatch(r"\d{8}T\d{6}Z", value):
        return datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except Exception:
        return None


def parse_datetime_with_tz(raw: Optional[str], tz_name: Optional[str] = None) -> Optional[datetime]:
    if not raw:
        return None

    value = str(raw).strip()
    tzinfo = tzinfo_from_name(tz_name) or UTC

    has_explicit_timezone = bool(re.search(r"(Z|[+-]\d{2}:\d{2})$", value))
    if tz_name and not has_explicit_timezone:
        compact_match = re.fullmatch(r"(\d{8})T(\d{6})", value)
        if compact_match:
            local = datetime.strptime(value, "%Y%m%dT%H%M%S")
            return local.replace(tzinfo=tzinfo).astimezone(UTC)

        try:
            parsed_local = datetime.fromisoformat(value)
        except Exception:
            parsed_local = None
        if parsed_local is not None and parsed_local.tzinfo is None:
            return parsed_local.replace(tzinfo=tzinfo).astimezone(UTC)

    parsed = parse_any_datetime(raw)
    if parsed:
        return parsed

    compact_match = re.fullmatch(r"(\d{8})T(\d{6})", value)
    if compact_match:
        local = datetime.strptime(value, "%Y%m%dT%H%M%S")
        return local.replace(tzinfo=tzinfo).astimezone(UTC)

    try:
        parsed_local = datetime.fromisoformat(value)
    except Exception:
        return None

    if parsed_local.tzinfo is None:
        return parsed_local.replace(tzinfo=tzinfo).astimezone(UTC)
    return parsed_local.astimezone(UTC)


def normalized_start_to_dt(norm: Dict[str, Any]) -> datetime:
    if norm.get("all_day"):
        return datetime.fromisoformat(norm["date"] + "T00:00:00+00:00").astimezone(UTC)
    parsed = parse_any_datetime(norm.get("dateTime"))
    if parsed:
        return parsed
    return datetime(1970, 1, 1, tzinfo=UTC)


def stable_sync_id(provider: str, provider_id: str) -> str:
    digest = hashlib.sha1(f"{provider}:{provider_id}".encode("utf-8")).hexdigest()
    return f"aether-{digest}"


def lines_unfold_ics(text: str) -> List[str]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    out: List[str] = []
    for line in normalized.split("\n"):
        if not line:
            continue
        if line.startswith(" ") and out:
            out[-1] += line[1:]
        else:
            out.append(line)
    return out


def parse_ics_value(lines: Iterable[str], key: str) -> Optional[str]:
    prefix = key.upper() + ":"
    for ln in lines:
        if ln.upper().startswith(prefix):
            return ln.split(":", 1)[1]
    return None


def parse_ics_prop(lines: Iterable[str], prop_name: str) -> Optional[Tuple[str, str]]:
    pat = prop_name.upper() + ";"
    pref = prop_name.upper() + ":"
    for ln in lines:
        up = ln.upper()
        if up.startswith(pref):
            return "", ln.split(":", 1)[1]
        if up.startswith(pat):
            head, value = ln.split(":", 1)
            return head[len(prop_name) + 1 :], value
    return None


def parse_prop_params(params: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not params:
        return values

    for chunk in params.split(";"):
        if not chunk:
            continue
        if "=" not in chunk:
            values[chunk.strip().upper()] = ""
            continue
        key, value = chunk.split("=", 1)
        values[key.strip().upper()] = value.strip().strip('"')
    return values


def ics_escape(text: str) -> str:
    return (
        (text or "")
        .replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "")
        .replace(";", "\\;")
        .replace(",", "\\,")
    )


def ics_unescape(text: str) -> str:
    return (text or "").replace("\\n", "\n").replace("\\,", ",").replace("\\;", ";").replace("\\\\", "\\")


def dt_ics_to_normalized(raw: str, params: str = "") -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    value = raw.strip()
    params_map = parse_prop_params(params)
    params_u = params.upper()

    # all-day (VALUE=DATE or 8 chars)
    if "VALUE=DATE" in params_u or re.fullmatch(r"\d{8}", value):
        if not re.fullmatch(r"\d{8}", value):
            return None
        date = f"{value[0:4]}-{value[4:6]}-{value[6:8]}"
        return {"all_day": True, "date": date}

    # timed
    m = re.fullmatch(r"(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(Z)?", value)
    if not m:
        parsed = parse_datetime_with_tz(value, params_map.get("TZID"))
        if not parsed:
            return None
        return {"all_day": False, "dateTime": iso_z(parsed)}

    y, mo, d, h, mi, s, z_suffix = m.groups()
    if z_suffix:
        return {"all_day": False, "dateTime": f"{y}-{mo}-{d}T{h}:{mi}:{s}Z"}

    parsed = parse_datetime_with_tz(value, params_map.get("TZID"))
    if not parsed:
        return None
    return {"all_day": False, "dateTime": iso_z(parsed)}


def ics_prop_to_dt(params: str, value: str) -> Optional[datetime]:
    n = dt_ics_to_normalized(value, params)
    if n:
        return normalized_start_to_dt(n)
    return parse_any_datetime(value)


def normalized_to_ics(dt: Dict[str, Any], end: bool = False) -> Tuple[str, str]:
    if dt.get("all_day"):
        date = dt.get("date", "")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
            raise ValueError("invalid all-day date")
        value = date.replace("-", "")
        return (";VALUE=DATE", value)

    raw = dt.get("dateTime", "")
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z", raw)
    if not m:
        raise ValueError(f"invalid datetime format: {raw}")
    y, mo, d, h, mi, s = m.groups()
    return ("", f"{y}{mo}{d}T{h}{mi}{s}Z")


def normalize_graph_dt(start: Dict[str, Any], is_all_day: bool) -> Optional[Dict[str, Any]]:
    dt = (start or {}).get("dateTime", "")
    if not dt:
        return None
    if is_all_day:
        return {"all_day": True, "date": dt[:10]}
    parsed = parse_datetime_with_tz(dt, (start or {}).get("timeZone"))
    if parsed:
        return {"all_day": False, "dateTime": iso_z(parsed)}
    if dt.endswith("Z"):
        return {"all_day": False, "dateTime": dt}
    return {"all_day": False, "dateTime": dt[:19] + "Z"}


def normalize_google_dt(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not obj:
        return None
    if obj.get("date"):
        return {"all_day": True, "date": obj["date"]}
    raw = obj.get("dateTime", "")
    if not raw:
        return None
    parsed = parse_any_datetime(raw)
    if parsed:
        return {"all_day": False, "dateTime": iso_z(parsed)}
    if raw.endswith("Z"):
        return {"all_day": False, "dateTime": raw}
    return {"all_day": False, "dateTime": raw[:19] + "Z"}


def join_absolute_url(base: str, href: str) -> str:
    return href if href.startswith("http://") or href.startswith("https://") else urljoin(base, href)


def json_fp(data: Dict[str, Any]) -> str:
    return hashlib.sha1(json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


HTML_MARKUP_RE = re.compile(
    r"<\s*(?:!doctype|html|head|body|meta|div|p|br|span|table|tr|td|th|ul|ol|li|blockquote|style|script|font)\b",
    re.IGNORECASE,
)
SYNC_METADATA_LINE_RE = re.compile(r"^(?:AETHER_SYNC[A-Z_]*:|SOURCE_ID:)", re.IGNORECASE)


class HTMLTextExtractor(HTMLParser):
    _block_tags = {
        "address",
        "article",
        "aside",
        "blockquote",
        "body",
        "div",
        "dl",
        "dt",
        "dd",
        "fieldset",
        "figcaption",
        "figure",
        "footer",
        "form",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "hr",
        "li",
        "main",
        "nav",
        "ol",
        "p",
        "pre",
        "section",
        "table",
        "tbody",
        "tfoot",
        "thead",
        "tr",
        "ul",
    }
    _line_break_tags = {"br"}
    _skip_tags = {"head", "script", "style", "title"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag_name = tag.lower()
        if tag_name in self._skip_tags:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag_name == "li":
            self._ensure_line_break()
            self.parts.append("- ")
            return
        if tag_name in self._line_break_tags:
            self._ensure_line_break()
            return
        if tag_name in self._block_tags:
            self._ensure_line_break()

    def handle_endtag(self, tag: str) -> None:
        tag_name = tag.lower()
        if tag_name in self._skip_tags:
            if self._skip_depth:
                self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if tag_name in self._block_tags:
            self._ensure_line_break()

    def handle_data(self, data: str) -> None:
        if self._skip_depth or not data:
            return
        self.parts.append(data)

    def get_text(self) -> str:
        return "".join(self.parts)

    def _ensure_line_break(self) -> None:
        if not self.parts:
            return
        if self.parts[-1].endswith("\n"):
            return
        self.parts.append("\n")


def decode_html_entities_deep(text: str, max_rounds: int = 6) -> str:
    current = str(text or "")
    for _ in range(max_rounds):
        decoded = html.unescape(current)
        decoded = decoded.replace("\xa0", " ")
        if decoded == current:
            break
        current = decoded
    return current


def looks_like_html_markup(text: str) -> bool:
    return bool(HTML_MARKUP_RE.search(str(text or "")))


def normalize_multiline_text(text: str) -> str:
    value = str(text or "").replace("\r\n", "\n").replace("\r", "\n").replace("\u200b", "")
    value = re.sub(r"[ \t\f\v]+\n", "\n", value)
    value = re.sub(r"\n[ \t\f\v]+", "\n", value)
    value = re.sub(r"[ \t\f\v]{2,}", " ", value)
    value = "\n".join(line.rstrip() for line in value.split("\n"))
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


def normalize_singleline_text(text: str) -> str:
    value = decode_html_entities_deep(str(text or ""))
    if looks_like_html_markup(value):
        value = html_to_plain_text(value)
    value = re.sub(r"\s+", " ", value.replace("\u200b", " "))
    return value.strip()


def html_to_plain_text(text: str) -> str:
    parser = HTMLTextExtractor()
    parser.feed(str(text or ""))
    parser.close()
    return normalize_multiline_text(parser.get_text())


def strip_sync_metadata_lines(text: str) -> str:
    lines = []
    for line in normalize_multiline_text(text).split("\n"):
        if SYNC_METADATA_LINE_RE.match(line.strip()):
            continue
        lines.append(line)
    return normalize_multiline_text("\n".join(lines))


def normalize_calendar_description(text: str, source_format: str = "auto") -> str:
    raw = str(text or "")
    if not raw:
        return ""

    current = raw
    for _ in range(10):
        changed = False
        if looks_like_html_markup(current):
            stripped = html_to_plain_text(current)
            if stripped != current:
                current = stripped
                changed = True

        decoded = decode_html_entities_deep(current)
        if decoded != current:
            current = decoded
            changed = True

        stripped_metadata = strip_sync_metadata_lines(current)
        if stripped_metadata != current:
            current = stripped_metadata
            changed = True

        normalized = normalize_multiline_text(current)
        if normalized != current:
            current = normalized
            changed = True

        if not changed:
            break
    return current


def request_exception_status(exc: requests.RequestException) -> Optional[int]:
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    return int(status) if isinstance(status, int) else None


def is_transient_http_status(status: Optional[int]) -> bool:
    return status in TRANSIENT_HTTP_STATUS_CODES


def retry_backoff_seconds(attempt_index: int) -> float:
    return min(ICLOUD_RETRY_MAX_SECONDS, ICLOUD_RETRY_BASE_SECONDS * (2 ** attempt_index))


@dataclass
class SyncEvent:
    provider: str
    provider_id: str
    title: str
    start: Dict[str, Any]
    end: Dict[str, Any]
    description: str = ""
    location: str = ""
    recurrence: List[str] = field(default_factory=list)
    sync_id: Optional[str] = None
    sync_origin: str = ""
    source: Optional[str] = None
    mode: Optional[str] = None
    modified_at: Optional[datetime] = None
    uid: Optional[str] = None
    href: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def fingerprint(self, mode: str, blocked_title: str) -> str:
        normalized_title = normalize_singleline_text(self.title)
        normalized_description = normalize_calendar_description(self.description, source_format="auto")
        normalized_location = normalize_singleline_text(self.location)
        if mode == MODE_BLOCKED:
            payload = {
                "title": blocked_title,
                "start": self.start,
                "end": self.end,
                "recurrence": self.recurrence,
                "all_day": self.start.get("all_day", False),
            }
            return json_fp(payload)

        payload = {
            "title": normalized_title,
            "start": self.start,
            "end": self.end,
            "description": normalized_description,
            "location": normalized_location,
            "recurrence": self.recurrence,
            "all_day": self.start.get("all_day", False),
        }
        return json_fp(payload)


@dataclass
class Config:
    # Exchange
    exchange_tenant_id: str
    exchange_client_id: str
    exchange_client_secret: str
    exchange_user: str

    # iCloud
    icloud_user: str
    icloud_app_pw: str
    icloud_principal_path: str
    icloud_target_calendar_display: str

    # Google
    google_enabled: bool
    google_calendar_id: str
    google_blocked_title: str
    google_oauth_client_id: str
    google_oauth_client_secret: str
    google_oauth_refresh_token: str
    google_service_account_json: str
    google_impersonate_user: str

    # Runtime
    state_path: Path
    dry_run: bool
    window_days: int
    timeout_sec: int
    write_delay_ms: int
    max_writes_per_run: int
    write_backoff_enabled: bool
    write_backoff_base_ms: int
    write_backoff_max_ms: int

    @staticmethod
    def from_env(dry_run_override: Optional[bool], window_days_override: Optional[int]) -> "Config":
        dry_run = env_bool("SYNC_DRY_RUN", False)
        if dry_run_override is not None:
            dry_run = dry_run_override

        window_days = int(os.getenv("SYNC_WINDOW_DAYS", "365"))
        if window_days_override is not None:
            window_days = window_days_override

        return Config(
            exchange_tenant_id=os.getenv("EXCHANGE_TENANT_ID", ""),
            exchange_client_id=os.getenv("EXCHANGE_CLIENT_ID", ""),
            exchange_client_secret=os.getenv("EXCHANGE_CLIENT_SECRET", ""),
            exchange_user=os.getenv("EXCHANGE_USER", ""),
            icloud_user=os.getenv("ICLOUD_USER", ""),
            icloud_app_pw=os.getenv("ICLOUD_APP_PW", ""),
            icloud_principal_path=os.getenv("ICLOUD_PRINCIPAL_PATH", ""),
            icloud_target_calendar_display=os.getenv("ICLOUD_TARGET_CAL_DISPLAY", "Kalender"),
            google_enabled=env_bool("GOOGLE_SYNC_ENABLED", False),
            google_calendar_id=os.getenv("GOOGLE_CALENDAR_ID", "primary"),
            google_blocked_title=os.getenv("GOOGLE_BLOCKED_TITLE", "Blocked"),
            google_oauth_client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID", ""),
            google_oauth_client_secret=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", ""),
            google_oauth_refresh_token=os.getenv("GOOGLE_OAUTH_REFRESH_TOKEN", ""),
            google_service_account_json=os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", ""),
            google_impersonate_user=os.getenv("GOOGLE_IMPERSONATE_USER", ""),
            state_path=Path(os.getenv("CAL_SYNC_STATE_PATH", "/root/.openclaw/workspace/memory/calendar-sync-state.json")),
            dry_run=dry_run,
            window_days=max(1, window_days),
            timeout_sec=max(5, int(os.getenv("CAL_SYNC_TIMEOUT_SEC", "30"))),
            write_delay_ms=max(0, int(os.getenv("SYNC_WRITE_DELAY_MS", "500"))),
            max_writes_per_run=max(1, int(os.getenv("MAX_WRITES_PER_RUN", "500"))),
            write_backoff_enabled=env_bool("SYNC_ENABLE_BACKOFF", True),
            write_backoff_base_ms=max(100, int(os.getenv("SYNC_BACKOFF_BASE_MS", "1000"))),
            write_backoff_max_ms=max(500, int(os.getenv("SYNC_BACKOFF_MAX_MS", "15000"))),
        )

    def validate(self) -> None:
        missing = []
        for key, val in [
            ("EXCHANGE_TENANT_ID", self.exchange_tenant_id),
            ("EXCHANGE_CLIENT_ID", self.exchange_client_id),
            ("EXCHANGE_CLIENT_SECRET", self.exchange_client_secret),
            ("EXCHANGE_USER", self.exchange_user),
            ("ICLOUD_USER", self.icloud_user),
            ("ICLOUD_APP_PW", self.icloud_app_pw),
            ("ICLOUD_PRINCIPAL_PATH", self.icloud_principal_path),
        ]:
            if not val:
                missing.append(key)

        if self.google_enabled:
            oauth_ready = all(
                [
                    self.google_oauth_client_id,
                    self.google_oauth_client_secret,
                    self.google_oauth_refresh_token,
                ]
            )
            sa_ready = bool(self.google_service_account_json)
            if not (oauth_ready or sa_ready):
                missing.append(
                    "GOOGLE auth (set OAUTH vars or GOOGLE_SERVICE_ACCOUNT_JSON)"
                )

        if missing:
            raise RuntimeError("missing required config: " + ", ".join(missing))


class Logger:
    def __init__(self) -> None:
        self.stats: Dict[str, int] = {}

    def _inc(self, key: str) -> None:
        self.stats[key] = self.stats.get(key, 0) + 1

    def info(self, message: str, **data: Any) -> None:
        compact = " ".join([f"{k}={v}" for k, v in data.items() if v not in (None, "")])
        print(f"[sync] {message}" + (f" {compact}" if compact else ""))

    def action(self, provider: str, action: str, sync_id: str, detail: str = "", **_extra: Any) -> None:
        self._inc(f"{provider}_{action}")
        suffix = f" ({detail})" if detail else ""
        print(f"[sync] {provider}:{action} sync_id={sync_id}{suffix}")

    def warn(self, message: str, **data: Any) -> None:
        compact = " ".join([f"{k}={v}" for k, v in data.items() if v not in (None, "")])
        print(f"[sync][warn] {message}" + (f" {compact}" if compact else ""))

    def error(self, message: str, **data: Any) -> None:
        compact = " ".join([f"{k}={v}" for k, v in data.items() if v not in (None, "")])
        print(f"[sync][error] {message}" + (f" {compact}" if compact else ""))

    def provider_error(self, provider: str, sync_id: str, status: Any, code: str, detail: str = "") -> None:
        self._inc(f"{provider}_errors")
        self.error(
            "provider_error",
            provider=provider,
            sync_id=sync_id,
            status=status,
            code=code,
            detail=detail,
        )

    def summary(self) -> None:
        created = sum(v for k, v in self.stats.items() if k.endswith("_created"))
        updated = sum(v for k, v in self.stats.items() if k.endswith("_updated"))
        deleted = sum(v for k, v in self.stats.items() if k.endswith("_deleted"))
        skipped = sum(v for k, v in self.stats.items() if k.endswith("_skipped"))
        self.info(
            "SUMMARY",
            created=created,
            updated=updated,
            deleted=deleted,
            skipped=skipped,
            exchange_errors=self.stats.get("exchange_errors", 0),
            icloud_errors=self.stats.get("icloud_errors", 0),
            google_errors=self.stats.get("google_errors", 0),
            writes_attempted=self.stats.get("writes_attempted", 0),
            write_cap_skipped=self.stats.get("write_cap_skipped", 0),
            retry_queue_size=self.stats.get("retry_queue_size", 0),
        )


class SyncState:
    def __init__(self, path: Path):
        self.path = path
        self.data = self._load()

    def _default(self) -> Dict[str, Any]:
        return {
            "version": SYNC_VERSION,
            "provider_to_sync": {
                SOURCE_EXCHANGE: {},
                SOURCE_ICLOUD: {},
                SOURCE_GOOGLE: {},
            },
            "sync_to_provider": {},
            "records": {},
            "retry_queue": {},
            "updatedAt": None,
        }

    def _load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return self._default()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return self._default()

        # migrate old shape ex_to_ic/ic_to_ex -> new map
        if "provider_to_sync" in raw and "sync_to_provider" in raw:
            raw.setdefault("version", SYNC_VERSION)
            raw.setdefault("records", {})
            raw.setdefault("retry_queue", {})
            raw.setdefault("provider_to_sync", {})
            for provider in [SOURCE_EXCHANGE, SOURCE_ICLOUD, SOURCE_GOOGLE]:
                raw["provider_to_sync"].setdefault(provider, {})
            return raw

        migrated = self._default()
        ex_to_ic = raw.get("ex_to_ic", {}) if isinstance(raw, dict) else {}
        for ex_id, val in ex_to_ic.items():
            if not isinstance(val, dict):
                continue
            sync_id = stable_sync_id(SOURCE_EXCHANGE, str(ex_id))
            href = val.get("href")
            migrated["provider_to_sync"][SOURCE_EXCHANGE][str(ex_id)] = sync_id
            migrated["sync_to_provider"].setdefault(sync_id, {})[SOURCE_EXCHANGE] = str(ex_id)
            if href:
                migrated["provider_to_sync"][SOURCE_ICLOUD][str(href)] = sync_id
                migrated["sync_to_provider"][sync_id][SOURCE_ICLOUD] = str(href)

        migrated["updatedAt"] = raw.get("updatedAt") if isinstance(raw, dict) else None
        return migrated

    def save(self) -> None:
        self.data["version"] = SYNC_VERSION
        self.data["updatedAt"] = iso_z(now_utc())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")

    def get_sync_id(self, provider: str, provider_id: str) -> Optional[str]:
        return self.data["provider_to_sync"].get(provider, {}).get(provider_id)

    def set_mapping(self, provider: str, provider_id: str, sync_id: str) -> None:
        provider_map = self.data["provider_to_sync"].setdefault(provider, {})
        sync_map = self.data["sync_to_provider"].setdefault(sync_id, {})

        previous_sync_id = provider_map.get(provider_id)
        if previous_sync_id and previous_sync_id != sync_id:
            previous_sync_map = self.data["sync_to_provider"].get(previous_sync_id, {})
            if previous_sync_map.get(provider) == provider_id:
                del previous_sync_map[provider]
            if not previous_sync_map:
                self.data["sync_to_provider"].pop(previous_sync_id, None)

        previous_provider_id = sync_map.get(provider)
        if previous_provider_id and previous_provider_id != provider_id:
            existing_sync = provider_map.get(previous_provider_id)
            if existing_sync == sync_id:
                del provider_map[previous_provider_id]

        provider_map[provider_id] = sync_id
        sync_map[provider] = provider_id

    def get_provider_id(self, provider: str, sync_id: str) -> Optional[str]:
        return self.data["sync_to_provider"].get(sync_id, {}).get(provider)

    def get_provider_record(self, sync_id: str, provider: str) -> Dict[str, Any]:
        return (
            self.data.get("records", {})
            .get(sync_id, {})
            .get("providers", {})
            .get(provider, {})
        )

    def set_provider_record(
        self,
        sync_id: str,
        provider: str,
        provider_id: str,
        fingerprint: str,
        source: str,
        mode: str,
        modified_at: datetime,
    ) -> None:
        self.set_mapping(provider, provider_id, sync_id)
        records = self.data.setdefault("records", {})
        sync_record = records.setdefault(sync_id, {"providers": {}})
        sync_record.setdefault("providers", {})[provider] = {
            "provider_id": provider_id,
            "fingerprint": fingerprint,
            "source": source,
            "mode": mode,
            "modified_at": iso_z(modified_at),
        }

    def set_retry_entry(
        self,
        sync_id: str,
        provider: str,
        payload: Dict[str, Any],
    ) -> None:
        key = f"{sync_id}|{provider}"
        queue = self.data.setdefault("retry_queue", {})
        queue[key] = payload

    def get_retry_entry(self, sync_id: str, provider: str) -> Optional[Dict[str, Any]]:
        key = f"{sync_id}|{provider}"
        return self.data.get("retry_queue", {}).get(key)

    def remove_retry_entry(self, sync_id: str, provider: str) -> None:
        key = f"{sync_id}|{provider}"
        self.data.setdefault("retry_queue", {}).pop(key, None)

    def list_retry_entries(self) -> List[Dict[str, Any]]:
        return list(self.data.get("retry_queue", {}).values())

    def due_retry_entries(self, now_dt: datetime) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for item in self.list_retry_entries():
            due_raw = item.get("next_retry_at")
            due_dt = parse_any_datetime(due_raw) if due_raw else None
            if due_dt is None or due_dt <= now_dt:
                out.append(item)
        return out

    def forget_provider(
        self,
        provider: str,
        provider_id: Optional[str] = None,
        sync_id: Optional[str] = None,
    ) -> None:
        provider_map = self.data["provider_to_sync"].setdefault(provider, {})
        if sync_id is None and provider_id is not None:
            sync_id = provider_map.get(provider_id)
        if provider_id is None and sync_id is not None:
            provider_id = self.data["sync_to_provider"].get(sync_id, {}).get(provider)

        if provider_id:
            provider_map.pop(provider_id, None)

        if sync_id:
            sync_map = self.data["sync_to_provider"].get(sync_id, {})
            if provider_id is None or sync_map.get(provider) == provider_id:
                sync_map.pop(provider, None)
            if not sync_map:
                self.data["sync_to_provider"].pop(sync_id, None)

            record = self.data.setdefault("records", {}).get(sync_id, {})
            providers = record.get("providers", {})
            record_provider_id = providers.get(provider, {}).get("provider_id")
            if provider_id is None or record_provider_id == provider_id:
                providers.pop(provider, None)
            if record and not providers:
                self.data["records"].pop(sync_id, None)

    def forget_sync(self, sync_id: str) -> None:
        providers = dict(self.data["sync_to_provider"].get(sync_id, {}))
        for provider, provider_id in providers.items():
            self.data["provider_to_sync"].setdefault(provider, {}).pop(provider_id, None)
        self.data["sync_to_provider"].pop(sync_id, None)
        self.data.setdefault("records", {}).pop(sync_id, None)


class ExchangeClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._token: Optional[str] = None

    def _token_value(self) -> str:
        if self._token:
            return self._token
        r = requests.post(
            f"https://login.microsoftonline.com/{self.cfg.exchange_tenant_id}/oauth2/v2.0/token",
            data={
                "client_id": self.cfg.exchange_client_id,
                "client_secret": self.cfg.exchange_client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            timeout=self.cfg.timeout_sec,
        )
        r.raise_for_status()
        self._token = r.json()["access_token"]
        return self._token

    def _headers(self, prefer_utc: bool = False) -> Dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._token_value()}",
            "Content-Type": "application/json",
        }
        if prefer_utc:
            headers["Prefer"] = 'outlook.timezone="UTC"'
        return headers

    @staticmethod
    def _extract_meta(item: Dict[str, Any]) -> Dict[str, str]:
        values = {}
        for prop in item.get("singleValueExtendedProperties", []) or []:
            pid = prop.get("id")
            if pid in (GRAPH_PROP_SYNC_ID, GRAPH_PROP_SOURCE, GRAPH_PROP_MODE):
                values[pid] = prop.get("value", "")
        return {
            "sync_id": values.get(GRAPH_PROP_SYNC_ID, ""),
            "source": values.get(GRAPH_PROP_SOURCE, ""),
            "mode": values.get(GRAPH_PROP_MODE, ""),
        }

    def _list_syncable_calendars(self, log: Logger) -> List[Dict[str, str]]:
        url = f"https://graph.microsoft.com/v1.0/users/{self.cfg.exchange_user}/calendars"
        params = {"$top": 200, "$select": "id,name,canEdit,isDefaultCalendar"}
        calendars: List[Dict[str, str]] = []
        next_url: Optional[str] = url
        next_params: Optional[Dict[str, Any]] = params

        while next_url:
            response = requests.get(
                next_url,
                headers=self._headers(prefer_utc=True),
                params=next_params,
                timeout=self.cfg.timeout_sec,
            )
            response.raise_for_status()
            payload = response.json()
            for item in payload.get("value", []) or []:
                calendar_id = str(item.get("id", "") or "")
                if not calendar_id:
                    continue
                can_edit = bool(item.get("canEdit"))
                is_default = bool(item.get("isDefaultCalendar"))
                if not (can_edit or is_default):
                    continue
                calendars.append(
                    {
                        "id": calendar_id,
                        "name": str(item.get("name", "") or "Kalender"),
                    }
                )
            next_url = payload.get("@odata.nextLink")
            next_params = None

        if calendars:
            log.info(
                "exchange_calendars_loaded",
                count=len(calendars),
                calendars=" | ".join(calendar["name"] for calendar in calendars),
            )
        else:
            log.warn("exchange_calendar_list_empty")
        return calendars

    def _calendar_view_events(
        self,
        calendar_id: str,
        calendar_name: str,
        start: datetime,
        end: datetime,
        log: Logger,
    ) -> List[SyncEvent]:
        url = f"https://graph.microsoft.com/v1.0/users/{self.cfg.exchange_user}/calendars/{quote(calendar_id, safe='')}/calendarView"
        params = {
            "startDateTime": iso_z(start),
            "endDateTime": iso_z(end),
            "$top": 500,
            "$select": "id,subject,start,end,isAllDay,lastModifiedDateTime,body,bodyPreview,location,recurrence,type,seriesMasterId",
            "$expand": (
                "singleValueExtendedProperties($filter="
                f"id eq '{GRAPH_PROP_SYNC_ID}' or "
                f"id eq '{GRAPH_PROP_SOURCE}' or "
                f"id eq '{GRAPH_PROP_MODE}')"
            ),
        }
        out: List[SyncEvent] = []
        next_url: Optional[str] = url
        next_params: Optional[Dict[str, Any]] = params
        while next_url:
            response = requests.get(
                next_url,
                headers=self._headers(prefer_utc=True),
                params=next_params,
                timeout=self.cfg.timeout_sec,
            )
            response.raise_for_status()
            payload = response.json()
            items = payload.get("value", [])

            for it in items:
                start_n = normalize_graph_dt(it.get("start", {}), bool(it.get("isAllDay")))
                end_n = normalize_graph_dt(it.get("end", {}), bool(it.get("isAllDay")))
                if not start_n or not end_n:
                    continue

                meta = self._extract_meta(it)
                rec = []
                if it.get("recurrence"):
                    # Graph recurrence object cannot be converted 1:1 into RRULE without complex mapping.
                    # Existing sync behavior: no recurrence serialization.
                    log.warn("exchange_recurrence_not_serialized", id=it.get("id", ""))

                raw = dict(it)
                raw["calendarId"] = calendar_id
                raw["calendarName"] = calendar_name
                out.append(
                    SyncEvent(
                        provider=SOURCE_EXCHANGE,
                        provider_id=str(it.get("id", "")),
                        title=normalize_singleline_text(str(it.get("subject", "") or "(ohne Betreff)")),
                        start=start_n,
                        end=end_n,
                        description=normalize_calendar_description(
                            ((it.get("body") or {}).get("content") or ""),
                            source_format=str((it.get("body") or {}).get("contentType") or "auto"),
                        ),
                        location=normalize_singleline_text(((it.get("location") or {}).get("displayName") or "")),
                        recurrence=rec,
                        sync_id=meta.get("sync_id") or None,
                        sync_origin=SYNC_ORIGIN_METADATA if meta.get("sync_id") else "",
                        source=meta.get("source") or None,
                        mode=meta.get("mode") or None,
                        modified_at=parse_any_datetime(it.get("lastModifiedDateTime")),
                        raw=raw,
                    )
                )
            next_url = payload.get("@odata.nextLink")
            next_params = None
        return out

    def list_events(self, start: datetime, end: datetime, log: Logger) -> List[SyncEvent]:
        out: List[SyncEvent] = []
        seen_provider_ids = set()
        calendars = self._list_syncable_calendars(log)
        if not calendars:
            return out
        for calendar in calendars:
            for event in self._calendar_view_events(calendar["id"], calendar["name"], start, end, log):
                if event.provider_id in seen_provider_ids:
                    log.warn(
                        "exchange_duplicate_event_id_across_calendars",
                        provider_id=event.provider_id,
                        calendar=calendar["name"],
                    )
                    continue
                seen_provider_ids.add(event.provider_id)
                out.append(event)
        return out

    def _payload_for_event(self, event: SyncEvent, sync_id: str, source: str, mode: str, blocked_title: str) -> Dict[str, Any]:
        title = blocked_title if mode == MODE_BLOCKED else normalize_singleline_text(event.title)
        desc = "" if mode == MODE_BLOCKED else normalize_calendar_description(event.description, source_format="auto")
        location = "" if mode == MODE_BLOCKED else normalize_singleline_text(event.location)

        if event.start.get("all_day"):
            start_date = event.start["date"] + "T00:00:00"
            end_date = event.end["date"] + "T00:00:00"
            start_obj = {"dateTime": start_date, "timeZone": "UTC"}
            end_obj = {"dateTime": end_date, "timeZone": "UTC"}
            is_all_day = True
        else:
            start_obj = {"dateTime": event.start["dateTime"].replace("Z", ""), "timeZone": "UTC"}
            end_obj = {"dateTime": event.end["dateTime"].replace("Z", ""), "timeZone": "UTC"}
            is_all_day = False

        payload: Dict[str, Any] = {
            "subject": title,
            "start": start_obj,
            "end": end_obj,
            "isAllDay": is_all_day,
            "body": {"contentType": "Text", "content": desc},
            "location": {"displayName": location},
            "showAs": "busy",
            "singleValueExtendedProperties": [
                {"id": GRAPH_PROP_SYNC_ID, "value": sync_id},
                {"id": GRAPH_PROP_SOURCE, "value": source},
                {"id": GRAPH_PROP_MODE, "value": mode},
            ],
        }
        return payload

    def upsert_event(
        self,
        existing: Optional[SyncEvent],
        desired: SyncEvent,
        sync_id: str,
        source: str,
        mode: str,
        blocked_title: str,
        dry_run: bool,
        log: Logger,
    ) -> str:
        payload = self._payload_for_event(desired, sync_id, source, mode, blocked_title)

        if existing is None:
            after_snapshot = event_log_snapshot(desired, mode, blocked_title)
            if dry_run:
                log.action("exchange", "created", sync_id, "dry-run", before=None, after=after_snapshot)
                return f"dry-{uuid.uuid4()}"
            r = requests.post(
                f"https://graph.microsoft.com/v1.0/users/{self.cfg.exchange_user}/events",
                headers=self._headers(),
                data=json.dumps(payload),
                timeout=self.cfg.timeout_sec,
            )
            r.raise_for_status()
            out = r.json()
            log.action("exchange", "created", sync_id, before=None, after=after_snapshot)
            return str(out.get("id"))

        desired_fp = desired.fingerprint(mode, blocked_title)
        existing_fp = existing.fingerprint(mode, blocked_title)
        before_snapshot = event_log_snapshot(existing, existing.mode or mode, blocked_title)
        after_snapshot = event_log_snapshot(desired, mode, blocked_title)
        if desired_fp == existing_fp and existing.source == source and existing.mode == mode:
            log.action("exchange", "skipped", sync_id, "no-change", before=before_snapshot, after=after_snapshot)
            return existing.provider_id

        if dry_run:
            log.action("exchange", "updated", sync_id, "dry-run", before=before_snapshot, after=after_snapshot)
            return existing.provider_id

        r = requests.patch(
            f"https://graph.microsoft.com/v1.0/users/{self.cfg.exchange_user}/events/{existing.provider_id}",
            headers=self._headers(),
            data=json.dumps(payload),
            timeout=self.cfg.timeout_sec,
        )
        r.raise_for_status()
        log.action("exchange", "updated", sync_id, before=before_snapshot, after=after_snapshot)
        return existing.provider_id

    def delete_event(self, event: SyncEvent, sync_id: str, dry_run: bool, log: Logger, detail: str = "") -> None:
        before_snapshot = event_log_snapshot(event, event.mode or MODE_FULL)
        if dry_run:
            suffix = "dry-run" if not detail else f"{detail},dry-run"
            log.action("exchange", "deleted", sync_id, suffix, before=before_snapshot, after=None)
            return

        r = requests.delete(
            f"https://graph.microsoft.com/v1.0/users/{self.cfg.exchange_user}/events/{event.provider_id}",
            headers=self._headers(),
            timeout=self.cfg.timeout_sec,
        )
        if r.status_code not in {204, 404}:
            r.raise_for_status()
        log.action(
            "exchange",
            "deleted",
            sync_id,
            detail or ("already-missing" if r.status_code == 404 else ""),
            before=before_snapshot,
            after=None,
        )


class ICloudClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._base: Optional[str] = None
        self._cal_href: Optional[str] = None

    def _auth(self) -> HTTPBasicAuth:
        return HTTPBasicAuth(self.cfg.icloud_user, self.cfg.icloud_app_pw)

    def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        log: Optional[Logger] = None,
        operation: str = "",
        **kwargs: Any,
    ) -> requests.Response:
        last_exc: Optional[Exception] = None
        for attempt in range(ICLOUD_RETRY_ATTEMPTS):
            try:
                response = requests.request(method, url, timeout=self.cfg.timeout_sec, **kwargs)
                if is_transient_http_status(response.status_code) and attempt < ICLOUD_RETRY_ATTEMPTS - 1:
                    if log:
                        log.warn(
                            "icloud_transient_retry",
                            operation=operation or method.lower(),
                            status=response.status_code,
                            attempt=attempt + 1,
                            url=url,
                        )
                    time.sleep(retry_backoff_seconds(attempt))
                    continue
                return response
            except requests.RequestException as exc:
                last_exc = exc
                status = request_exception_status(exc)
                if not is_transient_http_status(status) or attempt >= ICLOUD_RETRY_ATTEMPTS - 1:
                    raise
                if log:
                    log.warn(
                        "icloud_transient_retry",
                        operation=operation or method.lower(),
                        status=status or "request-error",
                        attempt=attempt + 1,
                        url=url,
                    )
                time.sleep(retry_backoff_seconds(attempt))
        if last_exc:
            raise last_exc
        raise RuntimeError(f"iCloud request failed without response: {method} {url}")

    def discover(self, log: Optional[Logger] = None) -> Tuple[str, str]:
        if self._base and self._cal_href:
            return self._base, self._cal_href

        auth = self._auth()
        body = '''<?xml version="1.0" encoding="UTF-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><C:calendar-home-set/></D:prop></D:propfind>'''
        r = self._request_with_retry(
            "PROPFIND",
            "https://caldav.icloud.com" + self.cfg.icloud_principal_path,
            log=log,
            operation="discover-home",
            headers={"Depth": "0", "Content-Type": "application/xml; charset=utf-8"},
            data=body,
            auth=auth,
        )
        r.raise_for_status()
        m = re.search(r"<calendar-home-set[^>]*>\s*<href[^>]*>([^<]+)</href>", r.text)
        if not m:
            raise RuntimeError("iCloud calendar-home-set not found")
        home = m.group(1)
        home_url = join_absolute_url("https://caldav.icloud.com", home)

        body2 = '''<?xml version="1.0" encoding="UTF-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:displayname/></D:prop></D:propfind>'''
        r2 = self._request_with_retry(
            "PROPFIND",
            home_url,
            log=log,
            operation="discover-calendars",
            headers={"Depth": "1", "Content-Type": "application/xml; charset=utf-8"},
            data=body2,
            auth=auth,
        )
        r2.raise_for_status()

        responses = re.findall(r"<response[^>]*>(.*?)</response>", r2.text, flags=re.S)
        cal_href = None
        for resp in responses:
            hrefm = re.search(r"<href>([^<]+)</href>", resp)
            dnm = re.search(r"<displayname[^>]*>([^<]*)</displayname>", resp)
            href = hrefm.group(1) if hrefm else ""
            dn = (dnm.group(1) if dnm else "").strip()
            if "/calendars/" in href and not href.endswith("/calendars/") and dn == self.cfg.icloud_target_calendar_display:
                cal_href = href
                break

        if not cal_href:
            raise RuntimeError(f"iCloud calendar '{self.cfg.icloud_target_calendar_display}' not found")

        host_match = re.match(r"https://([^/]+)/", home_url)
        host = host_match.group(1) if host_match else "caldav.icloud.com"
        base = f"https://{host}"
        self._base, self._cal_href = base, cal_href
        return base, cal_href

    def list_events(self, start: datetime, end: datetime, log: Logger) -> List[SyncEvent]:
        base, cal_href = self.discover(log)
        auth = self._auth()
        body = f'''<?xml version="1.0" encoding="UTF-8"?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <D:getetag/>
    <C:calendar-data/>
  </D:prop>
  <C:filter>
    <C:comp-filter name="VCALENDAR">
      <C:comp-filter name="VEVENT">
        <C:time-range start="{start.strftime('%Y%m%dT000000Z')}" end="{end.strftime('%Y%m%dT235959Z')}"/>
      </C:comp-filter>
    </C:comp-filter>
      </C:filter>
</C:calendar-query>'''
        r = self._request_with_retry(
            "REPORT",
            join_absolute_url(base, cal_href),
            log=log,
            operation="list-events",
            headers={"Depth": "1", "Content-Type": "application/xml; charset=utf-8"},
            data=body,
            auth=auth,
        )
        r.raise_for_status()

        out: List[SyncEvent] = []
        responses = re.findall(r"<response[^>]*>(.*?)</response>", r.text, flags=re.S)
        for resp in responses:
            hrefm = re.search(r"<href>([^<]+\.ics)</href>", resp)
            datam = re.search(r"<calendar-data[^>]*>([\s\S]*?)</calendar-data>", resp)
            if not hrefm or not datam:
                continue
            href = hrefm.group(1)
            ics = datam.group(1)
            lines = lines_unfold_ics(ics)

            dtstart_prop = parse_ics_prop(lines, "DTSTART")
            dtend_prop = parse_ics_prop(lines, "DTEND")
            if not dtstart_prop or not dtend_prop:
                continue
            start_n = dt_ics_to_normalized(dtstart_prop[1], dtstart_prop[0])
            end_n = dt_ics_to_normalized(dtend_prop[1], dtend_prop[0])
            if not start_n or not end_n:
                continue

            rec = [ln for ln in lines if ln.upper().startswith("RRULE:")]

            last_modified_prop = parse_ics_prop(lines, "LAST-MODIFIED")
            dtstamp_prop = parse_ics_prop(lines, "DTSTAMP")
            modified = None
            if last_modified_prop:
                modified = ics_prop_to_dt(last_modified_prop[0], last_modified_prop[1])
            if not modified and dtstamp_prop:
                modified = ics_prop_to_dt(dtstamp_prop[0], dtstamp_prop[1])
            if not modified:
                modified = normalized_start_to_dt(start_n)
                log.warn("icloud_missing_last_modified_fallback", href=href)

            out.append(
                SyncEvent(
                    provider=SOURCE_ICLOUD,
                    provider_id=href,
                    title=normalize_singleline_text(ics_unescape(parse_ics_value(lines, "SUMMARY") or "(ohne Betreff)")),
                    start=start_n,
                    end=end_n,
                    description=normalize_calendar_description(
                        ics_unescape(parse_ics_value(lines, "DESCRIPTION") or ""),
                        source_format="auto",
                    ),
                    location=normalize_singleline_text(ics_unescape(parse_ics_value(lines, "LOCATION") or "")),
                    recurrence=rec,
                    sync_id=parse_ics_value(lines, ICLOUD_META_SYNC_ID) or None,
                    sync_origin=SYNC_ORIGIN_METADATA if parse_ics_value(lines, ICLOUD_META_SYNC_ID) else "",
                    source=parse_ics_value(lines, ICLOUD_META_SOURCE) or None,
                    mode=parse_ics_value(lines, ICLOUD_META_MODE) or None,
                    modified_at=modified,
                    uid=parse_ics_value(lines, "UID") or None,
                    href=href,
                    raw={"ics": ics},
                )
            )
        return out

    def _build_ics(self, event: SyncEvent, sync_id: str, source: str, mode: str, blocked_title: str, uid: str) -> str:
        title = blocked_title if mode == MODE_BLOCKED else normalize_singleline_text(event.title)
        description = "" if mode == MODE_BLOCKED else normalize_calendar_description(event.description, source_format="auto")
        location = "" if mode == MODE_BLOCKED else normalize_singleline_text(event.location)

        start_params, start_value = normalized_to_ics(event.start)
        end_params, end_value = normalized_to_ics(event.end, end=True)

        lines = [
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//Aether//OpenClaw//DE",
            "BEGIN:VEVENT",
            f"UID:{uid}",
            f"DTSTAMP:{now_utc().strftime('%Y%m%dT%H%M%SZ')}",
            f"LAST-MODIFIED:{now_utc().strftime('%Y%m%dT%H%M%SZ')}",
            f"SUMMARY:{ics_escape(title)}",
            f"DTSTART{start_params}:{start_value}",
            f"DTEND{end_params}:{end_value}",
        ]

        if description:
            lines.append(f"DESCRIPTION:{ics_escape(description)}")
        if location:
            lines.append(f"LOCATION:{ics_escape(location)}")

        for rule in event.recurrence or []:
            if rule.upper().startswith("RRULE:"):
                lines.append(rule)

        lines.extend(
            [
                f"{ICLOUD_META_SYNC_ID}:{sync_id}",
                f"{ICLOUD_META_SOURCE}:{source}",
                f"{ICLOUD_META_MODE}:{mode}",
                "END:VEVENT",
                "END:VCALENDAR",
            ]
        )
        return "\r\n".join(lines) + "\r\n"

    def upsert_event(
        self,
        existing: Optional[SyncEvent],
        desired: SyncEvent,
        sync_id: str,
        source: str,
        mode: str,
        blocked_title: str,
        dry_run: bool,
        log: Logger,
    ) -> str:
        base, cal_href = self.discover(log)
        auth = self._auth()

        desired_fp = desired.fingerprint(mode, blocked_title)
        before_snapshot = event_log_snapshot(existing, existing.mode or mode, blocked_title) if existing else None
        after_snapshot = event_log_snapshot(desired, mode, blocked_title)
        if existing and desired_fp == existing.fingerprint(mode, blocked_title) and existing.source == source and existing.mode == mode:
            log.action("icloud", "skipped", sync_id, "no-change", before=before_snapshot, after=after_snapshot)
            return existing.provider_id

        uid = existing.uid if existing and existing.uid else str(uuid.uuid4())
        href = existing.href if existing and existing.href else cal_href + uid + ".ics"
        ics = self._build_ics(desired, sync_id, source, mode, blocked_title, uid)

        if dry_run:
            action = "updated" if existing else "created"
            log.action("icloud", action, sync_id, "dry-run", before=before_snapshot, after=after_snapshot)
            return href

        r = self._request_with_retry(
            "PUT",
            join_absolute_url(base, href),
            log=log,
            operation="upsert-event",
            data=ics.encode("utf-8"),
            headers={"Content-Type": "text/calendar; charset=utf-8"},
            auth=auth,
        )
        r.raise_for_status()
        action = "updated" if existing else "created"
        log.action("icloud", action, sync_id, before=before_snapshot, after=after_snapshot)
        return href

    def delete_event(self, event: SyncEvent, sync_id: str, dry_run: bool, log: Logger, detail: str = "") -> None:
        base, _cal_href = self.discover(log)
        before_snapshot = event_log_snapshot(event, event.mode or MODE_FULL)
        if dry_run:
            suffix = "dry-run" if not detail else f"{detail},dry-run"
            log.action("icloud", "deleted", sync_id, suffix, before=before_snapshot, after=None)
            return

        r = self._request_with_retry(
            "DELETE",
            join_absolute_url(base, event.href or event.provider_id),
            log=log,
            operation="delete-event",
            auth=self._auth(),
        )
        if r.status_code not in {204, 404}:
            r.raise_for_status()
        log.action(
            "icloud",
            "deleted",
            sync_id,
            detail or ("already-missing" if r.status_code == 404 else ""),
            before=before_snapshot,
            after=None,
        )


class GoogleClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._token: Optional[str] = None

    def _token_from_refresh(self) -> Optional[str]:
        if not (
            self.cfg.google_oauth_client_id
            and self.cfg.google_oauth_client_secret
            and self.cfg.google_oauth_refresh_token
        ):
            return None

        r = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": self.cfg.google_oauth_client_id,
                "client_secret": self.cfg.google_oauth_client_secret,
                "refresh_token": self.cfg.google_oauth_refresh_token,
                "grant_type": "refresh_token",
            },
            timeout=self.cfg.timeout_sec,
        )
        r.raise_for_status()
        return r.json().get("access_token")

    def _token_from_service_account(self) -> Optional[str]:
        if not self.cfg.google_service_account_json:
            return None

        try:
            import jwt  # type: ignore
        except Exception as exc:
            raise RuntimeError("PyJWT missing: cannot use GOOGLE_SERVICE_ACCOUNT_JSON") from exc

        raw = self.cfg.google_service_account_json.strip()
        if raw.startswith("{"):
            sa = json.loads(raw)
        else:
            sa = json.loads(Path(raw).read_text(encoding="utf-8"))

        now = int(datetime.utcnow().timestamp())
        claims: Dict[str, Any] = {
            "iss": sa["client_email"],
            "scope": "https://www.googleapis.com/auth/calendar",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 3600,
        }
        if self.cfg.google_impersonate_user:
            claims["sub"] = self.cfg.google_impersonate_user

        assertion = jwt.encode(claims, sa["private_key"], algorithm="RS256")
        r = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
            },
            timeout=self.cfg.timeout_sec,
        )
        r.raise_for_status()
        return r.json().get("access_token")

    def _token_value(self) -> str:
        if self._token:
            return self._token
        tok = self._token_from_refresh() or self._token_from_service_account()
        if not tok:
            raise RuntimeError("google auth config missing")
        self._token = tok
        return tok

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token_value()}",
            "Content-Type": "application/json",
        }

    @staticmethod
    def _extract_meta(item: Dict[str, Any]) -> Dict[str, str]:
        p = (((item.get("extendedProperties") or {}).get("private") or {}))
        return {
            "sync_id": p.get(GOOGLE_META_SYNC_ID, ""),
            "source": p.get(GOOGLE_META_SOURCE, ""),
            "mode": p.get(GOOGLE_META_MODE, ""),
        }

    def list_events(self, start: datetime, end: datetime) -> List[SyncEvent]:
        url = f"https://www.googleapis.com/calendar/v3/calendars/{self.cfg.google_calendar_id}/events"
        params: Dict[str, Any] = {
            "timeMin": iso_z(start),
            "timeMax": iso_z(end),
            "singleEvents": "true",
            "showDeleted": "false",
            "maxResults": 2500,
        }
        out: List[SyncEvent] = []
        page_token: Optional[str] = None
        while True:
            if page_token:
                params["pageToken"] = page_token
            else:
                params.pop("pageToken", None)

            r = requests.get(url, headers=self._headers(), params=params, timeout=self.cfg.timeout_sec)
            r.raise_for_status()
            payload = r.json()
            items = payload.get("items", [])

            for it in items:
                start_n = normalize_google_dt(it.get("start", {}))
                end_n = normalize_google_dt(it.get("end", {}))
                if not start_n or not end_n:
                    continue

                meta = self._extract_meta(it)
                out.append(
                    SyncEvent(
                        provider=SOURCE_GOOGLE,
                        provider_id=str(it.get("id", "")),
                        title=normalize_singleline_text(str(it.get("summary", "") or "(ohne Betreff)")),
                        start=start_n,
                        end=end_n,
                        description=normalize_calendar_description(str(it.get("description", "") or ""), source_format="auto"),
                        location=normalize_singleline_text(str(it.get("location", "") or "")),
                        recurrence=list(it.get("recurrence", []) or []),
                        sync_id=meta.get("sync_id") or None,
                        sync_origin=SYNC_ORIGIN_METADATA if meta.get("sync_id") else "",
                        source=meta.get("source") or None,
                        mode=meta.get("mode") or None,
                        modified_at=parse_any_datetime(it.get("updated")),
                        raw=it,
                    )
                )
            page_token = payload.get("nextPageToken")
            if not page_token:
                break
        return out

    def _payload_for_event(self, event: SyncEvent, sync_id: str, source: str, mode: str, blocked_title: str) -> Dict[str, Any]:
        title = blocked_title if mode == MODE_BLOCKED else normalize_singleline_text(event.title)
        description = "" if mode == MODE_BLOCKED else normalize_calendar_description(event.description, source_format="auto")
        location = "" if mode == MODE_BLOCKED else normalize_singleline_text(event.location)

        if event.start.get("all_day"):
            start_obj = {"date": event.start["date"]}
            end_obj = {"date": event.end["date"]}
        else:
            start_obj = {"dateTime": event.start["dateTime"], "timeZone": "UTC"}
            end_obj = {"dateTime": event.end["dateTime"], "timeZone": "UTC"}

        payload: Dict[str, Any] = {
            "summary": title,
            "start": start_obj,
            "end": end_obj,
            "extendedProperties": {
                "private": {
                    GOOGLE_META_SYNC_ID: sync_id,
                    GOOGLE_META_SOURCE: source,
                    GOOGLE_META_MODE: mode,
                }
            },
        }

        if event.recurrence:
            payload["recurrence"] = event.recurrence

        if description:
            payload["description"] = description
        if location:
            payload["location"] = location

        if mode == MODE_BLOCKED:
            payload["visibility"] = "private"
            payload["transparency"] = "opaque"

        return payload

    def upsert_event(
        self,
        existing: Optional[SyncEvent],
        desired: SyncEvent,
        sync_id: str,
        source: str,
        mode: str,
        blocked_title: str,
        dry_run: bool,
        log: Logger,
    ) -> str:
        payload = self._payload_for_event(desired, sync_id, source, mode, blocked_title)

        if existing:
            desired_fp = desired.fingerprint(mode, blocked_title)
            existing_fp = existing.fingerprint(mode, blocked_title)
            before_snapshot = event_log_snapshot(existing, existing.mode or mode, blocked_title)
            after_snapshot = event_log_snapshot(desired, mode, blocked_title)
            if desired_fp == existing_fp and existing.source == source and existing.mode == mode:
                log.action("google", "skipped", sync_id, "no-change", before=before_snapshot, after=after_snapshot)
                return existing.provider_id
        else:
            before_snapshot = None
            after_snapshot = event_log_snapshot(desired, mode, blocked_title)

        if dry_run:
            action = "updated" if existing else "created"
            log.action("google", action, sync_id, "dry-run", before=before_snapshot, after=after_snapshot)
            return existing.provider_id if existing else f"dry-{uuid.uuid4()}"

        recreate_existing = bool(
            existing
            and bool(existing.start.get("all_day")) != bool(desired.start.get("all_day"))
        )
        if existing:
            if recreate_existing:
                delete_url = f"https://www.googleapis.com/calendar/v3/calendars/{self.cfg.google_calendar_id}/events/{existing.provider_id}"
                delete_response = requests.delete(delete_url, headers=self._headers(), timeout=self.cfg.timeout_sec)
                if delete_response.status_code not in {204, 404, 410}:
                    delete_response.raise_for_status()
                create_url = f"https://www.googleapis.com/calendar/v3/calendars/{self.cfg.google_calendar_id}/events"
                create_response = requests.post(
                    create_url,
                    headers=self._headers(),
                    data=json.dumps(payload),
                    timeout=self.cfg.timeout_sec,
                )
                create_response.raise_for_status()
                out = create_response.json()
                log.action(
                    "google",
                    "updated",
                    sync_id,
                    "recreated-time-model",
                    before=before_snapshot,
                    after=after_snapshot,
                )
                return str(out.get("id"))

            url = f"https://www.googleapis.com/calendar/v3/calendars/{self.cfg.google_calendar_id}/events/{existing.provider_id}"
            r = requests.patch(url, headers=self._headers(), data=json.dumps(payload), timeout=self.cfg.timeout_sec)
            r.raise_for_status()
            log.action("google", "updated", sync_id, before=before_snapshot, after=after_snapshot)
            return existing.provider_id

        url = f"https://www.googleapis.com/calendar/v3/calendars/{self.cfg.google_calendar_id}/events"
        r = requests.post(url, headers=self._headers(), data=json.dumps(payload), timeout=self.cfg.timeout_sec)
        r.raise_for_status()
        out = r.json()
        log.action("google", "created", sync_id, before=before_snapshot, after=after_snapshot)
        return str(out.get("id"))

    def delete_event(self, event: SyncEvent, sync_id: str, dry_run: bool, log: Logger, detail: str = "") -> None:
        before_snapshot = event_log_snapshot(event, event.mode or MODE_FULL)
        if dry_run:
            suffix = "dry-run" if not detail else f"{detail},dry-run"
            log.action("google", "deleted", sync_id, suffix, before=before_snapshot, after=None)
            return

        url = f"https://www.googleapis.com/calendar/v3/calendars/{self.cfg.google_calendar_id}/events/{event.provider_id}"
        r = requests.delete(url, headers=self._headers(), timeout=self.cfg.timeout_sec)
        if r.status_code not in {204, 404, 410}:
            r.raise_for_status()
        detail_text = detail or ("already-missing" if r.status_code in {404, 410} else "")
        log.action("google", "deleted", sync_id, detail_text, before=before_snapshot, after=None)


def event_modified_or_fallback(event: SyncEvent) -> datetime:
    return event.modified_at or normalized_start_to_dt(event.start)


def event_time_signature(event: SyncEvent) -> str:
    return json.dumps({"start": event.start, "end": event.end}, sort_keys=True, ensure_ascii=False)


def effective_event_mode(event: SyncEvent, blocked_title: str) -> str:
    if event.mode in {MODE_FULL, MODE_BLOCKED}:
        return str(event.mode)
    if google_source_skip_reason(event, blocked_title) == "google-blocked-mirror":
        return MODE_BLOCKED
    return MODE_FULL


def event_log_snapshot(event: Optional[SyncEvent], mode: Optional[str], blocked_title: str = "Blocked") -> Optional[Dict[str, Any]]:
    if event is None:
        return None
    effective_mode = (mode or effective_event_mode(event, blocked_title)).strip().lower()
    title = blocked_title if effective_mode == MODE_BLOCKED else normalize_singleline_text(event.title)
    description = "" if effective_mode == MODE_BLOCKED else normalize_calendar_description(event.description, source_format="auto")
    location = "" if effective_mode == MODE_BLOCKED else normalize_singleline_text(event.location)
    starts_at = event.start.get("date") if event.start.get("all_day") else event.start.get("dateTime")
    ends_at = event.end.get("date") if event.end.get("all_day") else event.end.get("dateTime")
    return {
        "title": title,
        "starts_at": str(starts_at or ""),
        "ends_at": str(ends_at or ""),
        "all_day": bool(event.start.get("all_day")),
        "description": description,
        "location": location,
        "recurrence": [line for line in event.recurrence or [] if line.strip()],
    }


def event_snapshot_fingerprint(event: SyncEvent, blocked_title: str) -> str:
    return event.fingerprint(effective_event_mode(event, blocked_title), blocked_title)


def snapshot_matches_event(snapshot: Dict[str, Any], event: SyncEvent, blocked_title: str) -> bool:
    if not snapshot:
        return False
    return snapshot.get("fingerprint") == event_snapshot_fingerprint(event, blocked_title)


def provider_can_trigger_delete(provider: str, snapshot: Dict[str, Any]) -> bool:
    if not snapshot:
        return False
    if provider == SOURCE_GOOGLE:
        return snapshot.get("mode") != MODE_BLOCKED
    return True


def sync_origin_rank(origin: str) -> int:
    return {
        SYNC_ORIGIN_METADATA: 4,
        SYNC_ORIGIN_STATE: 3,
        SYNC_ORIGIN_MATCHED: 2,
        SYNC_ORIGIN_STABLE: 1,
    }.get(origin or "", 1)


def select_primary_event(events: List[SyncEvent], preferred_provider_id: Optional[str], blocked_title: str) -> SyncEvent:
    return max(
        events,
        key=lambda ev: (
            1 if preferred_provider_id and ev.provider_id == preferred_provider_id else 0,
            1 if effective_event_mode(ev, blocked_title) != MODE_BLOCKED else 0,
            sync_origin_rank(ev.sync_origin),
            event_modified_or_fallback(ev),
            ev.provider_id,
        ),
    )


def dedupe_provider_events(
    provider: str,
    events: List[SyncEvent],
    state: SyncState,
    blocked_title: str,
    log: Logger,
) -> Tuple[List[SyncEvent], List[SyncEvent]]:
    by_sync: Dict[str, List[SyncEvent]] = defaultdict(list)
    for event in events:
        if event.sync_id:
            by_sync[event.sync_id].append(event)

    deduped: List[SyncEvent] = []
    extras: List[SyncEvent] = []
    for sync_id, group in by_sync.items():
        if len(group) == 1:
            deduped.append(group[0])
            continue

        preferred_provider_id = state.get_provider_id(provider, sync_id)
        primary = select_primary_event(group, preferred_provider_id, blocked_title)
        deduped.append(primary)
        state.set_mapping(provider, primary.provider_id, sync_id)
        for event in group:
            if event is primary:
                continue
            extras.append(event)
        log.warn("duplicate_provider_events_detected", provider=provider, sync_id=sync_id, count=len(group))

    deduped.sort(key=lambda ev: (normalized_start_to_dt(ev.start), ev.provider_id))
    return deduped, extras


def relink_orphan_event(
    known: SyncEvent,
    orphan: SyncEvent,
    state: SyncState,
    match_kind: str,
    log: Logger,
) -> None:
    orphan.sync_id = known.sync_id
    orphan.sync_origin = SYNC_ORIGIN_MATCHED
    state.set_mapping(orphan.provider, orphan.provider_id, str(known.sync_id))
    log.info(
        "relinked_orphan",
        provider=orphan.provider,
        provider_id=orphan.provider_id,
        sync_id=known.sync_id,
        match=match_kind,
    )


def reconcile_orphaned_events(
    by_provider: Dict[str, List[SyncEvent]],
    enabled_providers: List[str],
    state: SyncState,
    blocked_title: str,
    log: Logger,
) -> None:
    changed = True
    while changed:
        changed = False
        for source_provider in enabled_providers:
            for target_provider in enabled_providers:
                if source_provider == target_provider:
                    continue

                known_by_fp: Dict[str, List[SyncEvent]] = defaultdict(list)
                orphan_by_fp: Dict[str, List[SyncEvent]] = defaultdict(list)

                for event in by_provider[source_provider]:
                    if event.sync_origin == SYNC_ORIGIN_STABLE:
                        continue
                    if effective_event_mode(event, blocked_title) == MODE_BLOCKED:
                        continue
                    known_by_fp[event.fingerprint(MODE_FULL, blocked_title)].append(event)

                for event in by_provider[target_provider]:
                    if event.sync_origin != SYNC_ORIGIN_STABLE:
                        continue
                    if effective_event_mode(event, blocked_title) == MODE_BLOCKED:
                        continue
                    orphan_by_fp[event.fingerprint(MODE_FULL, blocked_title)].append(event)

                for fp in sorted(set(known_by_fp) & set(orphan_by_fp)):
                    if len(known_by_fp[fp]) != 1 or len(orphan_by_fp[fp]) != 1:
                        continue
                    known = known_by_fp[fp][0]
                    orphan = orphan_by_fp[fp][0]
                    if not known.sync_id or known.sync_id == orphan.sync_id:
                        continue
                    relink_orphan_event(known, orphan, state, "full", log)
                    changed = True

        if SOURCE_GOOGLE not in enabled_providers:
            continue

        source_by_fp: Dict[str, List[SyncEvent]] = defaultdict(list)
        google_blocked_by_fp: Dict[str, List[SyncEvent]] = defaultdict(list)

        for provider in [SOURCE_EXCHANGE, SOURCE_ICLOUD]:
            if provider not in enabled_providers:
                continue
            for event in by_provider[provider]:
                if event.sync_origin == SYNC_ORIGIN_STABLE:
                    continue
                source_by_fp[event.fingerprint(MODE_BLOCKED, blocked_title)].append(event)

        for event in by_provider[SOURCE_GOOGLE]:
            if event.sync_origin != SYNC_ORIGIN_STABLE:
                continue
            if effective_event_mode(event, blocked_title) != MODE_BLOCKED:
                continue
            google_blocked_by_fp[event.fingerprint(MODE_BLOCKED, blocked_title)].append(event)

        for fp in sorted(set(source_by_fp) & set(google_blocked_by_fp)):
            if len(source_by_fp[fp]) != 1 or len(google_blocked_by_fp[fp]) != 1:
                continue
            known = source_by_fp[fp][0]
            orphan = google_blocked_by_fp[fp][0]
            if not known.sync_id or known.sync_id == orphan.sync_id:
                continue
            relink_orphan_event(known, orphan, state, "blocked", log)
            changed = True


def infer_group_delete_reason(
    sync_id: str,
    current_by_provider: Dict[str, Optional[SyncEvent]],
    state: SyncState,
    blocked_title: str,
) -> Optional[str]:
    missing_sources: List[str] = []
    known_providers = state.data.get("sync_to_provider", {}).get(sync_id, {})
    for provider in known_providers:
        if current_by_provider.get(provider):
            continue
        snapshot = state.get_provider_record(sync_id, provider)
        if provider_can_trigger_delete(provider, snapshot):
            missing_sources.append(provider)

    if not missing_sources:
        return None

    present_sources = [
        event
        for event in current_by_provider.values()
        if event and is_source_candidate(event, blocked_title)[0]
    ]
    if not present_sources:
        return "source-deleted:" + ",".join(sorted(missing_sources))

    if all(snapshot_matches_event(state.get_provider_record(sync_id, event.provider), event, blocked_title) for event in present_sources):
        return "source-deleted:" + ",".join(sorted(missing_sources))

    return None


def remember_event_snapshot(
    state: SyncState,
    sync_id: str,
    provider: str,
    provider_id: str,
    desired: SyncEvent,
    source: str,
    mode: str,
    blocked_title: str,
    modified_at: Optional[datetime] = None,
) -> None:
    fingerprint = desired.fingerprint(mode, blocked_title)
    state.set_provider_record(
        sync_id=sync_id,
        provider=provider,
        provider_id=provider_id,
        fingerprint=fingerprint,
        source=source,
        mode=mode,
        modified_at=modified_at or now_utc(),
    )


def google_source_skip_reason(event: SyncEvent, blocked_title: str) -> Optional[str]:
    if event.provider != SOURCE_GOOGLE:
        return None

    source = (event.source or "").strip().lower()
    mode = (event.mode or "").strip().lower()

    if mode == MODE_BLOCKED:
        return "google-blocked-mirror"

    if source in {SOURCE_EXCHANGE, SOURCE_ICLOUD}:
        return "google-blocked-mirror"

    if mode == MODE_FULL and source == SOURCE_GOOGLE:
        return None

    if not source and not mode:
        is_blocked_signature = (
            (event.title or "").strip() == blocked_title
            and not (event.description or "").strip()
            and not (event.location or "").strip()
            and (
                (event.raw.get("visibility") == "private")
                or (event.raw.get("transparency") == "opaque")
            )
        )
        if is_blocked_signature:
            return "google-blocked-mirror"
        return None

    return "google-non-authoritative"


def is_source_candidate(event: SyncEvent, blocked_title: str) -> Tuple[bool, str]:
    reason = google_source_skip_reason(event, blocked_title)
    if reason:
        return False, reason
    return True, ""


def resolve_group_conflict(sync_id: str, events: List[SyncEvent], log: Logger) -> Tuple[SyncEvent, str, SyncEvent]:
    ordered = sorted(events, key=lambda e: (event_modified_or_fallback(e), e.provider), reverse=True)
    winner = ordered[0]

    unique_time = {event_time_signature(e) for e in events}
    if len(events) > 1 and len(unique_time) > 1:
        winner_ts = iso_z(event_modified_or_fallback(winner))
        for loser in ordered[1:]:
            log.info(
                "conflict_detected",
                sync_id=sync_id,
                winner_provider=winner.provider,
                winner_timestamp=winner_ts,
                overwritten_provider=loser.provider,
            )

    source_hint = winner.source if winner.source in {SOURCE_EXCHANGE, SOURCE_ICLOUD, SOURCE_GOOGLE} else None
    if winner.mode == MODE_BLOCKED and source_hint:
        authoritative_source = source_hint
    else:
        authoritative_source = winner.provider

    detail_candidates = [e for e in ordered if e.mode != MODE_BLOCKED]
    detail_base = detail_candidates[0] if detail_candidates else winner

    merged = SyncEvent(
        provider=winner.provider,
        provider_id=winner.provider_id,
        title=detail_base.title,
        start=winner.start,
        end=winner.end,
        description=detail_base.description,
        location=detail_base.location,
        recurrence=winner.recurrence or detail_base.recurrence,
        sync_id=sync_id,
        source=authoritative_source,
        mode=MODE_FULL,
        modified_at=event_modified_or_fallback(winner),
        raw={"winner": winner.provider, "detail_base": detail_base.provider},
    )

    return winner, authoritative_source, merged


def choose_target_mode(source_provider: str, target_provider: str) -> str:
    if target_provider == SOURCE_GOOGLE and source_provider in {SOURCE_EXCHANGE, SOURCE_ICLOUD}:
        return MODE_BLOCKED
    return MODE_FULL


def index_by_sync(events: List[SyncEvent]) -> Dict[str, SyncEvent]:
    out: Dict[str, SyncEvent] = {}
    for ev in events:
        if ev.sync_id:
            out[ev.sync_id] = ev
    return out


def index_by_id(events: List[SyncEvent]) -> Dict[str, SyncEvent]:
    return {ev.provider_id: ev for ev in events}


def parse_http_error(err: requests.HTTPError) -> Tuple[Any, str, str]:
    status = err.response.status_code if err.response is not None else "n/a"
    code = "http_error"
    detail = str(err)

    if err.response is not None:
        try:
            payload = err.response.json()
            if isinstance(payload, dict):
                e = payload.get("error")
                if isinstance(e, dict):
                    code = str(e.get("code") or code)
                    msg = e.get("message")
                    if msg:
                        detail = str(msg)
                elif isinstance(e, str):
                    code = e
        except Exception:
            pass

    return status, code, detail


def is_backoff_status(status: Any) -> bool:
    try:
        s = int(status)
    except Exception:
        return False
    return s in {429, 503, 507}


def compute_backoff_ms(attempt: int, base_ms: int, max_ms: int) -> int:
    exp = max(0, attempt - 1)
    delay = base_ms * (2 ** exp)
    return max(0, min(delay, max_ms))


def serialize_retry_event(event: SyncEvent) -> Dict[str, Any]:
    return {
        "title": event.title,
        "start": event.start,
        "end": event.end,
        "description": event.description,
        "location": event.location,
        "recurrence": event.recurrence,
        "modified_at": iso_z(event.modified_at) if event.modified_at else "",
    }


def deserialize_retry_event(payload: Dict[str, Any], provider: str, sync_id: str) -> SyncEvent:
    mod_at = parse_any_datetime(payload.get("modified_at"))
    return SyncEvent(
        provider=provider,
        provider_id="",
        title=payload.get("title", "(ohne Betreff)"),
        start=payload.get("start", {}),
        end=payload.get("end", {}),
        description=payload.get("description", ""),
        location=payload.get("location", ""),
        recurrence=list(payload.get("recurrence", []) or []),
        sync_id=sync_id,
        modified_at=mod_at,
    )


def enqueue_retry(
    state: SyncState,
    sync_id: str,
    provider: str,
    desired: SyncEvent,
    source: str,
    mode: str,
    status: Any,
    code: str,
    detail: str,
    now_dt: datetime,
    cfg: Config,
) -> None:
    prev = state.get_retry_entry(sync_id, provider) or {}
    attempts = int(prev.get("attempts", 0)) + 1
    backoff_ms = compute_backoff_ms(attempts, cfg.write_backoff_base_ms, cfg.write_backoff_max_ms)
    next_retry_at = now_dt + timedelta(milliseconds=backoff_ms)
    state.set_retry_entry(
        sync_id,
        provider,
        {
            "sync_id": sync_id,
            "provider": provider,
            "source": source,
            "mode": mode,
            "desired": serialize_retry_event(desired),
            "attempts": attempts,
            "last_error": {"status": status, "code": code, "detail": detail},
            "next_retry_at": iso_z(next_retry_at),
            "updated_at": iso_z(now_dt),
        },
    )


def maybe_checkpoint(state: SyncState, dry_run: bool) -> None:
    if not dry_run:
        state.save()


def execute_provider_write(
    *,
    provider: str,
    sync_id: str,
    cfg: Config,
    state: SyncState,
    log: Logger,
    dry_run: bool,
    write_index: int,
    op_label: str,
    fn,
    desired: Optional[SyncEvent] = None,
    source: str = "",
    mode: str = MODE_FULL,
) -> Tuple[Optional[str], int]:
    if write_index >= cfg.max_writes_per_run:
        log._inc("write_cap_skipped")
        log.action(provider, "skipped", sync_id, f"write-cap:{cfg.max_writes_per_run}")
        return None, write_index

    if cfg.write_delay_ms > 0 and write_index > 0:
        time.sleep(cfg.write_delay_ms / 1000.0)

    log._inc("writes_attempted")
    write_index += 1

    try:
        result = fn()
        if provider == SOURCE_ICLOUD and not dry_run:
            state.remove_retry_entry(sync_id, SOURCE_ICLOUD)
            maybe_checkpoint(state, dry_run)
        return result, write_index
    except requests.HTTPError as err:
        status, code, detail = parse_http_error(err)
        log.provider_error(provider, sync_id, status=status, code=code, detail=detail)

        if provider == SOURCE_ICLOUD and str(status) == "507" and desired is not None:
            enqueue_retry(
                state=state,
                sync_id=sync_id,
                provider=provider,
                desired=desired,
                source=source,
                mode=mode,
                status=status,
                code=code,
                detail=detail,
                now_dt=now_utc(),
                cfg=cfg,
            )
            maybe_checkpoint(state, dry_run)

        if cfg.write_backoff_enabled and is_backoff_status(status):
            retry_entry = state.get_retry_entry(sync_id, provider)
            attempt = int((retry_entry or {}).get("attempts", 1))
            backoff_ms = compute_backoff_ms(attempt, cfg.write_backoff_base_ms, cfg.write_backoff_max_ms)
            if backoff_ms > 0:
                time.sleep(backoff_ms / 1000.0)

        return None, write_index


def process_retry_queue(
    *,
    cfg: Config,
    state: SyncState,
    log: Logger,
    dry_run: bool,
    write_index: int,
    exchange: ExchangeClient,
    icloud: ICloudClient,
    google: Optional[GoogleClient],
    indices_id: Dict[str, Dict[str, SyncEvent]],
) -> int:
    due = state.due_retry_entries(now_utc())
    if not due:
        return write_index

    for item in due:
        provider = item.get("provider", "")
        sync_id = item.get("sync_id", "")
        if not provider or not sync_id:
            continue

        desired = deserialize_retry_event(item.get("desired", {}), provider=provider, sync_id=sync_id)
        source = item.get("source", SOURCE_EXCHANGE)
        mode = item.get("mode", MODE_FULL)

        existing = None
        known_id = state.get_provider_id(provider, sync_id)
        if known_id:
            existing = indices_id.get(provider, {}).get(known_id)

        if provider == SOURCE_EXCHANGE:
            result, write_index = execute_provider_write(
                provider=provider,
                sync_id=sync_id,
                cfg=cfg,
                state=state,
                log=log,
                dry_run=dry_run,
                write_index=write_index,
                op_label="retry-upsert",
                fn=lambda: exchange.upsert_event(
                    existing=existing,
                    desired=desired,
                    sync_id=sync_id,
                    source=source,
                    mode=mode,
                    blocked_title=cfg.google_blocked_title,
                    dry_run=dry_run,
                    log=log,
                ),
                desired=desired,
                source=source,
                mode=mode,
            )
        elif provider == SOURCE_ICLOUD:
            result, write_index = execute_provider_write(
                provider=provider,
                sync_id=sync_id,
                cfg=cfg,
                state=state,
                log=log,
                dry_run=dry_run,
                write_index=write_index,
                op_label="retry-upsert",
                fn=lambda: icloud.upsert_event(
                    existing=existing,
                    desired=desired,
                    sync_id=sync_id,
                    source=source,
                    mode=mode,
                    blocked_title=cfg.google_blocked_title,
                    dry_run=dry_run,
                    log=log,
                ),
                desired=desired,
                source=source,
                mode=mode,
            )
        elif provider == SOURCE_GOOGLE and google:
            result, write_index = execute_provider_write(
                provider=provider,
                sync_id=sync_id,
                cfg=cfg,
                state=state,
                log=log,
                dry_run=dry_run,
                write_index=write_index,
                op_label="retry-upsert",
                fn=lambda: google.upsert_event(
                    existing=existing,
                    desired=desired,
                    sync_id=sync_id,
                    source=source,
                    mode=mode,
                    blocked_title=cfg.google_blocked_title,
                    dry_run=dry_run,
                    log=log,
                ),
                desired=desired,
                source=source,
                mode=mode,
            )
        else:
            continue

        if result:
            state.set_mapping(provider, result, sync_id)
            remember_event_snapshot(
                state=state,
                sync_id=sync_id,
                provider=provider,
                provider_id=result,
                desired=desired,
                source=source,
                mode=mode,
                blocked_title=cfg.google_blocked_title,
                modified_at=now_utc(),
            )
            state.remove_retry_entry(sync_id, provider)
            maybe_checkpoint(state, dry_run)

    return write_index


def delete_provider_event(
    provider: str,
    event: SyncEvent,
    sync_id: str,
    exchange: ExchangeClient,
    icloud: ICloudClient,
    google: Optional[GoogleClient],
    dry_run: bool,
    log: Logger,
    detail: str = "",
) -> None:
    if provider == SOURCE_EXCHANGE:
        exchange.delete_event(event, sync_id, dry_run, log, detail)
        return
    if provider == SOURCE_ICLOUD:
        icloud.delete_event(event, sync_id, dry_run, log, detail)
        return
    if provider == SOURCE_GOOGLE and google:
        google.delete_event(event, sync_id, dry_run, log, detail)


def sync_three_way(cfg: Config, dry_run: bool, window_days: int) -> None:
    log = Logger()
    state = SyncState(cfg.state_path)

    start = now_utc() - timedelta(days=1)
    end = now_utc() + timedelta(days=window_days)

    log.info(
        "START",
        dry_run=dry_run,
        google_enabled=cfg.google_enabled,
        exchange_user=cfg.exchange_user,
        icloud_user=mask_for_log(cfg.icloud_user),
        google_calendar=cfg.google_calendar_id if cfg.google_enabled else "disabled",
        state_path=str(cfg.state_path),
    )

    exchange = ExchangeClient(cfg)
    icloud = ICloudClient(cfg)
    google = GoogleClient(cfg) if cfg.google_enabled else None

    ex_events = exchange.list_events(start, end, log)
    ic_events = icloud.list_events(start, end, log)
    go_events = google.list_events(start, end) if google else []

    enabled_providers = [SOURCE_EXCHANGE, SOURCE_ICLOUD] + ([SOURCE_GOOGLE] if cfg.google_enabled else [])

    by_provider: Dict[str, List[SyncEvent]] = {
        SOURCE_EXCHANGE: ex_events,
        SOURCE_ICLOUD: ic_events,
        SOURCE_GOOGLE: go_events,
    }

    write_index = 0

    # normalize sync ids
    for provider, events in by_provider.items():
        for ev in events:
            if ev.sync_id:
                ev.sync_origin = ev.sync_origin or SYNC_ORIGIN_METADATA
            else:
                st_sync = state.get_sync_id(provider, ev.provider_id)
                if st_sync:
                    ev.sync_id = st_sync
                    ev.sync_origin = SYNC_ORIGIN_STATE
            if not ev.sync_id:
                ev.sync_id = stable_sync_id(provider, ev.provider_id)
                ev.sync_origin = SYNC_ORIGIN_STABLE
            state.set_mapping(provider, ev.provider_id, ev.sync_id)

    reconcile_orphaned_events(by_provider, enabled_providers, state, cfg.google_blocked_title, log)

    deduped_provider: Dict[str, List[SyncEvent]] = {
        SOURCE_EXCHANGE: [],
        SOURCE_ICLOUD: [],
        SOURCE_GOOGLE: [],
    }
    for provider in enabled_providers:
        deduped, extras = dedupe_provider_events(provider, by_provider[provider], state, cfg.google_blocked_title, log)
        deduped_provider[provider] = deduped
        for extra in extras:
            extra_sync_id = extra.sync_id or stable_sync_id(provider, extra.provider_id)
            delete_result, write_index = execute_provider_write(
                provider=provider,
                sync_id=extra_sync_id,
                cfg=cfg,
                state=state,
                log=log,
                dry_run=dry_run,
                write_index=write_index,
                op_label="duplicate-cleanup-delete",
                fn=lambda p=provider, e=extra, s=extra_sync_id: (
                    delete_provider_event(
                        provider=p,
                        event=e,
                        sync_id=s,
                        exchange=exchange,
                        icloud=icloud,
                        google=google,
                        dry_run=dry_run,
                        log=log,
                        detail="duplicate-cleanup",
                    ),
                    e.provider_id,
                )[1],
            )
            if delete_result:
                state.forget_provider(provider, provider_id=extra.provider_id, sync_id=extra.sync_id)
                maybe_checkpoint(state, dry_run)

    by_provider = deduped_provider

    indices_sync = {p: index_by_sync(events) for p, events in by_provider.items()}
    indices_id = {p: index_by_id(events) for p, events in by_provider.items()}

    all_sync_ids = sorted({ev.sync_id for events in by_provider.values() for ev in events if ev.sync_id})

    for sync_id in all_sync_ids:
        current_by_provider: Dict[str, Optional[SyncEvent]] = {
            provider: indices_sync[provider].get(sync_id)
            for provider in enabled_providers
        }

        delete_reason = infer_group_delete_reason(
            sync_id=sync_id,
            current_by_provider=current_by_provider,
            state=state,
            blocked_title=cfg.google_blocked_title,
        )
        if delete_reason:
            all_deleted = True
            for provider in enabled_providers:
                event = current_by_provider.get(provider)
                if event:
                    delete_result, write_index = execute_provider_write(
                        provider=provider,
                        sync_id=sync_id,
                        cfg=cfg,
                        state=state,
                        log=log,
                        dry_run=dry_run,
                        write_index=write_index,
                        op_label="group-delete",
                        fn=lambda p=provider, e=event, s=sync_id, d=delete_reason: (
                            delete_provider_event(
                                provider=p,
                                event=e,
                                sync_id=s,
                                exchange=exchange,
                                icloud=icloud,
                                google=google,
                                dry_run=dry_run,
                                log=log,
                                detail=d,
                            ),
                            e.provider_id,
                        )[1],
                    )
                    if delete_result:
                        state.forget_provider(provider, provider_id=event.provider_id, sync_id=sync_id)
                        maybe_checkpoint(state, dry_run)
                    else:
                        all_deleted = False
                else:
                    state.forget_provider(provider, provider_id=None, sync_id=sync_id)
                    maybe_checkpoint(state, dry_run)
            if all_deleted:
                state.forget_sync(sync_id)
                maybe_checkpoint(state, dry_run)
            continue

        group = [event for event in current_by_provider.values() if event]
        if not group:
            continue

        source_group: List[SyncEvent] = []
        for ev in group:
            allowed, reason = is_source_candidate(ev, cfg.google_blocked_title)
            if not allowed:
                log.action(ev.provider, "skipped", sync_id, reason)
                continue
            source_group.append(ev)

        if not source_group:
            log.action("sync", "skipped", sync_id, "no-source-candidate")
            continue

        _winner, authoritative_source, merged = resolve_group_conflict(sync_id, source_group, log)

        for provider in enabled_providers:
            mode = choose_target_mode(authoritative_source, provider)
            existing = current_by_provider.get(provider)
            if not existing:
                known_id = state.get_provider_id(provider, sync_id)
                if known_id:
                    existing = indices_id[provider].get(known_id)

            provider_id: Optional[str] = None
            if provider == SOURCE_EXCHANGE:
                provider_id, write_index = execute_provider_write(
                    provider=provider,
                    sync_id=sync_id,
                    cfg=cfg,
                    state=state,
                    log=log,
                    dry_run=dry_run,
                    write_index=write_index,
                    op_label="upsert",
                    fn=lambda: exchange.upsert_event(
                        existing=existing,
                        desired=merged,
                        sync_id=sync_id,
                        source=authoritative_source,
                        mode=mode,
                        blocked_title=cfg.google_blocked_title,
                        dry_run=dry_run,
                        log=log,
                    ),
                    desired=merged,
                    source=authoritative_source,
                    mode=mode,
                )
            elif provider == SOURCE_ICLOUD:
                provider_id, write_index = execute_provider_write(
                    provider=provider,
                    sync_id=sync_id,
                    cfg=cfg,
                    state=state,
                    log=log,
                    dry_run=dry_run,
                    write_index=write_index,
                    op_label="upsert",
                    fn=lambda: icloud.upsert_event(
                        existing=existing,
                        desired=merged,
                        sync_id=sync_id,
                        source=authoritative_source,
                        mode=mode,
                        blocked_title=cfg.google_blocked_title,
                        dry_run=dry_run,
                        log=log,
                    ),
                    desired=merged,
                    source=authoritative_source,
                    mode=mode,
                )
            elif provider == SOURCE_GOOGLE and google:
                provider_id, write_index = execute_provider_write(
                    provider=provider,
                    sync_id=sync_id,
                    cfg=cfg,
                    state=state,
                    log=log,
                    dry_run=dry_run,
                    write_index=write_index,
                    op_label="upsert",
                    fn=lambda: google.upsert_event(
                        existing=existing,
                        desired=merged,
                        sync_id=sync_id,
                        source=authoritative_source,
                        mode=mode,
                        blocked_title=cfg.google_blocked_title,
                        dry_run=dry_run,
                        log=log,
                    ),
                    desired=merged,
                    source=authoritative_source,
                    mode=mode,
                )
            else:
                continue

            if not provider_id:
                continue

            state.set_mapping(provider, provider_id, sync_id)
            remember_event_snapshot(
                state=state,
                sync_id=sync_id,
                provider=provider,
                provider_id=provider_id,
                desired=merged,
                source=authoritative_source,
                mode=mode,
                blocked_title=cfg.google_blocked_title,
                modified_at=event_modified_or_fallback(existing) if existing and existing.provider_id == provider_id else now_utc(),
            )
            maybe_checkpoint(state, dry_run)

    write_index = process_retry_queue(
        cfg=cfg,
        state=state,
        log=log,
        dry_run=dry_run,
        write_index=write_index,
        exchange=exchange,
        icloud=icloud,
        google=google,
        indices_id=indices_id,
    )

    log.stats["retry_queue_size"] = len(state.list_retry_entries())

    if dry_run:
        log.info("STATE_SKIPPED", reason="dry-run")
    else:
        state.save()
    log.summary()
    print("SYNC_OK")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Exchange <-> iCloud (+ Google optional) calendar sync")
    p.add_argument("--dry-run", action="store_true", help="No write operations")
    p.add_argument("--window-days", type=int, default=None, help="Sync window in days (default via env)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    cfg = Config.from_env(dry_run_override=True if args.dry_run else None, window_days_override=args.window_days)
    cfg.validate()
    sync_three_way(cfg, dry_run=cfg.dry_run, window_days=cfg.window_days)


if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "n/a"
        print(f"[sync][error] HTTP failure status={status} message={exc}")
        raise
    except Exception as exc:
        print(f"[sync][error] fatal {exc}")
        raise
