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
import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth


# ===== Constants =====
MARKER_PREFIX = "AETHER_SYNC"
SYNC_VERSION = 3

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
    params_u = params.upper()

    # all-day (VALUE=DATE or 8 chars)
    if "VALUE=DATE" in params_u or re.fullmatch(r"\d{8}", value):
        if not re.fullmatch(r"\d{8}", value):
            return None
        date = f"{value[0:4]}-{value[4:6]}-{value[6:8]}"
        return {"all_day": True, "date": date}

    # timed
    m = re.fullmatch(r"(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z?", value)
    if not m:
        return None
    y, mo, d, h, mi, s = m.groups()
    return {"all_day": False, "dateTime": f"{y}-{mo}-{d}T{h}:{mi}:{s}Z"}


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
    if dt.endswith("Z"):
        val = dt
    else:
        val = dt[:19] + "Z"
    return {"all_day": False, "dateTime": val}


def normalize_google_dt(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not obj:
        return None
    if obj.get("date"):
        return {"all_day": True, "date": obj["date"]}
    raw = obj.get("dateTime", "")
    if not raw:
        return None
    if raw.endswith("Z"):
        val = raw
    else:
        # best effort: no timezone conversion, assume UTC-like timestamp
        val = raw[:19] + "Z"
    return {"all_day": False, "dateTime": val}


def json_fp(data: Dict[str, Any]) -> str:
    return hashlib.sha1(json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


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
    source: Optional[str] = None
    mode: Optional[str] = None
    modified_at: Optional[datetime] = None
    uid: Optional[str] = None
    href: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def fingerprint(self, mode: str, blocked_title: str) -> str:
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
            "title": self.title,
            "start": self.start,
            "end": self.end,
            "description": self.description,
            "location": self.location,
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

    def action(self, provider: str, action: str, sync_id: str, detail: str = "") -> None:
        self._inc(f"{provider}_{action}")
        suffix = f" ({detail})" if detail else ""
        print(f"[sync] {provider}:{action} sync_id={sync_id}{suffix}")

    def warn(self, message: str, **data: Any) -> None:
        compact = " ".join([f"{k}={v}" for k, v in data.items() if v not in (None, "")])
        print(f"[sync][warn] {message}" + (f" {compact}" if compact else ""))

    def error(self, message: str, **data: Any) -> None:
        compact = " ".join([f"{k}={v}" for k, v in data.items() if v not in (None, "")])
        print(f"[sync][error] {message}" + (f" {compact}" if compact else ""))

    def summary(self) -> None:
        created = sum(v for k, v in self.stats.items() if k.endswith("_created"))
        updated = sum(v for k, v in self.stats.items() if k.endswith("_updated"))
        skipped = sum(v for k, v in self.stats.items() if k.endswith("_skipped"))
        self.info("SUMMARY", created=created, updated=updated, skipped=skipped)


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
        self.data["provider_to_sync"].setdefault(provider, {})[provider_id] = sync_id
        self.data["sync_to_provider"].setdefault(sync_id, {})[provider] = provider_id

    def get_provider_id(self, provider: str, sync_id: str) -> Optional[str]:
        return self.data["sync_to_provider"].get(sync_id, {}).get(provider)


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

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token_value()}",
            "Content-Type": "application/json",
        }

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

    def list_events(self, start: datetime, end: datetime, log: Logger) -> List[SyncEvent]:
        url = f"https://graph.microsoft.com/v1.0/users/{self.cfg.exchange_user}/calendarView"
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
        r = requests.get(url, headers=self._headers(), params=params, timeout=self.cfg.timeout_sec)
        r.raise_for_status()
        items = r.json().get("value", [])

        out: List[SyncEvent] = []
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

            out.append(
                SyncEvent(
                    provider=SOURCE_EXCHANGE,
                    provider_id=str(it.get("id", "")),
                    title=str(it.get("subject", "") or "(ohne Betreff)"),
                    start=start_n,
                    end=end_n,
                    description=((it.get("body") or {}).get("content") or ""),
                    location=((it.get("location") or {}).get("displayName") or ""),
                    recurrence=rec,
                    sync_id=meta.get("sync_id") or None,
                    source=meta.get("source") or None,
                    mode=meta.get("mode") or None,
                    modified_at=parse_any_datetime(it.get("lastModifiedDateTime")),
                    raw=it,
                )
            )
        return out

    def _payload_for_event(self, event: SyncEvent, sync_id: str, source: str, mode: str, blocked_title: str) -> Dict[str, Any]:
        title = blocked_title if mode == MODE_BLOCKED else event.title
        desc = "" if mode == MODE_BLOCKED else event.description
        location = "" if mode == MODE_BLOCKED else event.location

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
            if dry_run:
                log.action("exchange", "created", sync_id, "dry-run")
                return f"dry-{uuid.uuid4()}"
            r = requests.post(
                f"https://graph.microsoft.com/v1.0/users/{self.cfg.exchange_user}/events",
                headers=self._headers(),
                data=json.dumps(payload),
                timeout=self.cfg.timeout_sec,
            )
            r.raise_for_status()
            out = r.json()
            log.action("exchange", "created", sync_id)
            return str(out.get("id"))

        desired_fp = desired.fingerprint(mode, blocked_title)
        existing_fp = existing.fingerprint(mode, blocked_title)
        if desired_fp == existing_fp and existing.source == source and existing.mode == mode:
            log.action("exchange", "skipped", sync_id, "no-change")
            return existing.provider_id

        if dry_run:
            log.action("exchange", "updated", sync_id, "dry-run")
            return existing.provider_id

        r = requests.patch(
            f"https://graph.microsoft.com/v1.0/users/{self.cfg.exchange_user}/events/{existing.provider_id}",
            headers=self._headers(),
            data=json.dumps(payload),
            timeout=self.cfg.timeout_sec,
        )
        r.raise_for_status()
        log.action("exchange", "updated", sync_id)
        return existing.provider_id


class ICloudClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._base: Optional[str] = None
        self._cal_href: Optional[str] = None

    def _auth(self) -> HTTPBasicAuth:
        return HTTPBasicAuth(self.cfg.icloud_user, self.cfg.icloud_app_pw)

    def discover(self) -> Tuple[str, str]:
        if self._base and self._cal_href:
            return self._base, self._cal_href

        auth = self._auth()
        body = '''<?xml version="1.0" encoding="UTF-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><C:calendar-home-set/></D:prop></D:propfind>'''
        r = requests.request(
            "PROPFIND",
            "https://caldav.icloud.com" + self.cfg.icloud_principal_path,
            headers={"Depth": "0", "Content-Type": "application/xml; charset=utf-8"},
            data=body,
            auth=auth,
            timeout=self.cfg.timeout_sec,
        )
        r.raise_for_status()
        m = re.search(r"<calendar-home-set[^>]*>\s*<href[^>]*>([^<]+)</href>", r.text)
        if not m:
            raise RuntimeError("iCloud calendar-home-set not found")
        home = m.group(1)

        body2 = '''<?xml version="1.0" encoding="UTF-8"?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:displayname/></D:prop></D:propfind>'''
        r2 = requests.request(
            "PROPFIND",
            home,
            headers={"Depth": "1", "Content-Type": "application/xml; charset=utf-8"},
            data=body2,
            auth=auth,
            timeout=self.cfg.timeout_sec,
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

        host_match = re.match(r"https://([^/]+)/", home)
        host = host_match.group(1) if host_match else "caldav.icloud.com"
        base = f"https://{host}"
        self._base, self._cal_href = base, cal_href
        return base, cal_href

    def list_events(self, start: datetime, end: datetime, log: Logger) -> List[SyncEvent]:
        base, cal_href = self.discover()
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
        r = requests.request(
            "REPORT",
            base + cal_href,
            headers={"Depth": "1", "Content-Type": "application/xml; charset=utf-8"},
            data=body,
            auth=auth,
            timeout=self.cfg.timeout_sec,
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
                    title=ics_unescape(parse_ics_value(lines, "SUMMARY") or "(ohne Betreff)"),
                    start=start_n,
                    end=end_n,
                    description=ics_unescape(parse_ics_value(lines, "DESCRIPTION") or ""),
                    location=ics_unescape(parse_ics_value(lines, "LOCATION") or ""),
                    recurrence=rec,
                    sync_id=parse_ics_value(lines, ICLOUD_META_SYNC_ID) or None,
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
        title = blocked_title if mode == MODE_BLOCKED else event.title
        description = "" if mode == MODE_BLOCKED else event.description
        location = "" if mode == MODE_BLOCKED else event.location

        start_params, start_value = normalized_to_ics(event.start)
        end_params, end_value = normalized_to_ics(event.end, end=True)

        lines = [
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//Aether//OpenClaw//DE",
            "BEGIN:VEVENT",
            f"UID:{uid}",
            f"DTSTAMP:{now_utc().strftime('%Y%m%dT%H%M%SZ')}",
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
        base, cal_href = self.discover()
        auth = self._auth()

        desired_fp = desired.fingerprint(mode, blocked_title)
        if existing and desired_fp == existing.fingerprint(mode, blocked_title) and existing.source == source and existing.mode == mode:
            log.action("icloud", "skipped", sync_id, "no-change")
            return existing.provider_id

        uid = existing.uid if existing and existing.uid else str(uuid.uuid4())
        href = existing.href if existing and existing.href else cal_href + uid + ".ics"
        ics = self._build_ics(desired, sync_id, source, mode, blocked_title, uid)

        if dry_run:
            action = "updated" if existing else "created"
            log.action("icloud", action, sync_id, "dry-run")
            return href

        r = requests.put(
            base + href,
            data=ics.encode("utf-8"),
            headers={"Content-Type": "text/calendar; charset=utf-8"},
            auth=auth,
            timeout=self.cfg.timeout_sec,
        )
        r.raise_for_status()
        action = "updated" if existing else "created"
        log.action("icloud", action, sync_id)
        return href


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
        params = {
            "timeMin": iso_z(start),
            "timeMax": iso_z(end),
            "singleEvents": "true",
            "showDeleted": "false",
            "maxResults": 2500,
        }
        r = requests.get(url, headers=self._headers(), params=params, timeout=self.cfg.timeout_sec)
        r.raise_for_status()
        items = r.json().get("items", [])

        out: List[SyncEvent] = []
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
                    title=str(it.get("summary", "") or "(ohne Betreff)"),
                    start=start_n,
                    end=end_n,
                    description=str(it.get("description", "") or ""),
                    location=str(it.get("location", "") or ""),
                    recurrence=list(it.get("recurrence", []) or []),
                    sync_id=meta.get("sync_id") or None,
                    source=meta.get("source") or None,
                    mode=meta.get("mode") or None,
                    modified_at=parse_any_datetime(it.get("updated")),
                    raw=it,
                )
            )
        return out

    def _payload_for_event(self, event: SyncEvent, sync_id: str, source: str, mode: str, blocked_title: str) -> Dict[str, Any]:
        title = blocked_title if mode == MODE_BLOCKED else event.title
        description = "" if mode == MODE_BLOCKED else event.description
        location = "" if mode == MODE_BLOCKED else event.location

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
            if desired_fp == existing_fp and existing.source == source and existing.mode == mode:
                log.action("google", "skipped", sync_id, "no-change")
                return existing.provider_id

        if dry_run:
            action = "updated" if existing else "created"
            log.action("google", action, sync_id, "dry-run")
            return existing.provider_id if existing else f"dry-{uuid.uuid4()}"

        if existing:
            url = f"https://www.googleapis.com/calendar/v3/calendars/{self.cfg.google_calendar_id}/events/{existing.provider_id}"
            r = requests.patch(url, headers=self._headers(), data=json.dumps(payload), timeout=self.cfg.timeout_sec)
            r.raise_for_status()
            log.action("google", "updated", sync_id)
            return existing.provider_id

        url = f"https://www.googleapis.com/calendar/v3/calendars/{self.cfg.google_calendar_id}/events"
        r = requests.post(url, headers=self._headers(), data=json.dumps(payload), timeout=self.cfg.timeout_sec)
        r.raise_for_status()
        out = r.json()
        log.action("google", "created", sync_id)
        return str(out.get("id"))


def event_modified_or_fallback(event: SyncEvent) -> datetime:
    return event.modified_at or normalized_start_to_dt(event.start)


def event_time_signature(event: SyncEvent) -> str:
    return json.dumps({"start": event.start, "end": event.end}, sort_keys=True, ensure_ascii=False)


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

    # normalize sync ids
    for provider, events in by_provider.items():
        for ev in events:
            if not ev.sync_id:
                st_sync = state.get_sync_id(provider, ev.provider_id)
                if st_sync:
                    ev.sync_id = st_sync
            if not ev.sync_id:
                ev.sync_id = stable_sync_id(provider, ev.provider_id)
            state.set_mapping(provider, ev.provider_id, ev.sync_id)

    indices_sync = {p: index_by_sync(events) for p, events in by_provider.items()}
    indices_id = {p: index_by_id(events) for p, events in by_provider.items()}

    all_sync_ids = sorted({ev.sync_id for events in by_provider.values() for ev in events if ev.sync_id})

    for sync_id in all_sync_ids:
        group = [ev for p in enabled_providers for ev in by_provider[p] if ev.sync_id == sync_id]
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
            existing = indices_sync[provider].get(sync_id)
            if not existing:
                known_id = state.get_provider_id(provider, sync_id)
                if known_id:
                    existing = indices_id[provider].get(known_id)

            if provider == SOURCE_EXCHANGE:
                provider_id = exchange.upsert_event(
                    existing=existing,
                    desired=merged,
                    sync_id=sync_id,
                    source=authoritative_source,
                    mode=mode,
                    blocked_title=cfg.google_blocked_title,
                    dry_run=dry_run,
                    log=log,
                )
            elif provider == SOURCE_ICLOUD:
                provider_id = icloud.upsert_event(
                    existing=existing,
                    desired=merged,
                    sync_id=sync_id,
                    source=authoritative_source,
                    mode=mode,
                    blocked_title=cfg.google_blocked_title,
                    dry_run=dry_run,
                    log=log,
                )
            elif provider == SOURCE_GOOGLE and google:
                provider_id = google.upsert_event(
                    existing=existing,
                    desired=merged,
                    sync_id=sync_id,
                    source=authoritative_source,
                    mode=mode,
                    blocked_title=cfg.google_blocked_title,
                    dry_run=dry_run,
                    log=log,
                )
            else:
                continue

            state.set_mapping(provider, provider_id, sync_id)

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
