from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import struct
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Optional
from urllib.parse import quote

try:
    from argon2 import PasswordHasher as Argon2PasswordHasher
    from argon2.exceptions import InvalidHashError, VerifyMismatchError, VerificationError

    ARGON2_AVAILABLE = True
except ModuleNotFoundError:
    Argon2PasswordHasher = None
    InvalidHashError = ValueError
    VerifyMismatchError = ValueError
    VerificationError = ValueError
    ARGON2_AVAILABLE = False

try:
    from cryptography.fernet import Fernet, InvalidToken

    CRYPTOGRAPHY_AVAILABLE = True
except ModuleNotFoundError:
    Fernet = None
    InvalidToken = ValueError
    CRYPTOGRAPHY_AVAILABLE = False


def now_utc() -> datetime:
    return datetime.now(UTC)


def iso_z(dt: datetime) -> str:
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    value = raw.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class SessionData:
    user_id: int
    session_id: str
    expires_at: datetime


@dataclass(frozen=True)
class PendingLoginData:
    user_id: int
    challenge_id: str
    expires_at: datetime


def validate_password_policy(password: str) -> Optional[str]:
    if len(password) < 15:
        return "Passwoerter muessen mindestens 15 Zeichen lang sein."
    if len(password) > 1024:
        return "Passwoerter duerfen hoechstens 1024 Zeichen lang sein."
    return None


class PasswordHasher:
    legacy_algorithm = "pbkdf2_sha256"
    legacy_iterations = 210_000

    def __init__(self) -> None:
        self.argon2 = (
            Argon2PasswordHasher(time_cost=3, memory_cost=19_456, parallelism=1, hash_len=32, salt_len=16)
            if ARGON2_AVAILABLE
            else None
        )

    def hash_password(self, password: str) -> str:
        if self.argon2:
            return self.argon2.hash(password)
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            self.legacy_iterations,
        ).hex()
        return f"{self.legacy_algorithm}${self.legacy_iterations}${salt}${digest}"

    def verify_password(self, password: str, encoded: str) -> bool:
        if encoded.startswith("$argon2"):
            if not self.argon2:
                return False
            try:
                return bool(self.argon2.verify(encoded, password))
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                return False
        return self._verify_legacy_pbkdf2(password, encoded)

    def needs_rehash(self, encoded: str) -> bool:
        if encoded.startswith("$argon2"):
            if not self.argon2:
                return False
            try:
                return bool(self.argon2.check_needs_rehash(encoded))
            except (VerificationError, InvalidHashError):
                return True
        return True

    def _verify_legacy_pbkdf2(self, password: str, encoded: str) -> bool:
        try:
            _algorithm, raw_iterations, salt, expected_digest = encoded.split("$", 3)
        except ValueError:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            int(raw_iterations),
        ).hex()
        return hmac.compare_digest(digest, expected_digest)


class SessionManager:
    def __init__(self, secret_key: str, ttl_hours: int):
        self.secret_key = secret_key.encode("utf-8")
        self.ttl = timedelta(hours=ttl_hours)

    def _sign(self, payload: str) -> str:
        return hmac.new(self.secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def create(self, user_id: int) -> str:
        expires_at = iso_z(now_utc() + self.ttl)
        session_id = secrets.token_urlsafe(18)
        payload = f"{user_id}|{session_id}|{expires_at}"
        signature = self._sign(payload)
        return f"{payload}|{signature}"

    def parse(self, token: Optional[str]) -> Optional[SessionData]:
        if not token:
            return None

        parts = token.split("|")
        if len(parts) == 4:
            user_id_raw, session_id, expires_at_raw, signature = parts
            payload = f"{user_id_raw}|{session_id}|{expires_at_raw}"
        elif len(parts) == 3:
            user_id_raw, expires_at_raw, signature = parts
            session_id = ""
            payload = f"{user_id_raw}|{expires_at_raw}"
        else:
            return None

        if not hmac.compare_digest(signature, self._sign(payload)):
            return None
        expires_at = parse_utc(expires_at_raw)
        if not expires_at or expires_at < now_utc():
            return None
        try:
            user_id = int(user_id_raw)
        except ValueError:
            return None
        return SessionData(user_id=user_id, session_id=session_id, expires_at=expires_at)


class PendingLoginManager:
    def __init__(self, secret_key: str, ttl_minutes: int = 10):
        self.secret_key = secret_key.encode("utf-8")
        self.ttl = timedelta(minutes=ttl_minutes)
        self.purpose = "pending-2fa"

    def _sign(self, payload: str) -> str:
        return hmac.new(self.secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def create(self, user_id: int) -> str:
        expires_at = iso_z(now_utc() + self.ttl)
        challenge_id = secrets.token_urlsafe(18)
        payload = f"{self.purpose}|{user_id}|{challenge_id}|{expires_at}"
        signature = self._sign(payload)
        return f"{payload}|{signature}"

    def parse(self, token: Optional[str]) -> Optional[PendingLoginData]:
        if not token:
            return None
        try:
            purpose, user_id_raw, challenge_id, expires_at_raw, signature = token.split("|", 4)
        except ValueError:
            return None
        if purpose != self.purpose:
            return None
        payload = f"{purpose}|{user_id_raw}|{challenge_id}|{expires_at_raw}"
        if not hmac.compare_digest(signature, self._sign(payload)):
            return None
        expires_at = parse_utc(expires_at_raw)
        if not expires_at or expires_at < now_utc():
            return None
        try:
            user_id = int(user_id_raw)
        except ValueError:
            return None
        return PendingLoginData(user_id=user_id, challenge_id=challenge_id, expires_at=expires_at)


class CsrfManager:
    def __init__(self, secret_key: str, ttl_hours: int):
        self.secret_key = secret_key.encode("utf-8")
        self.ttl = timedelta(hours=ttl_hours)

    def _sign(self, payload: str) -> str:
        return hmac.new(self.secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def create(self) -> str:
        token_id = secrets.token_urlsafe(24)
        expires_at = iso_z(now_utc() + self.ttl)
        payload = f"{token_id}|{expires_at}"
        signature = self._sign(payload)
        return f"{payload}|{signature}"

    def parse(self, token: Optional[str]) -> bool:
        if not token:
            return False
        try:
            token_id, expires_at_raw, signature = token.split("|", 2)
        except ValueError:
            return False
        payload = f"{token_id}|{expires_at_raw}"
        if not hmac.compare_digest(signature, self._sign(payload)):
            return False
        expires_at = parse_utc(expires_at_raw)
        return bool(token_id and expires_at and expires_at >= now_utc())

    def issue(self, existing_token: Optional[str]) -> str:
        if self.parse(existing_token):
            return str(existing_token)
        return self.create()

    def validate(self, cookie_token: Optional[str], submitted_token: Optional[str]) -> bool:
        return bool(cookie_token and submitted_token and cookie_token == submitted_token and self.parse(cookie_token))


class SecretBox:
    prefix = "enc:"

    def __init__(self, key: str):
        if not key:
            raise ValueError("missing data encryption key")
        if not CRYPTOGRAPHY_AVAILABLE or Fernet is None:
            raise RuntimeError("cryptography package is required for encrypted provider settings")
        self.fernet = Fernet(key.encode("utf-8"))

    def encrypt_mapping(self, data: Dict[str, Any]) -> str:
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return self.prefix + self.fernet.encrypt(payload).decode("utf-8")

    def encrypt_text(self, value: str) -> str:
        if not value:
            return ""
        return self.prefix + self.fernet.encrypt(value.encode("utf-8")).decode("utf-8")

    def decrypt_mapping(self, raw: str) -> Dict[str, Any]:
        value = (raw or "").strip()
        if not value:
            return {}
        if not value.startswith(self.prefix):
            decoded = json.loads(value)
            return decoded if isinstance(decoded, dict) else {}
        try:
            decrypted = self.fernet.decrypt(value[len(self.prefix) :].encode("utf-8")).decode("utf-8")
        except (InvalidToken, ValueError) as exc:
            raise RuntimeError("unable to decrypt provider settings; check CAL_WEBAPP_DATA_KEY") from exc
        decoded = json.loads(decrypted)
        if not isinstance(decoded, dict):
            raise RuntimeError("decrypted provider settings payload is invalid")
        return decoded

    def decrypt_text(self, raw: str) -> str:
        value = (raw or "").strip()
        if not value:
            return ""
        if not value.startswith(self.prefix):
            return value
        try:
            return self.fernet.decrypt(value[len(self.prefix) :].encode("utf-8")).decode("utf-8")
        except (InvalidToken, ValueError) as exc:
            raise RuntimeError("unable to decrypt secure user settings; check CAL_WEBAPP_DATA_KEY") from exc

    def is_encrypted(self, raw: str) -> bool:
        return (raw or "").startswith(self.prefix)


class TotpManager:
    def __init__(self, *, digits: int = 6, period_seconds: int = 30):
        self.digits = digits
        self.period_seconds = period_seconds

    def generate_secret(self) -> str:
        return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")

    def provisioning_uri(self, secret: str, account_name: str, issuer: str) -> str:
        label = quote(f"{issuer}:{account_name}")
        return (
            f"otpauth://totp/{label}"
            f"?secret={quote(secret)}&issuer={quote(issuer)}&digits={self.digits}&period={self.period_seconds}"
        )

    def generate_code(self, secret: str, at_time: Optional[datetime] = None) -> str:
        key = self._decode_secret(secret)
        counter_value = int((at_time or now_utc()).timestamp()) // self.period_seconds
        counter_bytes = struct.pack(">Q", counter_value)
        digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        binary = (
            ((digest[offset] & 0x7F) << 24)
            | ((digest[offset + 1] & 0xFF) << 16)
            | ((digest[offset + 2] & 0xFF) << 8)
            | (digest[offset + 3] & 0xFF)
        )
        return str(binary % (10**self.digits)).zfill(self.digits)

    def verify_code(self, secret: str, code: str, at_time: Optional[datetime] = None, window: int = 1) -> bool:
        normalized_code = "".join(char for char in code if char.isdigit())
        if len(normalized_code) != self.digits:
            return False
        current_time = at_time or now_utc()
        for offset in range(-window, window + 1):
            candidate_time = current_time + timedelta(seconds=offset * self.period_seconds)
            try:
                candidate = self.generate_code(secret, at_time=candidate_time)
            except (ValueError, binascii.Error):
                return False
            if hmac.compare_digest(candidate, normalized_code):
                return True
        return False

    def _decode_secret(self, secret: str) -> bytes:
        normalized = "".join(str(secret).strip().upper().split())
        if not normalized:
            raise ValueError("missing totp secret")
        padding = "=" * ((8 - len(normalized) % 8) % 8)
        return base64.b32decode(normalized + padding, casefold=True)


def mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 6:
        return "***"
    return value[:3] + "***" + value[-2:]
