"""Server-side opaque OIDC session lifecycle primitives.

The store persists only a digest of each bearer session token. Subjects are encrypted at rest;
raw session tokens are returned only when created and are never written to SQLite. The host web
application remains responsible for secure cookies, CSRF protection, callback routing and UI.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class OidcSessionStoreError(RuntimeError):
    """Session data could not be safely read or changed."""


@dataclass(frozen=True)
class OidcSession:
    token: str = field(repr=False)
    subject: str
    created_at: float
    expires_at: float


class SQLiteOidcSessionStore:
    """Persistent opaque sessions with expiry, single-session logout and subject-wide revocation.

    Supply a dedicated database path and a stable, operator-managed 32-byte key from a secret
    manager. Key loss/rotation invalidates all sessions. Protect the database directory, WAL files
    and backups. This is a server-side session store, not a cookie or HTTP middleware.
    """

    _MAX_SESSIONS = 100_000
    _MAX_SUBJECT_LENGTH = 512
    _MAX_TTL_SECONDS = 30 * 24 * 60 * 60

    def __init__(self, database_path: str | os.PathLike[str], encryption_key: bytes) -> None:
        if not isinstance(encryption_key, bytes) or len(encryption_key) != 32:
            raise ValueError("encryption_key must be exactly 32 bytes (AES-256)")
        if str(database_path) == ":memory:":
            raise ValueError("session storage requires a durable SQLite file path")
        path = Path(database_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = str(path)
        self._cipher = AESGCM(encryption_key)
        self._subject_index_key = hmac.new(
            encryption_key, b"ARTA-OIDC-session-subject-index-v1", hashlib.sha256
        ).digest()
        self._lock = threading.RLock()
        with closing(self._connect()) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS oidc_sessions (
                token_hash BLOB PRIMARY KEY,
                subject_digest BLOB NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                revoked_at REAL,
                subject_nonce BLOB NOT NULL,
                subject_ciphertext BLOB NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS oidc_sessions_subject ON oidc_sessions(subject_digest, revoked_at)")
            db.execute("CREATE INDEX IF NOT EXISTS oidc_sessions_expiry ON oidc_sessions(expires_at)")
        if os.name == "posix":
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _subject_digest(self, subject: str) -> bytes:
        return hmac.new(self._subject_index_key, subject.encode("utf-8"), hashlib.sha256).digest()

    @staticmethod
    def _token_hash(token: str) -> bytes:
        return hashlib.sha256(token.encode("ascii")).digest()

    def create_session(self, subject: str, *, ttl_seconds: int = 3600) -> OidcSession:
        if (not isinstance(subject, str) or not subject or subject != subject.strip()
                or len(subject) > self._MAX_SUBJECT_LENGTH):
            raise ValueError("subject must be a non-empty, trimmed string of at most 512 characters")
        if (isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int)
                or not 60 <= ttl_seconds <= self._MAX_TTL_SECONDS):
            raise ValueError("session TTL must be between 60 seconds and 30 days")
        created_at = time.time()
        expires_at = created_at + ttl_seconds
        token = secrets.token_urlsafe(32)
        token_hash = self._token_hash(token)
        subject_digest = self._subject_digest(subject)
        nonce = secrets.token_bytes(12)
        ciphertext = self._cipher.encrypt(nonce, subject.encode("utf-8"), token_hash)
        with self._lock, closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("DELETE FROM oidc_sessions WHERE expires_at <= ?", (created_at,))
                count = db.execute("SELECT COUNT(*) FROM oidc_sessions WHERE expires_at > ?", (created_at,)).fetchone()[0]
                if count >= self._MAX_SESSIONS:
                    raise OidcSessionStoreError("session capacity reached")
                db.execute("""INSERT INTO oidc_sessions
                    (token_hash, subject_digest, created_at, expires_at, revoked_at, subject_nonce, subject_ciphertext)
                    VALUES (?, ?, ?, ?, NULL, ?, ?)""",
                    (token_hash, subject_digest, created_at, expires_at, nonce, ciphertext))
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        return OidcSession(token, subject, created_at, expires_at)

    def validate_session(self, token: str) -> OidcSession | None:
        if not isinstance(token, str) or not token or len(token) > 256:
            return None
        try:
            token_hash = self._token_hash(token)
        except UnicodeEncodeError:
            return None
        with closing(self._connect()) as db:
            row = db.execute("""SELECT subject_digest, created_at, expires_at, revoked_at,
                subject_nonce, subject_ciphertext FROM oidc_sessions WHERE token_hash = ?""",
                (token_hash,)).fetchone()
        if row is None:
            return None
        subject_digest, created_at, expires_at, revoked_at, nonce, ciphertext = row
        if revoked_at is not None or expires_at <= time.time():
            return None
        try:
            subject = self._cipher.decrypt(nonce, ciphertext, token_hash).decode("utf-8")
        except Exception:
            raise OidcSessionStoreError("session subject failed authenticated decryption") from None
        if not hmac.compare_digest(subject_digest, self._subject_digest(subject)):
            raise OidcSessionStoreError("session subject index does not match encrypted subject")
        return OidcSession(token, subject, float(created_at), float(expires_at))

    def revoke_session(self, token: str) -> bool:
        if not isinstance(token, str) or not token or len(token) > 256:
            return False
        try:
            token_hash = self._token_hash(token)
        except UnicodeEncodeError:
            return False
        now = time.time()
        with self._lock, closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                cursor = db.execute("""UPDATE oidc_sessions SET revoked_at = ?
                    WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?""",
                    (now, token_hash, now))
                db.execute("COMMIT")
                return cursor.rowcount == 1
            except Exception:
                db.execute("ROLLBACK")
                raise

    def revoke_all_sessions(self, subject: str) -> int:
        if (not isinstance(subject, str) or not subject or subject != subject.strip()
                or len(subject) > self._MAX_SUBJECT_LENGTH):
            raise ValueError("subject must be a non-empty, trimmed string of at most 512 characters")
        now = time.time()
        digest = self._subject_digest(subject)
        with self._lock, closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                cursor = db.execute("""UPDATE oidc_sessions SET revoked_at = ?
                    WHERE subject_digest = ? AND revoked_at IS NULL AND expires_at > ?""",
                    (now, digest, now))
                db.execute("COMMIT")
                return cursor.rowcount
            except Exception:
                db.execute("ROLLBACK")
                raise
