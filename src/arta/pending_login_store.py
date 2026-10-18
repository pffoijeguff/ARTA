"""Encrypted, one-use storage for OIDC Authorization Code + PKCE transactions.

The encryption key is operator-managed configuration and must be shared by workers that
need to complete each other's login transactions. This module stores only short-lived
PKCE verifier/nonce material; it is not a browser-session store.
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class PendingLogin:
    verifier: str
    nonce: str
    expires_at: float


class PendingLoginStore(Protocol):
    """Atomic, single-use transaction storage. Times are Unix epoch seconds."""

    def put(self, state: str, verifier: str, nonce: str, expires_at: float) -> None: ...
    def consume(self, state: str, *, now: float | None = None) -> PendingLogin | None: ...


class InMemoryPendingLoginStore:
    """Single-process development store; transactions do not survive restarts."""

    def __init__(self, max_entries: int = 1024) -> None:
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or not 1 <= max_entries <= 100_000:
            raise ValueError("max_entries must be an integer between 1 and 100000")
        self._max_entries = max_entries
        self._items: dict[str, PendingLogin] = {}
        self._lock = threading.RLock()

    def put(self, state: str, verifier: str, nonce: str, expires_at: float) -> None:
        with self._lock:
            now = time.time()
            self._items = {k: v for k, v in self._items.items() if v.expires_at > now}
            if len(self._items) >= self._max_entries:
                raise ValueError("pending login capacity reached")
            if state in self._items:
                raise ValueError("duplicate login state")
            self._items[state] = PendingLogin(verifier, nonce, expires_at)

    def consume(self, state: str, *, now: float | None = None) -> PendingLogin | None:
        with self._lock:
            transaction = self._items.pop(state, None)
            if transaction is None:
                return None
            current = time.time() if now is None else now
            return transaction if transaction.expires_at > current else None


class EncryptedSQLitePendingLoginStore:
    """SQLite-backed, AES-256-GCM encrypted and atomic one-use transaction store.

    Use a dedicated database file with restrictive OS permissions. Keep the exact same
    32-byte key in a secret manager for every worker sharing this database. Losing or
    rotating the key invalidates all pending logins; it does not expose their plaintext.
    """

    _MAX_ENTRIES = 100_000
    _MAX_STATE_LENGTH = 512

    def __init__(self, database_path: str | os.PathLike[str], encryption_key: bytes) -> None:
        if not isinstance(encryption_key, bytes) or len(encryption_key) != 32:
            raise ValueError("encryption_key must be exactly 32 bytes (AES-256)")
        path = Path(database_path)
        if str(database_path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True)
        self._path = str(path)
        self._cipher = AESGCM(encryption_key)
        self._lock = threading.RLock()
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS pending_oidc_login (state TEXT PRIMARY KEY, expires_at REAL NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS pending_oidc_login_expiry ON pending_oidc_login(expires_at)")
        if self._path != ":memory:" and os.name == "posix":
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

    @classmethod
    def _validate_state(cls, state: str) -> None:
        if not isinstance(state, str) or not state or len(state) > cls._MAX_STATE_LENGTH:
            raise ValueError("invalid login state")

    def put(self, state: str, verifier: str, nonce: str, expires_at: float) -> None:
        self._validate_state(state)
        if not isinstance(verifier, str) or not verifier or len(verifier) > 256:
            raise ValueError("invalid PKCE verifier")
        if not isinstance(nonce, str) or not nonce or len(nonce) > 256:
            raise ValueError("invalid OIDC nonce")
        if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)) or expires_at <= time.time():
            raise ValueError("transaction expiry must be in the future")
        payload = json.dumps({"verifier": verifier, "nonce": nonce}, separators=(",", ":")).encode("utf-8")
        iv = secrets.token_bytes(12)
        ciphertext = self._cipher.encrypt(iv, payload, state.encode("utf-8"))
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("DELETE FROM pending_oidc_login WHERE expires_at <= ?", (time.time(),))
                count = db.execute("SELECT COUNT(*) FROM pending_oidc_login").fetchone()[0]
                if count >= self._MAX_ENTRIES:
                    raise ValueError("pending login capacity reached")
                db.execute("INSERT INTO pending_oidc_login(state, expires_at, nonce, ciphertext) VALUES (?, ?, ?, ?)",
                           (state, float(expires_at), iv, ciphertext))
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise

    def consume(self, state: str, *, now: float | None = None) -> PendingLogin | None:
        self._validate_state(state)
        current = time.time() if now is None else now
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT expires_at, nonce, ciphertext FROM pending_oidc_login WHERE state = ?", (state,)).fetchone()
                if row is None:
                    db.execute("COMMIT")
                    return None
                db.execute("DELETE FROM pending_oidc_login WHERE state = ?", (state,))
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
        expires_at, iv, ciphertext = row
        if expires_at <= current:
            return None
        try:
            plaintext = self._cipher.decrypt(iv, ciphertext, state.encode("utf-8"))
            payload = json.loads(plaintext.decode("utf-8"))
            verifier, nonce = payload["verifier"], payload["nonce"]
            if not isinstance(verifier, str) or not isinstance(nonce, str):
                raise ValueError("invalid encrypted transaction payload")
        except Exception:
            # State is already consumed. Fail closed on wrong keys, corruption or tampering.
            raise ValueError("pending login transaction failed authenticated decryption") from None
        return PendingLogin(verifier, nonce, float(expires_at))
