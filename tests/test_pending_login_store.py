from __future__ import annotations

import sqlite3
import time

import pytest

from arta.pending_login_store import EncryptedSQLitePendingLoginStore


KEY = b"\x11" * 32
STATE = "opaque-state-value"
VERIFIER = "pkce-verifier-that-must-not-be-plaintext"
NONCE = "oidc-nonce-that-must-not-be-plaintext"
BINDING_HASH = "a" * 64


def test_encrypted_store_is_shared_and_consumes_state_exactly_once(tmp_path):
    path = tmp_path / "oidc-transactions.sqlite3"
    writer = EncryptedSQLitePendingLoginStore(path, KEY)
    reader = EncryptedSQLitePendingLoginStore(path, KEY)
    writer.put(STATE, VERIFIER, NONCE, time.time() + 60, BINDING_HASH)

    # A callback from another browser must not consume the legitimate transaction.
    assert reader.consume(STATE, browser_binding_hash="b" * 64) is None
    result = reader.consume(STATE, browser_binding_hash=BINDING_HASH)
    assert result is not None
    assert result.verifier == VERIFIER
    assert result.nonce == NONCE
    assert writer.consume(STATE, browser_binding_hash=BINDING_HASH) is None


def test_encrypted_store_rejects_wrong_key_and_consumes_corrupt_transaction(tmp_path):
    path = tmp_path / "oidc-transactions.sqlite3"
    EncryptedSQLitePendingLoginStore(path, KEY).put(STATE, VERIFIER, NONCE, time.time() + 60, BINDING_HASH)
    wrong_key_store = EncryptedSQLitePendingLoginStore(path, b"\x22" * 32)

    with pytest.raises(ValueError, match="authenticated decryption"):
        wrong_key_store.consume(STATE, browser_binding_hash=BINDING_HASH)
    assert EncryptedSQLitePendingLoginStore(path, KEY).consume(STATE, browser_binding_hash=BINDING_HASH) is None


def test_encrypted_store_expired_transaction_cannot_be_consumed(tmp_path):
    path = tmp_path / "oidc-transactions.sqlite3"
    store = EncryptedSQLitePendingLoginStore(path, KEY)
    store.put(STATE, VERIFIER, NONCE, time.time() + 60, BINDING_HASH)

    assert store.consume(STATE, browser_binding_hash=BINDING_HASH, now=time.time() + 120) is None
    assert store.consume(STATE, browser_binding_hash=BINDING_HASH) is None


def test_encrypted_store_rejects_invalid_key_and_ephemeral_database(tmp_path):
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        EncryptedSQLitePendingLoginStore(tmp_path / "invalid.sqlite3", b"short")
    with pytest.raises(ValueError, match="durable SQLite file"):
        EncryptedSQLitePendingLoginStore(":memory:", KEY)


def test_encrypted_store_persists_ciphertext_not_plaintext(tmp_path):
    path = tmp_path / "oidc-transactions.sqlite3"
    store = EncryptedSQLitePendingLoginStore(path, KEY)
    store.put(STATE, VERIFIER, NONCE, time.time() + 60, BINDING_HASH)
    with sqlite3.connect(path) as db:
        row = db.execute("SELECT ciphertext FROM pending_oidc_login WHERE state = ?", (STATE,)).fetchone()
    assert row is not None
    assert VERIFIER.encode() not in row[0]
    assert NONCE.encode() not in row[0]
