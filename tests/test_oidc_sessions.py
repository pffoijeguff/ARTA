from __future__ import annotations

import sqlite3
import time

import pytest

from arta.oidc_sessions import OidcSessionStoreError, SQLiteOidcSessionStore


KEY = b"\x44" * 32


def test_session_token_is_opaque_persistent_and_subject_is_encrypted(tmp_path):
    path = tmp_path / "sessions.sqlite3"
    store = SQLiteOidcSessionStore(path, KEY)
    session = store.create_session("provider-subject-123")

    assert store.validate_session(session.token).subject == "provider-subject-123"
    with sqlite3.connect(path) as db:
        row = db.execute(
            "SELECT token_hash, subject_ciphertext FROM oidc_sessions"
        ).fetchone()
    assert row is not None
    assert session.token.encode() not in row[0]
    assert b"provider-subject-123" not in row[1]
    assert session.token not in repr(session)


def test_session_revoke_is_immediate_and_single_use(tmp_path):
    store = SQLiteOidcSessionStore(tmp_path / "sessions.sqlite3", KEY)
    session = store.create_session("subject-a")

    assert store.validate_session(session.token) is not None
    assert store.revoke_session(session.token) is True
    assert store.validate_session(session.token) is None
    assert store.revoke_session(session.token) is False


def test_revoke_all_sessions_only_affects_the_selected_subject(tmp_path):
    store = SQLiteOidcSessionStore(tmp_path / "sessions.sqlite3", KEY)
    first = store.create_session("subject-a")
    second = store.create_session("subject-a")
    other = store.create_session("subject-b")

    assert store.revoke_all_sessions("subject-a") == 2
    assert store.validate_session(first.token) is None
    assert store.validate_session(second.token) is None
    assert store.validate_session(other.token) is not None


def test_session_expiry_and_unknown_token_fail_closed(tmp_path):
    path = tmp_path / "sessions.sqlite3"
    store = SQLiteOidcSessionStore(path, KEY)
    session = store.create_session("subject-a")
    with sqlite3.connect(path) as db:
        db.execute("UPDATE oidc_sessions SET expires_at = ? WHERE token_hash = ?",
                   (time.time() - 1, store._token_hash(session.token)))
        db.commit()

    assert store.validate_session(session.token) is None
    assert store.validate_session("not-a-session-token") is None


def test_session_store_rejects_bad_key_ttl_and_subject(tmp_path):
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        SQLiteOidcSessionStore(tmp_path / "bad.sqlite3", b"short")
    store = SQLiteOidcSessionStore(tmp_path / "sessions.sqlite3", KEY)
    with pytest.raises(ValueError, match="TTL"):
        store.create_session("subject-a", ttl_seconds=30)
    with pytest.raises(ValueError, match="subject"):
        store.create_session(" subject-a")
    with pytest.raises(ValueError, match="durable SQLite"):
        SQLiteOidcSessionStore(":memory:", KEY)


def test_session_store_fails_closed_on_wrong_key(tmp_path):
    path = tmp_path / "sessions.sqlite3"
    session = SQLiteOidcSessionStore(path, KEY).create_session("subject-a")
    wrong_store = SQLiteOidcSessionStore(path, b"\x55" * 32)

    with pytest.raises(OidcSessionStoreError, match="authenticated decryption"):
        wrong_store.validate_session(session.token)
