import hashlib
import hmac
import os
import sqlite3
from unittest.mock import MagicMock

import pytest
from telebot.types import Chat, Message, User

import handlers
from utils import SECRET_KEY, cipher

# Use a temporary local file instead of :memory: to persist data between connections
TEST_DB_PATH = "test_passwords.sqlite3"
os.environ["SECRET_KEY"] = "test_super_secret_key_1234567890"
os.environ["DB_PATH"] = TEST_DB_PATH

from utils import DB_PATH, escape_md, get_suffix, init_db, set_shared_status


@pytest.fixture(autouse=True)
def setup_database():
    """
    Pytest fixture executed automatically before each test.
    Initializes the DB and completely removes the file during teardown.
    """
    init_db()
    yield
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


def test_escape_md():
    """Test the pure utility function for MarkdownV2 escaping."""
    assert escape_md("Hello_World*") == "Hello\\_World\\*"
    assert escape_md("user.name!") == "user\\.name\\!"

    assert escape_md("code`block\\", in_code_block=True) == "code\\`block\\\\"
    assert escape_md("no_escape_here*", in_code_block=True) == "no_escape_here*"


def test_get_suffix_behavior():
    """Test cryptographic logic for password generation."""
    site = "github"
    user_id = 12345

    suffix_base = get_suffix(site, user_id, "1")

    # Determinism: same input yields identical hash
    assert get_suffix(site, user_id, "1") == suffix_base

    # Iteration isolation: changing iteration changes the suffix entirely
    assert get_suffix(site, user_id, "2") != suffix_base

    # Case normalization: uppercase letters should not alter the result
    assert get_suffix("GITHUB", user_id, "1") == suffix_base
    assert get_suffix("GitHub", user_id, "1") == suffix_base


def test_set_shared_status_integration():
    """Integration test: logic interaction with the SQLite database."""
    site_hash = "fake_hash_123"
    user_id = 999

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO passwords_v2 (site_hash, site_encrypted, user_id, iteration, username) 
            VALUES (?, ?, ?, ?, ?)
            """,
            (site_hash, "encrypted_dummy", user_id, "1", "test_user"),
        )

    affected_rows = set_shared_status(site_hash, user_id, 1)
    assert affected_rows == 1

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT is_shared FROM passwords_v2 WHERE site_hash = ? AND user_id = ?",
            (site_hash, user_id),
        )
        is_shared = cursor.fetchone()[0]

    assert is_shared == 1

    set_shared_status(site_hash, user_id, 0)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT is_shared FROM passwords_v2 WHERE site_hash = ?", (site_hash,)
        )
        assert cursor.fetchone()[0] == 0


def test_fernet_encryption_roundtrip():
    """Ensure site encryption is reversible and decrypts to original value."""
    original_site = "bank-service-login"
    encrypted = cipher.encrypt(original_site.encode("utf-8")).decode("utf-8")

    assert encrypted != original_site
    decrypted = cipher.decrypt(encrypted.encode("utf-8")).decode("utf-8")
    assert decrypted == original_site


def test_unauthorized_user_access_denied(monkeypatch):
    """Ensure handlers exit early for users not in ALLOWED_USER_IDS."""
    mock_reply = MagicMock()
    monkeypatch.setattr("handlers.bot.reply_to", mock_reply)
    monkeypatch.setattr("handlers.ALLOWED_USER_IDS", [111, 222])

    message = MagicMock()
    message.from_user.id = 999
    message.text = "/list"

    handlers.handle_list(message)

    # Bot should ignore the request and never call reply_to
    mock_reply.assert_not_called()


def test_callback_next_action(monkeypatch):
    mock_bot = MagicMock()
    monkeypatch.setattr("handlers.bot", mock_bot)
    monkeypatch.setattr("handlers.ALLOWED_USER_IDS", [999])

    site = "cb_test_next"
    site_hash = hmac.new(
        SECRET_KEY.encode("utf-8"), site.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO passwords_v2 (site_hash, site_encrypted, user_id, iteration, username) 
            VALUES (?, ?, ?, ?, ?)
            """,
            (site_hash, "enc", 999, "1", "test_user"),
        )

    call = MagicMock()
    call.data = f"next:{site}"
    call.from_user.id = 999
    call.message.chat.id = 111
    call.message.message_id = 222
    call.id = "cb_1"

    handlers.handle_callbacks(call)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT iteration FROM passwords_v2 WHERE site_hash = ?", (site_hash,)
        )
        assert cursor.fetchone()[0] == "2"

    mock_bot.edit_message_text.assert_called_once()
    mock_bot.answer_callback_query.assert_called_once()


def test_callback_del_action(monkeypatch):
    mock_bot = MagicMock()
    monkeypatch.setattr("handlers.bot", mock_bot)
    monkeypatch.setattr("handlers.ALLOWED_USER_IDS", [999])

    site = "cb_test_del"
    site_hash = hmac.new(
        SECRET_KEY.encode("utf-8"), site.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO passwords_v2 (site_hash, site_encrypted, user_id, iteration, username) 
            VALUES (?, ?, ?, ?, ?)
            """,
            (site_hash, "enc", 999, "1", "test_user"),
        )

    call = MagicMock()
    call.data = f"del:{site}"
    call.from_user.id = 999
    call.message.chat.id = 111
    call.message.message_id = 222
    call.id = "cb_2"

    handlers.handle_callbacks(call)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT * FROM passwords_v2 WHERE site_hash = ?", (site_hash,)
        )
        assert cursor.fetchone() is None

    mock_bot.delete_message.assert_called_once_with(111, 222)
    mock_bot.answer_callback_query.assert_called_once()


def test_callback_share_action(monkeypatch):
    mock_bot = MagicMock()
    monkeypatch.setattr("handlers.bot", mock_bot)
    monkeypatch.setattr("handlers.ALLOWED_USER_IDS", [999])

    site = "cb_test_share"
    site_hash = hmac.new(
        SECRET_KEY.encode("utf-8"), site.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO passwords_v2 (site_hash, site_encrypted, user_id, iteration, username, is_shared) 
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (site_hash, "enc", 999, "1", "test_user", 0),
        )

    call = MagicMock()
    call.data = f"share:{site}"
    call.from_user.id = 999
    call.message.chat.id = 111
    call.message.message_id = 222
    call.id = "cb_3"

    handlers.handle_callbacks(call)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT is_shared FROM passwords_v2 WHERE site_hash = ?", (site_hash,)
        )
        assert cursor.fetchone()[0] == 1

    mock_bot.edit_message_reply_markup.assert_called_once()
    mock_bot.answer_callback_query.assert_called_once()
