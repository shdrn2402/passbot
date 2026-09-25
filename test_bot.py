import os
import sqlite3
from unittest.mock import MagicMock

import pytest
from telebot.types import CallbackQuery, Message, User

# Set env vars before importing internal modules to prevent init errors
TEST_DB_PATH = "test_passwords.sqlite3"
os.environ["SECRET_KEY"] = "test_super_secret_key_1234567890"
os.environ["DB_PATH"] = TEST_DB_PATH
os.environ["TELEGRAM_TOKEN"] = "123456:dummy_test_token"

import handlers
from config import AuthMiddleware
from utils import (
    DB_PATH,
    cipher,
    escape_md,
    get_site_hash,
    get_suffix,
    init_db,
    set_shared_status,
)


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
    site_hash = get_site_hash("fake_site")
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


def test_auth_middleware_blocks_unauthorized(monkeypatch):
    """Ensure AuthMiddleware intercepts and cancels updates for unauthorized users."""
    monkeypatch.setattr("config.ALLOWED_USER_IDS", [111, 222])
    middleware = AuthMiddleware()

    message = MagicMock()

    # Test unauthorized
    message.from_user.id = 999
    result = middleware.pre_process(message, {})
    assert result is not None
    assert type(result).__name__ == "CancelUpdate"

    # Test authorized
    message.from_user.id = 111
    result = middleware.pre_process(message, {})
    assert result is None


def test_list_pagination(monkeypatch):
    """Ensure /list breaks output into multiple messages if rows exceed chunk size."""
    mock_bot = MagicMock()
    monkeypatch.setattr("handlers.bot", mock_bot)

    req_user_id = 999

    with sqlite3.connect(DB_PATH) as conn:
        for i in range(50):
            site = f"site_{i:02d}"
            site_hash = get_site_hash(site)
            site_enc = cipher.encrypt(site.encode("utf-8")).decode("utf-8")
            conn.execute(
                "INSERT INTO passwords_v2 (site_hash, site_encrypted, user_id, iteration, is_shared) VALUES (?, ?, ?, ?, ?)",
                (site_hash, site_enc, req_user_id, "1", 0),
            )

    message = MagicMock()
    message.from_user.id = req_user_id
    message.chat.id = 111
    message.message_id = 222

    handlers.handle_list(message)

    # Default chunk size is 40. 50 items should produce 2 calls.
    assert mock_bot.reply_to.call_count == 2

    for call_args in mock_bot.reply_to.call_args_list:
        text = call_args[0][1]
        assert text.startswith("```text\n")
        assert text.endswith("```")


def test_callback_next_action(monkeypatch):
    """Ensure the 'next' inline button increments the iteration correctly."""
    mock_bot = MagicMock()
    monkeypatch.setattr("handlers.bot", mock_bot)

    site = "cb_test_next"
    site_hash = get_site_hash(site)

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

    # Verify the code block formatting
    args, _ = mock_bot.edit_message_text.call_args
    assert args[0].startswith("```\n")
    assert args[0].endswith("\n```")

    mock_bot.answer_callback_query.assert_called_once()


def test_callback_del_action(monkeypatch):
    """Ensure the 'del' inline button deletes the target site."""
    mock_bot = MagicMock()
    monkeypatch.setattr("handlers.bot", mock_bot)

    site = "cb_test_del"
    site_hash = get_site_hash(site)

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
    """Ensure the 'share' inline button toggles the shared state."""
    mock_bot = MagicMock()
    monkeypatch.setattr("handlers.bot", mock_bot)

    site = "cb_test_share"
    site_hash = get_site_hash(site)

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
