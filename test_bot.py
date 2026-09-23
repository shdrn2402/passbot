import hashlib
import hmac
import os
import sqlite3

from bot import get_suffix

TEST_USER_ID = 123456789
TEST_SITE = "github"
TEST_ITERATION = "2"
TEST_SECRET = "test_super_secret_key"


def test_get_suffix_deterministic(monkeypatch):
    monkeypatch.setattr("bot.SECRET_KEY", TEST_SECRET)

    message = f"{TEST_SITE}:{TEST_USER_ID}:{TEST_ITERATION}".encode("utf-8")
    secret = TEST_SECRET.encode("utf-8")
    expected_suffix = hmac.new(secret, message, hashlib.sha256).hexdigest()[:6]

    result = get_suffix(TEST_SITE, TEST_USER_ID, TEST_ITERATION)
    assert result == expected_suffix


def test_database_isolation():
    test_db_path = ":memory:"
    os.environ["DB_PATH"] = test_db_path

    with sqlite3.connect(test_db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                site TEXT,
                user_id INTEGER,
                iteration TEXT,
                username TEXT,
                PRIMARY KEY (site, user_id)
            )
        """)
        conn.execute("INSERT INTO passwords VALUES ('vk', 111, '1', 'user1')")
        conn.execute("INSERT INTO passwords VALUES ('vk', 222, '1', 'user2')")

        cursor = conn.execute("SELECT * FROM passwords WHERE user_id = ?", (111,))
        rows = cursor.fetchall()

    assert len(rows) == 1
    assert rows[0][1] == 111
