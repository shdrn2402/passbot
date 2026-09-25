import base64
import hashlib
import hmac
import logging
import os
import sqlite3
import time
from logging.handlers import RotatingFileHandler
from threading import Timer

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from telebot.apihelper import ApiTelegramException

LOG_DIR = os.getenv("LOG_DIR", "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "bot.log")

file_handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3)
console_handler = logging.StreamHandler()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[file_handler, console_handler],
)

logger = logging.getLogger(__name__)

load_dotenv()

DB_PATH: str = os.getenv("DB_PATH", "data/passwords.db")
try:
    SECRET_KEY = os.environ["SECRET_KEY"]
except KeyError:
    logger.critical("SECRET_KEY environment variable is not set")
    raise ValueError("SECRET_KEY is strictly required for secure password generation.")

fernet_key = base64.urlsafe_b64encode(
    hashlib.sha256(SECRET_KEY.encode("utf-8")).digest()
)
cipher = Fernet(fernet_key)


def init_db() -> None:
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS passwords_v2 (
                site_hash TEXT,
                site_encrypted TEXT,
                user_id INTEGER,
                iteration TEXT,
                username TEXT,
                is_shared INTEGER DEFAULT 0,
                updated_at INTEGER,
                PRIMARY KEY (site_hash, user_id)
            )
        """)

        cursor = conn.execute("PRAGMA table_info(passwords_v2)")
        columns = [col[1] for col in cursor.fetchall()]

        if "is_shared" not in columns:
            conn.execute(
                "ALTER TABLE passwords_v2 ADD COLUMN is_shared INTEGER DEFAULT 0"
            )
            logger.info("Database migrated: added is_shared column")

        if "updated_at" not in columns:
            conn.execute(
                "ALTER TABLE passwords_v2 ADD COLUMN updated_at INTEGER DEFAULT 0"
            )
            logger.info("Database migrated: added updated_at column")

    logger.info("Database initialized")


def get_site_hash(site: str) -> str:
    return hmac.new(
        SECRET_KEY.encode("utf-8"), site.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def format_relative_time(timestamp: int | None) -> str:
    if not timestamp:
        return "Unknown"

    diff = int(time.time()) - timestamp
    days = diff // 86400

    if days == 0:
        return "Today"
    if days == 1:
        return "1 day ago"

    return f"{days} days ago"


def get_suffix(site: str, user_id: int, iteration: str = "1", length: int = 6) -> str:
    message = f"{site.strip().lower()}:{user_id}:{iteration}".encode("utf-8")
    secret = SECRET_KEY.encode("utf-8")

    hash_bytes = hmac.new(secret, message, hashlib.sha256).digest()
    suffix = base64.urlsafe_b64encode(hash_bytes).decode("utf-8").rstrip("=")

    return suffix[:length]


def escape_md(text: str, in_code_block: bool = False) -> str:
    if in_code_block:
        return text.replace("\\", "\\\\").replace("`", "\\`")

    special_chars = r"_*[]()~`>#+-=|{}.!"
    return "".join(f"\\{char}" if char in special_chars else char for char in text)


def set_shared_status(site_hash: str, user_id: int, is_shared: int) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "UPDATE passwords_v2 SET is_shared = ?, updated_at = CAST(strftime('%s', 'now') AS INTEGER) WHERE site_hash = ? AND user_id = ?",
            (is_shared, site_hash, user_id),
        )
        return cursor.rowcount


def schedule_deletion(
    bot, chat_id: int, message_ids: list[int], delay: float = 15.0
) -> None:
    Timer(delay, delete_messages, args=[bot, chat_id, message_ids]).start()


def delete_messages(bot, chat_id: int, message_ids: list[int]) -> None:
    for msg_id in message_ids:
        try:
            bot.delete_message(chat_id, msg_id)
        except ApiTelegramException as e:
            logger.error(f"Telegram API error deleting msg {msg_id}: {e}")
