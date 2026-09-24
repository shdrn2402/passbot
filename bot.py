import base64
import hashlib
import hmac
import logging
import os
import sqlite3
from logging.handlers import RotatingFileHandler
from threading import Timer

import cryptography
import telebot
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from telebot.apihelper import ApiTelegramException
from telebot.types import KeyboardButton, Message, ReplyKeyboardMarkup

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

try:
    TOKEN = os.environ["TELEGRAM_TOKEN"]
except KeyError:
    logger.critical("TELEGRAM_TOKEN environment variable is not set")
    raise ValueError("TELEGRAM_TOKEN environment variable is not set")


allowed_ids_raw: str = os.getenv("ALLOWED_USER_IDS", "")
ALLOWED_USER_IDS = [
    int(uid.strip()) for uid in allowed_ids_raw.split(",") if uid.strip().isdigit()
]

if not ALLOWED_USER_IDS:
    logger.warning(
        "ALLOWED_USER_IDS is not set or empty. The bot will ignore all messages."
    )

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
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS passwords_v2 (
                site_hash TEXT,
                site_encrypted TEXT,
                user_id INTEGER,
                iteration TEXT,
                username TEXT,
                PRIMARY KEY (site_hash, user_id)
            )
        """)
    logger.info("Database initialized")


bot = telebot.TeleBot(TOKEN)


def schedule_deletion(
    chat_id: int, message_ids: list[int], delay: float = 15.0
) -> None:
    Timer(delay, delete_messages, args=[chat_id, message_ids]).start()


def escape_md(text: str, in_code_block: bool = False) -> str:
    if in_code_block:
        return text.replace("\\", "\\\\").replace("`", "\\`")

    special_chars = r"_*[]()~`>#+-=|{}.!"
    return "".join(f"\\{char}" if char in special_chars else char for char in text)


def get_suffix(site: str, user_id: int, iteration: str = "1", length: int = 6) -> str:
    message = f"{site.strip().lower()}:{user_id}:{iteration}".encode("utf-8")
    secret = SECRET_KEY.encode("utf-8")

    hash_bytes = hmac.new(secret, message, hashlib.sha256).digest()
    suffix = base64.urlsafe_b64encode(hash_bytes).decode("utf-8").rstrip("=")

    return suffix[:length]


def delete_messages(chat_id: int, message_ids: list[int]) -> None:
    for msg_id in message_ids:
        try:
            bot.delete_message(chat_id, msg_id)
        except ApiTelegramException as e:
            logger.error(f"Telegram API error deleting msg {msg_id}: {e}")


@bot.message_handler(commands=["start"])
def handle_start(message: Message) -> None:
    if message.from_user.id not in ALLOWED_USER_IDS:
        return

    markup = ReplyKeyboardMarkup(resize_keyboard=True, is_persistent=True)
    markup.add(KeyboardButton("/list"))

    text = (
        "🔒 *Password Suffix Bot*\n\n"
        "Send: `site [iteration]`\n"
        "Example: `google 2`\n\n"
        "_Messages auto-delete after 15s_"
    )
    bot.reply_to(message, text, parse_mode="Markdown", reply_markup=markup)


@bot.message_handler(commands=["list"])
def handle_list(message: Message) -> None:
    if message.from_user.id not in ALLOWED_USER_IDS:
        return

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT site_encrypted, user_id, iteration, username FROM passwords_v2 WHERE user_id = ?",
            (message.from_user.id,),
        )
        rows = cursor.fetchall()

    if not rows:
        try:
            sent_msg = bot.reply_to(message, "Database is empty.")
            schedule_deletion(
                message.chat.id, [message.message_id, sent_msg.message_id]
            )
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending empty DB message: {e}")
        return

    lines = ["```text", f"{'Site':<10} | {'User':<10} | {'It':<2} | Suffix", "-" * 37]

    decrypted_rows = []
    for site_encrypted, user_id, iteration, username in rows:
        try:
            site = cipher.decrypt(site_encrypted.encode("utf-8")).decode("utf-8")
        except cryptography.fernet.InvalidToken:
            logger.error(
                f"Decryption failed for user {user_id}. Data might be corrupted or key changed."
            )
            continue
        decrypted_rows.append((site, user_id, iteration, username))

    decrypted_rows.sort(key=lambda x: x[0])

    for site, user_id, iteration, username in decrypted_rows:
        suffix = get_suffix(site, user_id, iteration)
        safe_site = escape_md(site, in_code_block=True)
        site_name = safe_site[:10]
        user_name = (username or str(user_id))[:10]
        lines.append(f"{site_name:<10} | {user_name:<10} | {iteration:<2} | {suffix}")
    lines.append("```")

    text = "\n".join(lines)

    try:
        sent_msg = bot.reply_to(message, text, parse_mode="MarkdownV2")
        schedule_deletion(message.chat.id, [message.message_id, sent_msg.message_id])
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending list: {e}")


@bot.message_handler(commands=["del", "delete"])
def handle_delete(message: Message) -> None:
    if message.from_user.id not in ALLOWED_USER_IDS:
        return

    args = message.text.split()
    if len(args) < 2:
        try:
            sent_msg = bot.reply_to(
                message, "Usage: `/del site`", parse_mode="MarkdownV2"
            )
            schedule_deletion(
                message.chat.id, [message.message_id, sent_msg.message_id]
            )
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending usage: {e}")
        return

    site = args[1].strip().lower()

    if len(site) > 50:
        schedule_deletion(message.chat.id, [message.message_id])
        return

    user_id = message.from_user.id
    site_hash = hmac.new(
        SECRET_KEY.encode("utf-8"), site.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "DELETE FROM passwords_v2 WHERE site_hash = ? AND user_id = ?",
            (site_hash, user_id),
        )
        affected = cursor.rowcount

    safe_site = escape_md(site, in_code_block=True)
    response_text = (
        f"Deleted `{safe_site}`" if affected > 0 else f"Site `{safe_site}` not found"
    )

    try:
        sent_msg = bot.reply_to(message, response_text, parse_mode="MarkdownV2")
        schedule_deletion(message.chat.id, [message.message_id, sent_msg.message_id])
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending delete response: {e}")


@bot.message_handler(content_types=["text"])
def handle_text(message: Message) -> None:
    if message.from_user.id not in ALLOWED_USER_IDS:
        return

    if message.text.startswith("/"):
        return

    args = message.text.split()
    site = args[0].strip().lower()
    iteration = args[1] if len(args) > 1 else "1"

    if len(site) > 50 or len(iteration) > 10:
        schedule_deletion(message.chat.id, [message.message_id])
        return

    user_id = message.from_user.id
    username = message.from_user.first_name or message.from_user.username or "User"

    site_hash = hmac.new(
        SECRET_KEY.encode("utf-8"), site.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT 1 FROM passwords_v2 WHERE site_hash = ? AND user_id = ?",
            (site_hash, user_id),
        )

        if cursor.fetchone():
            conn.execute(
                """
                UPDATE passwords_v2 
                SET iteration = ?, username = ? 
                WHERE site_hash = ? AND user_id = ?
                """,
                (iteration, username, site_hash, user_id),
            )
        else:
            site_encrypted = cipher.encrypt(site.encode("utf-8")).decode("utf-8")
            conn.execute(
                """
                INSERT INTO passwords_v2 (site_hash, site_encrypted, user_id, iteration, username)
                VALUES (?, ?, ?, ?, ?)
                """,
                (site_hash, site_encrypted, user_id, iteration, username),
            )

    suffix = get_suffix(site, user_id, iteration)

    try:
        sent_msg = bot.reply_to(message, f"`{suffix}`", parse_mode="MarkdownV2")
        schedule_deletion(message.chat.id, [message.message_id, sent_msg.message_id])
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending message: {e}")


if __name__ == "__main__":
    init_db()
    logger.info("Starting bot...")
    bot.infinity_polling()
