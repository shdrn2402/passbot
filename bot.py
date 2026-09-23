import hashlib
import hmac
import logging
import os
import sqlite3
from logging.handlers import RotatingFileHandler
from threading import Timer

import telebot
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

TOKEN: str | None = os.getenv("TELEGRAM_TOKEN")
if not TOKEN:
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
SECRET_KEY: str | None = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    logger.critical("SECRET_KEY environment variable is not set")
    raise ValueError("SECRET_KEY is strictly required for secure password generation.")


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                site TEXT,
                user_id INTEGER,
                iteration TEXT,
                username TEXT,
                PRIMARY KEY (site, user_id)
            )
        """)
    logger.info("Database initialized")


bot = telebot.TeleBot(TOKEN)


def get_suffix(site: str, user_id: int, iteration: str = "1", length: int = 6) -> str:
    message = f"{site.strip().lower()}:{user_id}:{iteration}".encode("utf-8")
    secret = SECRET_KEY.encode("utf-8")

    hash_hex = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return hash_hex[:length]


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
        "Example: `yandex 2`\n\n"
        "_Messages auto-delete after 15s_"
    )
    bot.reply_to(message, text, parse_mode="Markdown", reply_markup=markup)


@bot.message_handler(commands=["list"])
def handle_list(message: Message) -> None:
    if message.from_user.id not in ALLOWED_USER_IDS:
        return

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT site, user_id, iteration, username FROM passwords WHERE user_id = ? ORDER BY site",
            (message.from_user.id,),
        )
        rows = cursor.fetchall()

    if not rows:
        try:
            sent_msg = bot.reply_to(message, "Database is empty.")
            Timer(
                15.0,
                delete_messages,
                args=[message.chat.id, [message.message_id, sent_msg.message_id]],
            ).start()
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending empty DB message: {e}")
        return

    lines = ["```text", f"{'Site':<10} | {'User':<10} | {'It':<2} | Suffix", "-" * 37]
    for site, user_id, iteration, username in rows:
        suffix = get_suffix(site, user_id, iteration)
        site_name = site[:10]
        user_name = (username or str(user_id))[:10]
        lines.append(f"{site_name:<10} | {user_name:<10} | {iteration:<2} | {suffix}")
    lines.append("```")

    text = "\n".join(lines)

    try:
        sent_msg = bot.reply_to(message, text, parse_mode="MarkdownV2")
        Timer(
            15.0,
            delete_messages,
            args=[message.chat.id, [message.message_id, sent_msg.message_id]],
        ).start()
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
            Timer(
                15.0,
                delete_messages,
                args=[message.chat.id, [message.message_id, sent_msg.message_id]],
            ).start()
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending usage: {e}")
        return

    site = args[1].strip().lower()
    user_id = message.from_user.id

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "DELETE FROM passwords WHERE site = ? AND user_id = ?", (site, user_id)
        )
        conn.commit()
        affected = cursor.rowcount

    response_text = f"Deleted `{site}`" if affected > 0 else f"Site `{site}` not found"

    try:
        sent_msg = bot.reply_to(message, response_text, parse_mode="MarkdownV2")
        Timer(
            15.0,
            delete_messages,
            args=[message.chat.id, [message.message_id, sent_msg.message_id]],
        ).start()
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending delete response: {e}")


@bot.message_handler(content_types=["text"])
def handle_text(message: Message) -> None:
    if message.from_user.id not in ALLOWED_USER_IDS:
        return

    if message.text.startswith("/"):
        return

    args = message.text.split()
    site = args[0]
    iteration = args[1] if len(args) > 1 else "1"

    user_id = message.from_user.id
    username = message.from_user.first_name or message.from_user.username or "User"

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO passwords (site, user_id, iteration, username)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(site, user_id) DO UPDATE SET 
                iteration = excluded.iteration,
                username = excluded.username
        """,
            (site, user_id, iteration, username),
        )

    suffix = get_suffix(site, user_id, iteration)

    try:
        sent_msg = bot.reply_to(message, f"`{suffix}`", parse_mode="MarkdownV2")
        Timer(
            15.0,
            delete_messages,
            args=[message.chat.id, [message.message_id, sent_msg.message_id]],
        ).start()
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending message: {e}")


if __name__ == "__main__":
    init_db()
    logger.info("Starting bot...")
    bot.infinity_polling()
