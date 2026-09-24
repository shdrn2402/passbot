import logging
import os

import telebot
from dotenv import load_dotenv
from telebot.types import BotCommand

load_dotenv()

from utils import init_db

logger = logging.getLogger(__name__)

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

bot = telebot.TeleBot(TOKEN)

# Imported after bot initialization to avoid circular imports
import handlers  # noqa: F401

if __name__ == "__main__":
    init_db()

    bot.set_my_commands(
        [
            BotCommand("list", "Show all passwords"),
            BotCommand("help", "Show available commands"),
            BotCommand("start", "Show start message"),
        ]
    )

    logger.info("Starting bot...")
    bot.infinity_polling()
