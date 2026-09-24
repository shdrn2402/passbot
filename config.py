import logging
import os

import telebot
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

try:
    TOKEN = os.environ["TELEGRAM_TOKEN"]
except KeyError:
    logger.critical("TELEGRAM_TOKEN environment variable is not set")
    raise ValueError("TELEGRAM_TOKEN is not set")

allowed_ids_raw: str = os.getenv("ALLOWED_USER_IDS", "")
ALLOWED_USER_IDS = [
    int(uid.strip()) for uid in allowed_ids_raw.split(",") if uid.strip().isdigit()
]

if not ALLOWED_USER_IDS:
    logger.warning("ALLOWED_USER_IDS is empty. The bot will ignore all messages.")

bot = telebot.TeleBot(TOKEN)
