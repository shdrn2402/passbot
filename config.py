import logging
import os

import telebot
from dotenv import load_dotenv
from telebot.handler_backends import BaseMiddleware, CancelUpdate

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


class AuthMiddleware(BaseMiddleware):
    """
    Global middleware to restrict bot access exclusively to allowed users.
    Intercepts both incoming messages and callback queries.
    """

    def __init__(self) -> None:
        self.update_types = ["message", "callback_query"]

    def pre_process(self, message, data: dict) -> CancelUpdate | None:
        user = getattr(message, "from_user", None)
        if user and user.id not in ALLOWED_USER_IDS:
            logger.info(f"Unauthorized access attempt from user ID: {user.id}")
            return CancelUpdate()
        return None

    def post_process(self, message, data: dict, exception: Exception | None) -> None:
        pass


bot = telebot.TeleBot(TOKEN, use_class_middlewares=True)
bot.setup_middleware(AuthMiddleware())
