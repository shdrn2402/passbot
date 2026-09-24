import logging

from telebot.types import BotCommand

# Import initialization logic and the bot instance
from config import bot
from utils import init_db

logger = logging.getLogger(__name__)

# Import handlers to register them with the bot instance
import handlers  # noqa: F401

if __name__ == "__main__":
    init_db()

    bot.set_my_commands(
        [
            BotCommand("list", "Show all passwords"),
            BotCommand("help", "Show available commands"),
        ]
    )

    logger.info("Starting bot...")
    bot.infinity_polling()
