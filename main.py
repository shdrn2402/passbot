import logging

from telebot.types import BotCommand

from config import bot
from utils import init_db

logger = logging.getLogger(__name__)

import handlers  # noqa: F401

if __name__ == "__main__":
    init_db()

    bot.set_my_commands(
        [
            BotCommand("find", "Search for a specific site"),
            BotCommand("get", "Get suffix for exact site"),
            BotCommand("info", "Show detailed site info"),
            BotCommand("list", "Show all passwords"),
            BotCommand("shared", "List your shared services"),
            BotCommand("share", "Make your site available to family"),
            BotCommand("unshare", "Make your site private again"),
            BotCommand("del", "Delete a site completely"),
            BotCommand("help", "Show available commands"),
        ]
    )

    logger.info("Starting bot...")
    bot.infinity_polling()
