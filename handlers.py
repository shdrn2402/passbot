import hashlib
import hmac
import logging
import sqlite3

import cryptography
from telebot.apihelper import ApiTelegramException
from telebot.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    ReplyKeyboardRemove,
)

from config import ALLOWED_USER_IDS, bot
from utils import (
    DB_PATH,
    SECRET_KEY,
    cipher,
    escape_md,
    get_suffix,
    schedule_deletion,
    set_shared_status,
)

logger = logging.getLogger(__name__)


def get_site_keyboard(site: str, is_shared: bool) -> InlineKeyboardMarkup:
    markup = InlineKeyboardMarkup()

    btn_next = InlineKeyboardButton("🔄 Next", callback_data=f"next:{site}")

    share_text = "🔒 Unshare" if is_shared else "👨‍👩‍👧 Share"
    share_action = "unshare" if is_shared else "share"
    btn_share = InlineKeyboardButton(share_text, callback_data=f"{share_action}:{site}")

    btn_del = InlineKeyboardButton("🗑 Del", callback_data=f"del:{site}")

    markup.row(btn_next, btn_share, btn_del)
    return markup


def process_share_command(message: Message, is_shared: int) -> None:
    if message.from_user.id not in ALLOWED_USER_IDS:
        return

    args = message.text.split()
    command = args[0]

    if len(args) < 2:
        try:
            sent_msg = bot.reply_to(
                message, f"Usage: `{command} site`", parse_mode="MarkdownV2"
            )
            schedule_deletion(
                bot, message.chat.id, [message.message_id, sent_msg.message_id]
            )
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending usage: {e}")
        return

    site = args[1].strip().lower()
    if len(site) > 50:
        schedule_deletion(bot, message.chat.id, [message.message_id])
        return

    user_id = message.from_user.id
    site_hash = hmac.new(
        SECRET_KEY.encode("utf-8"), site.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    affected = set_shared_status(site_hash, user_id, is_shared)

    safe_site = escape_md(site, in_code_block=True)
    status_text = "shared" if is_shared else "unshared"

    response_text = (
        f"Site `{safe_site}` is now {status_text}"
        if affected > 0
        else f"Site `{safe_site}` not found or access denied"
    )

    try:
        sent_msg = bot.reply_to(message, response_text, parse_mode="MarkdownV2")
        schedule_deletion(
            bot, message.chat.id, [message.message_id, sent_msg.message_id]
        )
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending share response: {e}")


@bot.message_handler(commands=["start"])
def handle_start(message: Message) -> None:

    if message.from_user.id not in ALLOWED_USER_IDS:
        return

    markup = ReplyKeyboardRemove()
    text = (
        "🔒 *Password Suffix Bot*\n\n"
        "Send: `site [iteration]`\n"
        "Example: `google 2`\n\n"
        "Type /help to see all available commands\\.\n"
        "_This message stays here as a quick reference\\._"
    )

    try:
        bot.reply_to(message, text, parse_mode="MarkdownV2", reply_markup=markup)
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending start: {e}")


@bot.message_handler(commands=["help"])
def handle_help(message: Message) -> None:
    if message.from_user.id not in ALLOWED_USER_IDS:
        return

    text = (
        "📚 *Available Commands:*\n\n"
        "*/list* \\- Show all personal and shared passwords\n"
        "*/get \\[site\\]* \\- Search for a specific site\n"
        "*/next \\[site\\]* \\- Increment iteration for your site\n"
        "*/share \\[site\\]* \\- Make your site available to family\n"
        "*/unshare \\[site\\]* \\- Make your site private again\n"
        "*/del \\[site\\]* \\- Delete a site completely\n\n"
        "_Message auto\\-deletes in 30s_"
    )

    try:
        sent_msg = bot.reply_to(message, text, parse_mode="MarkdownV2")
        schedule_deletion(
            bot, message.chat.id, [message.message_id, sent_msg.message_id], delay=30.0
        )
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending help: {e}")


@bot.message_handler(commands=["list"])
def handle_list(message: Message) -> None:
    if message.from_user.id not in ALLOWED_USER_IDS:
        return

    req_user_id = message.from_user.id

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT site_encrypted, user_id, iteration, is_shared FROM passwords_v2 WHERE user_id = ? OR is_shared = 1",
            (req_user_id,),
        )
        rows = cursor.fetchall()

    if not rows:
        try:
            sent_msg = bot.reply_to(message, "Database is empty.")
            schedule_deletion(
                bot, message.chat.id, [message.message_id, sent_msg.message_id]
            )
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending empty DB message: {e}")
        return

    decrypted_rows = []
    for site_encrypted, owner_id, iteration, is_shared in rows:
        try:
            site = cipher.decrypt(site_encrypted.encode("utf-8")).decode("utf-8")
            decrypted_rows.append((site, owner_id, iteration, is_shared))
        except cryptography.fernet.InvalidToken:
            continue

    decrypted_rows.sort(key=lambda x: x[0])

    lines = ["```text", f"{'Site':<12} | {'T':<3} | {'It':<2} | Suffix", "-" * 33]

    for site, owner_id, iteration, is_shared in decrypted_rows:
        tag = "[P]" if owner_id == req_user_id else "[S]"
        suffix = get_suffix(site, owner_id, iteration)
        safe_site = escape_md(site, in_code_block=True)[:12]

        lines.append(f"{safe_site:<12} | {tag:<3} | {iteration:<2} | {suffix}")

    lines.append("```")

    text = "\n".join(lines)

    try:
        sent_msg = bot.reply_to(message, text, parse_mode="MarkdownV2")
        schedule_deletion(
            bot, message.chat.id, [message.message_id, sent_msg.message_id]
        )
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending list: {e}")


@bot.message_handler(commands=["get"])
def handle_get(message: Message) -> None:
    if message.from_user.id not in ALLOWED_USER_IDS:
        return

    args = message.text.split()
    if len(args) < 2:
        try:
            sent_msg = bot.reply_to(
                message, "Usage: `/get search_term`", parse_mode="MarkdownV2"
            )
            schedule_deletion(
                bot, message.chat.id, [message.message_id, sent_msg.message_id]
            )
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending usage: {e}")
        return

    search_term = args[1].strip().lower()
    req_user_id = message.from_user.id

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT site_encrypted, user_id, iteration, is_shared FROM passwords_v2 WHERE user_id = ? OR is_shared = 1",
            (req_user_id,),
        )
        rows = cursor.fetchall()

    results = []
    for site_encrypted, owner_id, iteration, is_shared in rows:
        try:
            site = cipher.decrypt(site_encrypted.encode("utf-8")).decode("utf-8")
        except cryptography.fernet.InvalidToken:
            continue

        if search_term in site:
            results.append((site, owner_id, iteration, is_shared))

    if not results:
        try:
            sent_msg = bot.reply_to(message, "No matches found.")
            schedule_deletion(
                bot, message.chat.id, [message.message_id, sent_msg.message_id]
            )
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending empty response: {e}")
        return

    results.sort(key=lambda x: x[0])

    lines = ["```text", f"{'T':<3} | {'Site':<15} | {'It':<2} | Suffix", "-" * 34]

    for site, owner_id, iteration, is_shared in results:
        tag = "[P]" if owner_id == req_user_id else "[S]"
        suffix = get_suffix(site, owner_id, iteration)
        safe_site = escape_md(site, in_code_block=True)[:15]

        lines.append(f"{tag:<3} | {safe_site:<15} | {iteration:<2} | {suffix}")

    lines.append("```")
    text = "\n".join(lines)

    try:
        sent_msg = bot.reply_to(message, text, parse_mode="MarkdownV2")
        schedule_deletion(
            bot, message.chat.id, [message.message_id, sent_msg.message_id]
        )
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending get response: {e}")


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
                bot, message.chat.id, [message.message_id, sent_msg.message_id]
            )
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending usage: {e}")
        return

    site = args[1].strip().lower()

    if len(site) > 50:
        schedule_deletion(bot, message.chat.id, [message.message_id])
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
        schedule_deletion(
            bot, message.chat.id, [message.message_id, sent_msg.message_id]
        )
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending delete response: {e}")


@bot.message_handler(commands=["share"])
def handle_share(message: Message) -> None:
    process_share_command(message, 1)


@bot.message_handler(commands=["unshare"])
def handle_unshare(message: Message) -> None:
    process_share_command(message, 0)


@bot.message_handler(commands=["next"])
def handle_next(message: Message) -> None:
    if message.from_user.id not in ALLOWED_USER_IDS:
        return

    args = message.text.split()
    if len(args) < 2:
        try:
            sent_msg = bot.reply_to(
                message, "Usage: `/next site`", parse_mode="MarkdownV2"
            )
            schedule_deletion(
                bot, message.chat.id, [message.message_id, sent_msg.message_id]
            )
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending usage: {e}")
        return

    site = args[1].strip().lower()
    user_id = message.from_user.id
    site_hash = hmac.new(
        SECRET_KEY.encode("utf-8"), site.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT iteration FROM passwords_v2 WHERE site_hash = ? AND user_id = ?",
            (site_hash, user_id),
        )
        row = cursor.fetchone()

        if not row:
            try:
                sent_msg = bot.reply_to(
                    message,
                    f"Site `{escape_md(site, in_code_block=True)}` not found or access denied.",
                    parse_mode="MarkdownV2",
                )
                schedule_deletion(
                    bot, message.chat.id, [message.message_id, sent_msg.message_id]
                )
            except ApiTelegramException as e:
                logger.error(f"Telegram API error: {e}")
            return

        current_iteration = row[0]

        try:
            next_iteration = str(int(current_iteration) + 1)
        except ValueError:
            sent_msg = bot.reply_to(
                message, "Current iteration is not a number. Update it manually first."
            )
            schedule_deletion(
                bot, message.chat.id, [message.message_id, sent_msg.message_id]
            )
            return

        conn.execute(
            "UPDATE passwords_v2 SET iteration = ? WHERE site_hash = ? AND user_id = ?",
            (next_iteration, site_hash, user_id),
        )

    suffix = get_suffix(site, user_id, next_iteration)

    try:
        sent_msg = bot.reply_to(message, f"`{suffix}`", parse_mode="MarkdownV2")
        schedule_deletion(
            bot, message.chat.id, [message.message_id, sent_msg.message_id]
        )
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending next suffix: {e}")


@bot.message_handler(content_types=["text"])
def handle_text(message: Message) -> None:
    if message.from_user.id not in ALLOWED_USER_IDS:
        return

    if message.text.startswith("/"):
        return

    args = message.text.split()
    site = args[0].strip().lower()
    iteration = args[1] if len(args) > 1 else "1"

    try:
        int(iteration)
    except ValueError:
        try:
            sent_msg = bot.reply_to(
                message, "Iteration must be a number\\.", parse_mode="MarkdownV2"
            )
            schedule_deletion(
                bot, message.chat.id, [message.message_id, sent_msg.message_id]
            )
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending iteration warning: {e}")
        return

    if len(site) > 50 or len(iteration) > 10:
        schedule_deletion(bot, message.chat.id, [message.message_id])
        return

    user_id = message.from_user.id
    username = message.from_user.first_name or message.from_user.username or "User"

    site_hash = hmac.new(
        SECRET_KEY.encode("utf-8"), site.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT is_shared FROM passwords_v2 WHERE site_hash = ? AND user_id = ?",
            (site_hash, user_id),
        )
        row = cursor.fetchone()

        if row:
            is_shared = bool(row[0])
            conn.execute(
                """
                    UPDATE passwords_v2 
                    SET iteration = ?, username = ? 
                    WHERE site_hash = ? AND user_id = ?
                    """,
                (iteration, username, site_hash, user_id),
            )
        else:
            is_shared = False
            site_encrypted = cipher.encrypt(site.encode("utf-8")).decode("utf-8")  # noqa
            conn.execute(
                """
                    INSERT INTO passwords_v2 (site_hash, site_encrypted, user_id, iteration, username)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                (site_hash, site_encrypted, user_id, iteration, username),
            )

    suffix = get_suffix(site, user_id, iteration)
    markup = get_site_keyboard(site, is_shared)

    try:
        sent_msg = bot.reply_to(
            message, f"`{suffix}`", parse_mode="MarkdownV2", reply_markup=markup
        )
        schedule_deletion(
            bot, message.chat.id, [message.message_id, sent_msg.message_id]
        )
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending message: {e}")


@bot.callback_query_handler(
    func=lambda call: call.data.startswith(("next:", "share:", "unshare:", "del:"))
)
def handle_callbacks(call: CallbackQuery) -> None:
    if call.from_user.id not in ALLOWED_USER_IDS:
        return

    action, site = call.data.split(":", 1)
    user_id = call.from_user.id
    site_hash = hmac.new(
        SECRET_KEY.encode("utf-8"), site.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    try:
        with sqlite3.connect(DB_PATH) as conn:
            if action == "next":
                cursor = conn.execute(
                    "SELECT iteration, is_shared FROM passwords_v2 WHERE site_hash = ? AND user_id = ?",
                    (site_hash, user_id),
                )
                row = cursor.fetchone()

                if not row:
                    bot.answer_callback_query(
                        call.id, "Site not found", show_alert=True
                    )
                    return

                current_iteration, is_shared = row
                try:
                    next_iteration = str(int(current_iteration) + 1)
                except ValueError:
                    bot.answer_callback_query(
                        call.id, "Error: Invalid iteration format", show_alert=True
                    )
                    return

                conn.execute(
                    "UPDATE passwords_v2 SET iteration = ? WHERE site_hash = ? AND user_id = ?",
                    (next_iteration, site_hash, user_id),
                )

                suffix = get_suffix(site, user_id, next_iteration)
                markup = get_site_keyboard(site, bool(is_shared))

                bot.edit_message_text(
                    f"`{suffix}`",
                    call.message.chat.id,
                    call.message.message_id,
                    parse_mode="MarkdownV2",
                    reply_markup=markup,
                )
                bot.answer_callback_query(
                    call.id, f"Iteration incremented to {next_iteration}"
                )

            elif action in ("share", "unshare"):
                is_shared_new = 1 if action == "share" else 0
                conn.execute(
                    "UPDATE passwords_v2 SET is_shared = ? WHERE site_hash = ? AND user_id = ?",
                    (is_shared_new, site_hash, user_id),
                )

                cursor = conn.execute(
                    "SELECT iteration FROM passwords_v2 WHERE site_hash = ? AND user_id = ?",
                    (site_hash, user_id),
                )
                row = cursor.fetchone()

                if row:
                    suffix = get_suffix(site, user_id, row[0])
                    markup = get_site_keyboard(site, bool(is_shared_new))
                    bot.edit_message_reply_markup(
                        call.message.chat.id,
                        call.message.message_id,
                        reply_markup=markup,
                    )

                status_text = "Shared with family" if is_shared_new else "Made private"
                bot.answer_callback_query(call.id, status_text)

            elif action == "del":
                conn.execute(
                    "DELETE FROM passwords_v2 WHERE site_hash = ? AND user_id = ?",
                    (site_hash, user_id),
                )
                bot.delete_message(call.message.chat.id, call.message.message_id)
                bot.answer_callback_query(call.id, "Site deleted successfully")

    except ApiTelegramException as e:
        logger.error(f"Telegram API error in callback {action}: {e}")
