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

from config import bot
from utils import (
    DB_PATH,
    cipher,
    escape_md,
    format_relative_time,
    get_site_hash,
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
    if not message.text:
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
    site_hash = get_site_hash(site)

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
    text = (
        "📚 *Available Commands:*\n\n"
        "*/list* \\- Show all personal and shared passwords\n"
        "*/shared* \\- List your shared services\n"
        "*/get \\[site\\]* \\- Get suffix for exact site\n"
        "*/find \\[query\\]* \\- Search for a specific site\n"
        "*/info \\[site\\]* \\- Show detailed site info\n"
        "*/share \\[site\\]* \\- Make your site available to shared\n"
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
    req_user_id = message.from_user.id

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT site_encrypted, user_id, is_shared FROM passwords_v2 WHERE user_id = ? OR is_shared = 1",
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
    for site_encrypted, owner_id, is_shared in rows:
        try:
            site = cipher.decrypt(site_encrypted.encode("utf-8")).decode("utf-8")
            decrypted_rows.append((site, owner_id, is_shared))
        except cryptography.fernet.InvalidToken:
            continue

    decrypted_rows.sort(key=lambda x: x[0])

    lines = ["```text", f"{'Site':<15} | Type", "-" * 23]

    for site, owner_id, is_shared in decrypted_rows:
        if owner_id != req_user_id:
            tag = "shared"
        else:
            tag = "shared" if is_shared else "private"

        safe_site = escape_md(site, in_code_block=True)[:15]
        lines.append(f"{safe_site:<15} | {tag}")

    lines.append("```")

    # Pagination to handle API limits
    chunk_size = 40
    chunks = [lines[i : i + chunk_size] for i in range(0, len(lines), chunk_size)]

    sent_msgs = []
    try:
        for chunk in chunks:
            if not chunk[0].startswith("```text"):
                chunk.insert(0, "```text")
            if chunk[-1] != "```":
                chunk.append("```")

            text = "\n".join(chunk)
            msg = bot.reply_to(message, text, parse_mode="MarkdownV2")
            sent_msgs.append(msg.message_id)

        schedule_deletion(
            bot, message.chat.id, [message.message_id] + sent_msgs, delay=20.0
        )
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending list: {e}")


@bot.message_handler(commands=["shared"])
def handle_shared(message: Message) -> None:
    req_user_id = message.from_user.id

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT site_encrypted FROM passwords_v2 WHERE user_id = ? AND is_shared = 1",
            (req_user_id,),
        )
        rows = cursor.fetchall()

    if not rows:
        try:
            sent_msg = bot.reply_to(message, "You have no shared services.")
            schedule_deletion(
                bot, message.chat.id, [message.message_id, sent_msg.message_id]
            )
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending empty shared message: {e}")
        return

    decrypted_sites = []
    for (site_encrypted,) in rows:
        try:
            site = cipher.decrypt(site_encrypted.encode("utf-8")).decode("utf-8")
            decrypted_sites.append(site)
        except cryptography.fernet.InvalidToken:
            continue

    decrypted_sites.sort()

    lines = ["*Shared Services:*", ""]
    for site in decrypted_sites:
        lines.append(f"👨‍👩‍👧 `{escape_md(site)}`")

    text = "\n".join(lines)

    try:
        sent_msg = bot.reply_to(message, text, parse_mode="MarkdownV2")
        schedule_deletion(
            bot, message.chat.id, [message.message_id, sent_msg.message_id]
        )
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending shared list: {e}")


@bot.message_handler(commands=["info"])
def handle_info(message: Message) -> None:
    if not message.text:
        return

    args = message.text.split()
    if len(args) < 2:
        try:
            sent_msg = bot.reply_to(
                message, "Usage: `/info site`", parse_mode="MarkdownV2"
            )
            schedule_deletion(
                bot, message.chat.id, [message.message_id, sent_msg.message_id]
            )
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending usage: {e}")
        return

    site = args[1].strip().lower()
    req_user_id = message.from_user.id
    site_hash = get_site_hash(site)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT user_id, iteration, is_shared, updated_at FROM passwords_v2 WHERE site_hash = ? AND (user_id = ? OR is_shared = 1)",
            (site_hash, req_user_id),
        )
        row = cursor.fetchone()

    if not row:
        try:
            sent_msg = bot.reply_to(message, "Site not found.")
            schedule_deletion(
                bot, message.chat.id, [message.message_id, sent_msg.message_id]
            )
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending empty response: {e}")
        return

    owner_id, iteration, is_shared, updated_at = row

    status_emoji = "👥 Shared" if is_shared or owner_id != req_user_id else "🔒 Private"
    time_str = format_relative_time(updated_at)
    suffix = get_suffix(site, owner_id, iteration)
    safe_site = escape_md(site)

    text = (
        f"*{safe_site}*\n"
        f"{status_emoji}\n"
        f"Iteration: {iteration}\n"
        f"Updated: {time_str}\n\n"
        f"```\n{suffix}\n```"
    )

    try:
        sent_msg = bot.reply_to(message, text, parse_mode="MarkdownV2")
        schedule_deletion(
            bot, message.chat.id, [message.message_id, sent_msg.message_id]
        )
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending info response: {e}")


@bot.message_handler(commands=["get"])
def handle_get(message: Message) -> None:
    if not message.text:
        return

    args = message.text.split()
    if len(args) < 2:
        try:
            sent_msg = bot.reply_to(
                message, "Usage: `/get site`", parse_mode="MarkdownV2"
            )
            schedule_deletion(
                bot, message.chat.id, [message.message_id, sent_msg.message_id]
            )
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending usage: {e}")
        return

    site = args[1].strip().lower()
    req_user_id = message.from_user.id
    site_hash = get_site_hash(site)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT user_id, iteration, is_shared FROM passwords_v2 WHERE site_hash = ? AND (user_id = ? OR is_shared = 1)",
            (site_hash, req_user_id),
        )
        row = cursor.fetchone()

    if not row:
        try:
            sent_msg = bot.reply_to(message, "Site not found.")
            schedule_deletion(
                bot, message.chat.id, [message.message_id, sent_msg.message_id]
            )
        except ApiTelegramException as e:
            logger.error(f"Telegram API error sending empty response: {e}")
        return

    owner_id, iteration, is_shared = row

    suffix = get_suffix(site, owner_id, iteration)

    # Do not allow modifying shared member's records, but show buttons for own
    is_owner = owner_id == req_user_id
    markup = get_site_keyboard(site, bool(is_shared)) if is_owner else None

    response_text = f"```\n{suffix}\n```"

    try:
        sent_msg = bot.reply_to(
            message, response_text, parse_mode="MarkdownV2", reply_markup=markup
        )
        schedule_deletion(
            bot, message.chat.id, [message.message_id, sent_msg.message_id]
        )
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending get response: {e}")


@bot.message_handler(commands=["find"])
def handle_find(message: Message) -> None:
    if not message.text:
        return

    args = message.text.split()
    if len(args) < 2:
        try:
            sent_msg = bot.reply_to(
                message, "Usage: `/find query`", parse_mode="MarkdownV2"
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
            "SELECT site_encrypted, user_id, is_shared FROM passwords_v2 WHERE user_id = ? OR is_shared = 1",
            (req_user_id,),
        )
        rows = cursor.fetchall()

    results = []
    for site_encrypted, owner_id, is_shared in rows:
        try:
            site = cipher.decrypt(site_encrypted.encode("utf-8")).decode("utf-8")
        except cryptography.fernet.InvalidToken:
            continue

        if search_term in site:
            results.append((site, owner_id, is_shared))

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

    markup = InlineKeyboardMarkup(row_width=2)
    buttons = []

    for site, owner_id, is_shared in results:
        icon = "👥" if is_shared or owner_id != req_user_id else "🔒"
        btn_text = f"{icon} {site}"
        # We route find clicks to get_site callback
        buttons.append(InlineKeyboardButton(btn_text, callback_data=f"get_site:{site}"))

    markup.add(*buttons)

    try:
        sent_msg = bot.reply_to(message, "Select a site:", reply_markup=markup)
        schedule_deletion(
            bot, message.chat.id, [message.message_id, sent_msg.message_id]
        )
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending find response: {e}")


@bot.message_handler(commands=["del", "delete"])
def handle_delete(message: Message) -> None:
    if not message.text:
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
    site_hash = get_site_hash(site)

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


@bot.message_handler(content_types=["text"])
def handle_text(message: Message) -> None:
    if not message.text or message.text.startswith("/"):
        return

    args = message.text.split()
    if not args:
        return

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
    site_hash = get_site_hash(site)

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
                SET iteration = ?, username = ?, updated_at = CAST(strftime('%s', 'now') AS INTEGER)
                WHERE site_hash = ? AND user_id = ?
                """,
                (iteration, username, site_hash, user_id),
            )
        else:
            is_shared = False
            site_encrypted = cipher.encrypt(site.encode("utf-8")).decode("utf-8")
            conn.execute(
                """
                INSERT INTO passwords_v2 (site_hash, site_encrypted, user_id, iteration, username, updated_at)
                VALUES (?, ?, ?, ?, ?, CAST(strftime('%s', 'now') AS INTEGER))
                """,
                (site_hash, site_encrypted, user_id, iteration, username),
            )

    suffix = get_suffix(site, user_id, iteration)
    markup = get_site_keyboard(site, is_shared)

    response_text = f"```\n{suffix}\n```"

    try:
        sent_msg = bot.reply_to(
            message, response_text, parse_mode="MarkdownV2", reply_markup=markup
        )
        schedule_deletion(
            bot, message.chat.id, [message.message_id, sent_msg.message_id]
        )
    except ApiTelegramException as e:
        logger.error(f"Telegram API error sending message: {e}")


@bot.callback_query_handler(
    func=lambda call: call.data.startswith(
        ("next:", "share:", "unshare:", "del:", "get_site:")
    )
)
def handle_callbacks(call: CallbackQuery) -> None:
    action, site = call.data.split(":", 1)
    user_id = call.from_user.id
    site_hash = get_site_hash(site)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            if action == "get_site":
                cursor = conn.execute(
                    "SELECT user_id, iteration, is_shared FROM passwords_v2 WHERE site_hash = ? AND (user_id = ? OR is_shared = 1)",
                    (site_hash, user_id),
                )
                row = cursor.fetchone()

                if not row:
                    bot.answer_callback_query(
                        call.id, "Site not found", show_alert=True
                    )
                    return

                owner_id, iteration, is_shared = row
                suffix = get_suffix(site, owner_id, iteration)

                is_owner = owner_id == user_id
                markup = get_site_keyboard(site, bool(is_shared)) if is_owner else None

                bot.edit_message_text(
                    f"```\n{suffix}\n```",
                    call.message.chat.id,
                    call.message.message_id,
                    parse_mode="MarkdownV2",
                    reply_markup=markup,
                )
                bot.answer_callback_query(call.id)
                return

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
                    "UPDATE passwords_v2 SET iteration = ?, updated_at = CAST(strftime('%s', 'now') AS INTEGER) WHERE site_hash = ? AND user_id = ?",
                    (next_iteration, site_hash, user_id),
                )

                suffix = get_suffix(site, user_id, next_iteration)
                markup = get_site_keyboard(site, bool(is_shared))

                bot.edit_message_text(
                    f"```\n{suffix}\n```",
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
                    "UPDATE passwords_v2 SET is_shared = ?, updated_at = CAST(strftime('%s', 'now') AS INTEGER) WHERE site_hash = ? AND user_id = ?",
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

                status_text = "Shared with shared" if is_shared_new else "Made private"
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
