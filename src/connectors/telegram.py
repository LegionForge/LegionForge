"""
src/connectors/telegram.py
───────────────────────────
Telegram bot connector for LegionForge.

Bridges Telegram messages to the gateway API and streams responses back to the
chat as the agent generates them (edit-in-place, throttled).

Flow:
    Telegram message starting with PREFIX (default "/")
        → POST /tasks  (gateway, as telegram-bot user)
        → subscribe SSE stream (httpx streaming)
        → edit reply message every MAX_EDIT_INTERVAL seconds
        → final edit on task_complete / task_error

Security:
    - The bot authenticates to the gateway as a dedicated 'telegram-bot' user
      with no operator access.
    - action="telegram" is set so Guardian and audit logs identify the source.
    - Input length is capped at 4000 chars (Telegram API limit: 4096).
    - The bot only responds to TELEGRAM_ALLOWED_CHATS (empty = all, not recommended).
    - Bot token and gateway API key are stored in macOS Keychain — never in env files.

Setup (one-time):
    1. Create a bot via @BotFather on Telegram. Copy the bot token.
    2. Store the bot token in Keychain:
         security add-generic-password -s legionforge_telegram_token -a api_key -w '<token>'
    3. Create the gateway user:
         make create-user USERNAME=telegram-bot
       (copy the printed API key)
    4. Store the gateway API key in Keychain:
         security add-generic-password -s legionforge_telegram_api_key -a api_key -w '<key>'
    5. Get your chat ID by sending /start to the bot and checking the Telegram API:
         curl https://api.telegram.org/bot<TOKEN>/getUpdates
    6. Set allowed chats (recommended):
         export TELEGRAM_ALLOWED_CHATS=123456789,-987654321
    7. Start the connector:
         make telegram-start

Environment / Keychain:
    legionforge_telegram_token    — Telegram bot token (Keychain, required)
    legionforge_telegram_api_key  — Gateway Bearer API key (Keychain, required)
    TELEGRAM_GATEWAY_URL          — default http://localhost:8080
    TELEGRAM_ALLOWED_CHATS        — comma-separated chat IDs (empty = all, not recommended)
    TELEGRAM_PREFIX               — command prefix, default "/"  (e.g. "/task ...")
    TELEGRAM_MAX_EDIT_INTERVAL    — seconds between message edits, default 2.0
    TELEGRAM_AGENT_TYPE           — default "orchestrator"
"""

from __future__ import annotations

import asyncio
import logging
import os
import time

from telegram import Update
from telegram.ext import Application, MessageHandler, filters, ContextTypes

from src.connectors.base import _load_secret, _run_task

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────

GATEWAY_URL = os.environ.get("TELEGRAM_GATEWAY_URL", "http://localhost:8080")
ALLOWED_CHATS: set[int] = {
    int(c.strip())
    for c in os.environ.get("TELEGRAM_ALLOWED_CHATS", "").split(",")
    if c.strip().lstrip("-").isdigit()
}
PREFIX = os.environ.get("TELEGRAM_PREFIX", "/")
MAX_EDIT_INTERVAL = float(os.environ.get("TELEGRAM_MAX_EDIT_INTERVAL", "2.0"))
AGENT_TYPE = os.environ.get("TELEGRAM_AGENT_TYPE", "orchestrator")

# Telegram message character limit
_TELEGRAM_MAX_LEN = 4096
# Gateway task input limit
_TASK_MAX_LEN = 4000


# ── Message handler ────────────────────────────────────────────────────────────


async def _stream_to_telegram(
    chat_id: int,
    reply_msg_id: int,
    on_token: asyncio.Queue,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """
    Consume the token queue and periodically edit the Telegram reply message.

    Edits at most once every MAX_EDIT_INTERVAL seconds to avoid rate limits.
    Telegram's edit API rate limit is ~20 edits/minute per chat.
    """
    accumulated = ""
    last_edit = 0.0
    done = False

    while not done:
        try:
            item = await asyncio.wait_for(on_token.get(), timeout=60.0)
        except asyncio.TimeoutError:
            break

        if isinstance(item, str):
            accumulated += item
        elif isinstance(item, dict):
            if item.get("done"):
                done = True
            elif "error" in item:
                accumulated += f"\n\n⚠️ {item['error']}"
                done = True

        now = time.monotonic()
        if done or (now - last_edit >= MAX_EDIT_INTERVAL and accumulated):
            display = accumulated or "*(working...)*"
            if not done:
                display += " ▌"
            if len(display) > _TELEGRAM_MAX_LEN:
                display = display[: _TELEGRAM_MAX_LEN - 3] + "..."

            try:
                await context.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=reply_msg_id,
                    text=display,
                )
                last_edit = now
            except Exception as exc:
                logger.warning(f"[telegram] Edit failed: {exc}")

    # Final edit
    final = accumulated or "*(no response)*"
    if len(final) > _TELEGRAM_MAX_LEN - 10:
        final = final[: _TELEGRAM_MAX_LEN - 13] + "..."
    if "⚠️" not in final:
        final += "\n✅"

    try:
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=reply_msg_id,
            text=final,
        )
    except Exception as exc:
        logger.warning(f"[telegram] Final edit failed: {exc}")


async def _handle_message(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    api_key: str,
) -> None:
    """Process an incoming Telegram message."""
    if not update.message or not update.message.text:
        return

    chat_id = update.message.chat_id
    text = update.message.text

    # Chat filter
    if ALLOWED_CHATS and chat_id not in ALLOWED_CHATS:
        return

    # Prefix filter
    if not text.startswith(PREFIX):
        return

    task_text = text[len(PREFIX) :].strip()
    if not task_text:
        await update.message.reply_text(
            f"Usage: `{PREFIX}<task>` — e.g. `{PREFIX}Research LLM safety in 2026`",
            parse_mode="Markdown",
        )
        return

    if len(task_text) > _TASK_MAX_LEN:
        await update.message.reply_text(
            f"Task too long ({len(task_text)} chars). Maximum is {_TASK_MAX_LEN}."
        )
        return

    logger.info(f"[telegram] Task from chat_id={chat_id} len={len(task_text)}")

    # Post initial reply
    reply = await update.message.reply_text("*Thinking...*", parse_mode="Markdown")

    # Run task + stream back concurrently
    on_token: asyncio.Queue = asyncio.Queue()
    await asyncio.gather(
        _run_task(
            task_text, api_key, GATEWAY_URL, AGENT_TYPE, on_token, action="telegram"
        ),
        _stream_to_telegram(chat_id, reply.message_id, on_token, context),
    )


# ── Entry point ────────────────────────────────────────────────────────────────


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    bot_token = _load_secret("legionforge_telegram_token", "TELEGRAM_BOT_TOKEN")
    api_key = _load_secret("legionforge_telegram_api_key", "TELEGRAM_GATEWAY_API_KEY")

    logger.info(
        f"[telegram] Starting connector "
        f"gateway={GATEWAY_URL} agent={AGENT_TYPE} prefix={PREFIX!r} "
        f"allowed_chats={ALLOWED_CHATS or 'all'}"
    )

    app = Application.builder().token(bot_token).build()

    # Wrap handler to inject api_key (closure)
    async def handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await _handle_message(update, context, api_key)

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handler))
    app.add_handler(MessageHandler(filters.COMMAND, handler))

    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
