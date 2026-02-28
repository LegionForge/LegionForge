"""
src/connectors/slack.py
────────────────────────
Slack Socket Mode connector for LegionForge.

Bridges Slack messages to the gateway API and streams responses back to the
channel as the agent generates them (update-in-place, throttled).

Socket Mode means no public URL is required — the bot connects outbound via
Slack's WebSocket API, which works behind NAT/firewall on self-hosted setups.

Flow:
    Slack message starting with PREFIX (default "!") in allowed channels
        → POST /tasks  (gateway, as slack-bot user)
        → subscribe SSE stream (httpx streaming)
        → update Slack message every MAX_EDIT_INTERVAL seconds
        → final update on task_complete / task_error

Security:
    - The bot authenticates to the gateway as a dedicated 'slack-bot' user
      with no operator access.
    - action="slack" is set so Guardian and audit logs identify the source.
    - Input length is capped at 4000 chars before submission.
    - Only responds to SLACK_ALLOWED_CHANNELS (empty = all, not recommended).
    - Secrets stored in macOS Keychain — never in env files.

Setup (one-time):
    1. Create a Slack App at https://api.slack.com/apps
       Enable: Socket Mode, Event Subscriptions (message.channels + app_mention)
       Add Bot Token Scopes: chat:write, channels:history
    2. Generate an App-level token with scope connections:write (xapp-...).
    3. Store secrets in Keychain:
         security add-generic-password -s legionforge_slack_bot_token -a api_key -w 'xoxb-...'
         security add-generic-password -s legionforge_slack_app_token -a api_key -w 'xapp-...'
    4. Create the gateway user:
         make create-user USERNAME=slack-bot
    5. Store the gateway API key:
         security add-generic-password -s legionforge_slack_api_key -a api_key -w '<key>'
    6. Set allowed channels (recommended):
         export SLACK_ALLOWED_CHANNELS=C01234567,C09876543
    7. Start the connector:
         make slack-start

Environment / Keychain:
    legionforge_slack_bot_token  — Slack bot token (xoxb-...) (Keychain, required)
    legionforge_slack_app_token  — App-level token for Socket Mode (xapp-...) (Keychain, required)
    legionforge_slack_api_key    — Gateway Bearer API key (Keychain, required)
    SLACK_GATEWAY_URL            — default http://localhost:8080
    SLACK_ALLOWED_CHANNELS       — comma-separated channel IDs (empty = all, not recommended)
    SLACK_PREFIX                 — command prefix, default "!" (e.g. "!research ...")
    SLACK_MAX_EDIT_INTERVAL      — seconds between message updates, default 2.0
    SLACK_AGENT_TYPE             — default "orchestrator"
"""

from __future__ import annotations

import asyncio
import logging
import os
import time

from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler

from src.connectors.base import _load_secret, _run_task

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────

GATEWAY_URL = os.environ.get("SLACK_GATEWAY_URL", "http://localhost:8080")
ALLOWED_CHANNELS: set[str] = {
    c.strip()
    for c in os.environ.get("SLACK_ALLOWED_CHANNELS", "").split(",")
    if c.strip()
}
PREFIX = os.environ.get("SLACK_PREFIX", "!")
MAX_EDIT_INTERVAL = float(os.environ.get("SLACK_MAX_EDIT_INTERVAL", "2.0"))
AGENT_TYPE = os.environ.get("SLACK_AGENT_TYPE", "orchestrator")

# Slack block text limit
_SLACK_MAX_LEN = 3000
# Gateway task input limit
_TASK_MAX_LEN = 4000


# ── Message streaming ──────────────────────────────────────────────────────────


async def _stream_to_slack(
    client,
    channel: str,
    ts: str,
    on_token: asyncio.Queue,
) -> None:
    """
    Consume the token queue and periodically update the Slack message.

    Uses chat.update to edit the original placeholder message in place.
    Rate-limited to at most once per MAX_EDIT_INTERVAL seconds.
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
            display = accumulated or "_(working...)_"
            if not done:
                display += " ▌"
            if len(display) > _SLACK_MAX_LEN:
                display = display[: _SLACK_MAX_LEN - 3] + "..."

            try:
                await client.chat_update(
                    channel=channel,
                    ts=ts,
                    text=display,
                )
                last_edit = now
            except Exception as exc:
                logger.warning(f"[slack] Update failed: {exc}")

    # Final update
    final = accumulated or "_(no response)_"
    if len(final) > _SLACK_MAX_LEN - 10:
        final = final[: _SLACK_MAX_LEN - 13] + "..."
    if "⚠️" not in final:
        final += "\n✅"

    try:
        await client.chat_update(channel=channel, ts=ts, text=final)
    except Exception as exc:
        logger.warning(f"[slack] Final update failed: {exc}")


# ── App setup ──────────────────────────────────────────────────────────────────


def _build_app(bot_token: str, api_key: str) -> AsyncApp:
    """Build and configure the Slack bolt application."""
    app = AsyncApp(token=bot_token)

    @app.message()
    async def handle_message(message, say, client) -> None:
        channel_id = message.get("channel", "")
        text = message.get("text", "") or ""
        user = message.get("user", "unknown")

        # Channel filter
        if ALLOWED_CHANNELS and channel_id not in ALLOWED_CHANNELS:
            return

        # Prefix filter
        if not text.startswith(PREFIX):
            return

        task_text = text[len(PREFIX) :].strip()
        if not task_text:
            await say(
                f"Usage: `{PREFIX}<task>` — e.g. `{PREFIX}Research LLM safety in 2026`"
            )
            return

        if len(task_text) > _TASK_MAX_LEN:
            await say(
                f"Task too long ({len(task_text)} chars). Maximum is {_TASK_MAX_LEN}."
            )
            return

        logger.info(
            f"[slack] Task from user={user} channel={channel_id} len={len(task_text)}"
        )

        # Post initial placeholder
        response = await say("_Thinking..._")
        ts = response.get("ts")

        # Run task + stream back concurrently
        on_token: asyncio.Queue = asyncio.Queue()
        await asyncio.gather(
            _run_task(
                task_text, api_key, GATEWAY_URL, AGENT_TYPE, on_token, action="slack"
            ),
            _stream_to_slack(client, channel_id, ts, on_token),
        )

    return app


# ── Entry point ────────────────────────────────────────────────────────────────


async def _main_async(bot_token: str, app_token: str, api_key: str) -> None:
    app = _build_app(bot_token, api_key)
    handler = AsyncSocketModeHandler(app, app_token)
    logger.info(
        f"[slack] Starting Socket Mode connector "
        f"gateway={GATEWAY_URL} agent={AGENT_TYPE} prefix={PREFIX!r} "
        f"allowed_channels={ALLOWED_CHANNELS or 'all'}"
    )
    await handler.start_async()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    bot_token = _load_secret("legionforge_slack_bot_token", "SLACK_BOT_TOKEN")
    app_token = _load_secret("legionforge_slack_app_token", "SLACK_APP_TOKEN")
    api_key = _load_secret("legionforge_slack_api_key", "SLACK_GATEWAY_API_KEY")

    asyncio.run(_main_async(bot_token, app_token, api_key))


if __name__ == "__main__":
    main()
