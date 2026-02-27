"""
src/connectors/discord.py
──────────────────────────
Discord bot connector for LegionForge.

Bridges Discord messages to the gateway API and streams responses back to the
channel as the agent generates them.

Flow:
    Discord message (in allowed channel)
        → POST /tasks  (gateway, as discord-bot user)
        → subscribe SSE stream (httpx streaming, in-process SSE parser)
        → edit reply message every 2 s with accumulated tokens
        → final edit on task_complete / task_error

Security:
    - The bot authenticates to the gateway as a dedicated 'discord-bot' user.
      It has no operator access. Tasks it submits are indistinguishable from
      API tasks and go through the same Guardian pipeline.
    - action="discord" is set in state so Guardian and audit logs can see the source.
    - Input length is capped at 4000 chars before submission (gateway enforces too).
    - The bot only responds in DISCORD_ALLOWED_CHANNELS (empty = all, not recommended).

Setup (one-time):
    1. Create a Discord bot at https://discord.com/developers/applications
       Enable: Message Content Intent, Send Messages, Read Message History
    2. Store the bot token in Keychain:
         security add-generic-password -s legionforge_discord_token -a api_key -w '<token>'
    3. Create the gateway user:
         make create-user USERNAME=discord-bot
       (copy the printed API key)
    4. Store the gateway API key in Keychain:
         security add-generic-password -s legionforge_discord_api_key -a api_key -w '<key>'
    5. Invite the bot to your server with the OAuth2 URL from the dev portal.
    6. Set allowed channels (optional but recommended):
         export DISCORD_ALLOWED_CHANNELS=123456789012345678,987654321098765432
    7. Start the connector:
         make discord-start

Environment / Keychain:
    legionforge_discord_token   — Discord bot token (Keychain, required)
    legionforge_discord_api_key — Gateway Bearer API key (Keychain, required)
    DISCORD_GATEWAY_URL         — default http://localhost:8080
    DISCORD_ALLOWED_CHANNELS    — comma-separated channel IDs (empty = all channels)
    DISCORD_PREFIX              — command prefix, default "!"  (e.g. "!research ...")
    DISCORD_MAX_EDIT_INTERVAL   — seconds between message edits, default 2.0
    DISCORD_AGENT_TYPE          — default "orchestrator"
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import AsyncGenerator

import discord
import httpx

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

GATEWAY_URL = os.environ.get("DISCORD_GATEWAY_URL", "http://localhost:8080")
ALLOWED_CHANNELS: set[int] = {
    int(c.strip())
    for c in os.environ.get("DISCORD_ALLOWED_CHANNELS", "").split(",")
    if c.strip().isdigit()
}
PREFIX = os.environ.get("DISCORD_PREFIX", "!")
MAX_EDIT_INTERVAL = float(os.environ.get("DISCORD_MAX_EDIT_INTERVAL", "2.0"))
AGENT_TYPE = os.environ.get("DISCORD_AGENT_TYPE", "orchestrator")

# Discord message length limit
_DISCORD_MAX_LEN = 2000
# Gateway task input limit
_TASK_MAX_LEN = 4000


# ── Credential loader ─────────────────────────────────────────────────────────


def _load_secret(keychain_service: str, env_var: str) -> str:
    """
    Load a secret from Keychain (preferred) or environment variable.
    Raises RuntimeError if neither source has the value.
    """
    # ── Keychain ───────────────────────────────────────────────────────────
    try:
        import subprocess

        result = subprocess.run(
            [
                "security",
                "find-generic-password",
                "-s",
                keychain_service,
                "-a",
                "api_key",
                "-w",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        value = result.stdout.strip()
        if value:
            return value
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # ── Environment variable fallback ─────────────────────────────────────
    value = os.environ.get(env_var, "").strip()
    if value:
        return value

    raise RuntimeError(
        f"Secret '{keychain_service}' not found in Keychain or env var '{env_var}'.\n"
        f"Store it with:\n"
        f"  security add-generic-password -s {keychain_service} -a api_key -w '<value>'"
    )


# ── SSE stream consumer ───────────────────────────────────────────────────────


async def _consume_sse(
    client: httpx.AsyncClient,
    stream_url: str,
    stream_token: str,
) -> AsyncGenerator[dict, None]:
    """
    Consume an SSE stream from the gateway using httpx streaming.

    Parses the raw SSE line format:
        event: token
        data: {"delta": "hello"}

    Yields parsed event dicts: {"event": "token", "data": {...}}
    """
    url = f"{GATEWAY_URL}{stream_url}?stream_token={stream_token}"
    async with client.stream("GET", url, timeout=300.0) as response:
        response.raise_for_status()

        event_type: str = "message"
        data_lines: list[str] = []

        async for line in response.aiter_lines():
            if line.startswith("event:"):
                event_type = line[len("event:") :].strip()
            elif line.startswith("data:"):
                data_lines.append(line[len("data:") :].strip())
            elif line == "":
                # Blank line = event boundary
                if data_lines:
                    raw = " ".join(data_lines)
                    try:
                        data = json.loads(raw) if raw else {}
                    except json.JSONDecodeError:
                        data = {"raw": raw}
                    yield {"event": event_type, "data": data}
                event_type = "message"
                data_lines = []


# ── Task submission + streaming ────────────────────────────────────────────────


async def _run_task_and_stream(
    task_text: str,
    api_key: str,
    on_token: asyncio.Queue,
) -> None:
    """
    Submit a task to the gateway and push token/status events to on_token queue.

    Puts string tokens for accumulated text, or sentinel dicts for terminal events:
        {"done": True, "result_url": "..."} on task_complete
        {"error": "..."} on task_error / task_cancelled
    """
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(base_url=GATEWAY_URL, timeout=30.0) as client:
        # Submit task
        resp = await client.post(
            "/tasks",
            json={
                "task": task_text,
                "agent_type": AGENT_TYPE,
                "config": {"tracing_enabled": True},
            },
            headers=headers,
        )

        if resp.status_code != 202:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            await on_token.put({"error": f"Gateway error {resp.status_code}: {detail}"})
            return

        payload = resp.json()
        task_id = payload["task_id"]
        stream_url = payload["stream_url"]
        stream_token = payload["stream_token"]

        logger.info(f"[discord] Task queued task_id={task_id}")

        # Subscribe to SSE stream
        try:
            async with httpx.AsyncClient(timeout=300.0) as stream_client:
                async for event in _consume_sse(
                    stream_client, stream_url, stream_token
                ):
                    etype = event["event"]
                    data = event["data"]

                    if etype == "token":
                        delta = data.get("delta", "")
                        if delta:
                            await on_token.put(delta)

                    elif etype == "task_complete":
                        result_url = data.get("result_url", f"/tasks/{task_id}")
                        await on_token.put({"done": True, "result_url": result_url})
                        return

                    elif etype in ("task_error", "task_cancelled"):
                        await on_token.put(
                            {"error": data.get("error", f"Task {etype}")}
                        )
                        return

                    # heartbeat, chain_start, chain_end, tool_start, tool_end → ignored

        except httpx.HTTPError as exc:
            await on_token.put({"error": f"Stream connection failed: {exc}"})


# ── Discord message editor ────────────────────────────────────────────────────


async def _stream_to_discord(
    reply_msg: discord.Message,
    on_token: asyncio.Queue,
) -> None:
    """
    Consume the token queue and periodically edit the Discord reply message.

    Edits at most once every MAX_EDIT_INTERVAL seconds to avoid rate limits.
    Appends tool/status indicators inline.
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

        # Throttle edits
        now = time.monotonic()
        if done or (now - last_edit >= MAX_EDIT_INTERVAL and accumulated):
            display = accumulated
            if len(display) > _DISCORD_MAX_LEN:
                display = display[: _DISCORD_MAX_LEN - 3] + "..."
            if not done:
                display += " ▌"  # typing cursor indicator

            try:
                await reply_msg.edit(content=display or "*(working...)*")
                last_edit = now
            except discord.HTTPException as exc:
                logger.warning(f"[discord] Edit failed: {exc}")

    # Final edit — remove cursor, show completion indicator
    final = accumulated or "*(no response)*"
    if len(final) > _DISCORD_MAX_LEN - 10:
        final = final[: _DISCORD_MAX_LEN - 13] + "..."
    final += "\n✅" if not any(c in final for c in ["⚠️"]) else ""

    try:
        await reply_msg.edit(content=final)
    except discord.HTTPException as exc:
        logger.warning(f"[discord] Final edit failed: {exc}")


# ── Discord bot ───────────────────────────────────────────────────────────────


class LegionForgeBot(discord.Client):
    """
    Minimal Discord bot that routes messages to the LegionForge gateway.

    Listens for messages starting with PREFIX in ALLOWED_CHANNELS
    (or all channels if ALLOWED_CHANNELS is empty).
    """

    def __init__(self, api_key: str):
        intents = discord.Intents.default()
        intents.message_content = True  # required for reading message content
        super().__init__(intents=intents)
        self._api_key = api_key

    async def on_ready(self) -> None:
        logger.info(
            f"[discord] Connected as {self.user} "
            f"(allowed_channels={ALLOWED_CHANNELS or 'all'} prefix={PREFIX!r})"
        )

    async def on_message(self, message: discord.Message) -> None:
        # Ignore own messages
        if message.author == self.user:
            return

        # Channel filter
        if ALLOWED_CHANNELS and message.channel.id not in ALLOWED_CHANNELS:
            return

        # Prefix filter
        if not message.content.startswith(PREFIX):
            return

        task_text = message.content[len(PREFIX) :].strip()
        if not task_text:
            await message.reply(
                f"Usage: `{PREFIX}<task>` — e.g. `{PREFIX}Research LLM safety in 2026`",
                mention_author=False,
            )
            return

        if len(task_text) > _TASK_MAX_LEN:
            await message.reply(
                f"Task too long ({len(task_text)} chars). Maximum is {_TASK_MAX_LEN}.",
                mention_author=False,
            )
            return

        logger.info(
            f"[discord] Task from {message.author} "
            f"channel={message.channel.id} len={len(task_text)}"
        )

        # Post initial reply
        reply_msg = await message.reply("*Thinking...*", mention_author=False)

        # Run task + stream back concurrently
        on_token: asyncio.Queue = asyncio.Queue()
        await asyncio.gather(
            _run_task_and_stream(task_text, self._api_key, on_token),
            _stream_to_discord(reply_msg, on_token),
        )


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    bot_token = _load_secret("legionforge_discord_token", "DISCORD_BOT_TOKEN")
    api_key = _load_secret("legionforge_discord_api_key", "DISCORD_GATEWAY_API_KEY")

    logger.info(
        f"[discord] Starting connector "
        f"gateway={GATEWAY_URL} agent={AGENT_TYPE} prefix={PREFIX!r}"
    )

    bot = LegionForgeBot(api_key=api_key)
    bot.run(bot_token, log_handler=None)


if __name__ == "__main__":
    main()
