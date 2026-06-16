"""
src/connectors/base.py
──────────────────────
Shared helpers used by all LegionForge channel connectors.

Extracted from discord.py so Telegram, Slack, and Webhook connectors
don't duplicate secret-loading and SSE-parsing logic.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
from typing import AsyncGenerator

import httpx

logger = logging.getLogger(__name__)


# ── Secret loader ─────────────────────────────────────────────────────────────


def _load_secret(keychain_service: str, env_var: str) -> str:
    """
    Load a secret from Keychain (preferred) or environment variable.
    Raises RuntimeError if neither source has the value.

    Args:
        keychain_service: macOS Keychain service name (account = "api_key").
        env_var:          Fallback environment variable name.
    """
    # `keychain_service` is a connector-internal constant string (passed by the
    # caller from a static registry, never user-controlled). `security` is the
    # macOS Keychain CLI at /usr/bin/security.
    try:
        result = subprocess.run(  # nosec B603 B607
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
    gateway_url: str,
) -> AsyncGenerator[dict, None]:
    """
    Consume an SSE stream from the gateway using httpx streaming.

    Parses the raw SSE line format::

        event: token
        data: {"delta": "hello"}

    Yields parsed event dicts: ``{"event": "token", "data": {...}}``

    Args:
        client:       Open httpx.AsyncClient (caller manages lifecycle).
        stream_url:   Path portion of the stream URL (e.g. ``/tasks/abc/stream``).
        stream_token: Short-lived stream token returned by POST /tasks.
        gateway_url:  Gateway base URL (e.g. ``http://localhost:8080``).
    """
    url = f"{gateway_url}{stream_url}?stream_token={stream_token}"
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
                if data_lines:
                    raw = " ".join(data_lines)
                    try:
                        data = json.loads(raw) if raw else {}
                    except json.JSONDecodeError:
                        data = {"raw": raw}
                    yield {"event": event_type, "data": data}
                event_type = "message"
                data_lines = []


# ── Task runner (submit + stream) ─────────────────────────────────────────────


async def _run_task(
    task_text: str,
    api_key: str,
    gateway_url: str,
    agent_type: str,
    on_token: asyncio.Queue,
    action: str = "channel",
) -> None:
    """
    Submit a task to the gateway and push token/status events to ``on_token``.

    Puts string tokens for accumulated text, or sentinel dicts:

    - ``{"done": True, "result_url": "..."}`` on task_complete
    - ``{"error": "..."}`` on task_error / task_cancelled

    Args:
        task_text:   Raw task string from the user.
        api_key:     Gateway Bearer API key.
        gateway_url: Gateway base URL.
        agent_type:  Agent type (orchestrator / researcher / base_agent).
        on_token:    asyncio.Queue to push events into.
        action:      Source label for audit logs (e.g. "telegram", "slack", "webhook").
    """
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(base_url=gateway_url, timeout=30.0) as client:
        resp = await client.post(
            "/tasks",
            json={
                "task": task_text,
                "agent_type": agent_type,
                "config": {"tracing_enabled": True, "action": action},
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

        logger.info(f"[{action}] Task queued task_id={task_id}")

        try:
            async with httpx.AsyncClient(timeout=300.0) as stream_client:
                async for event in _consume_sse(
                    stream_client, stream_url, stream_token, gateway_url
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

        except httpx.HTTPError as exc:
            await on_token.put({"error": f"Stream connection failed: {exc}"})
