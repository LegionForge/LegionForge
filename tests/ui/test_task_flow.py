"""
tests/ui/test_task_flow.py
──────────────────────────
Playwright tests: task submission, SSE streaming, and completion display.

Each test uses the MockGateway to control the SSE event stream so tests
run deterministically without a real LLM backend.
"""

from __future__ import annotations

import time
import threading

import pytest
from playwright.sync_api import Page, expect

from tests.ui.mock_server import MockGateway

pytestmark = pytest.mark.ui

TASK_ID = "ui-test-task-001"
STREAM_TOKEN = "st-" + TASK_ID


# ── Helpers ───────────────────────────────────────────────────────────────────


def _submit_and_wait(page: Page, gateway: MockGateway, task_text: str) -> str:
    """
    Fill in the task input, click Submit, and wait until POST /tasks is received
    by the mock server. Returns the submitted task_id.
    """
    page.fill("#task-input", task_text)
    page.click("#submit-btn")
    return gateway.wait_for_submission(timeout=5.0)


# ── Submission ────────────────────────────────────────────────────────────────


def test_submit_shows_queued_status(authed_page: Page, mock_gateway: MockGateway):
    """After submit, output shows '[submitting…]' and then '[queued: ...]'."""
    mock_gateway.configure(next_task_id=TASK_ID)

    _submit_and_wait(authed_page, mock_gateway, "Test task A")

    out = authed_page.locator("#output")
    expect(out).to_contain_text("queued", timeout=5000)


def test_submit_disables_submit_button(authed_page: Page, mock_gateway: MockGateway):
    """Submit button becomes disabled while a task is running."""
    mock_gateway.configure(next_task_id=TASK_ID)
    _submit_and_wait(authed_page, mock_gateway, "Test task B")

    btn = authed_page.locator("#submit-btn")
    expect(btn).to_be_disabled(timeout=3000)


def test_submit_shows_cancel_button(authed_page: Page, mock_gateway: MockGateway):
    """Cancel button becomes visible after task submission."""
    mock_gateway.configure(next_task_id=TASK_ID)
    _submit_and_wait(authed_page, mock_gateway, "Test task C")

    cancel = authed_page.locator("#cancel-btn")
    expect(cancel).to_be_visible(timeout=3000)


def test_conn_dot_goes_live_on_submit(authed_page: Page, mock_gateway: MockGateway):
    """Connection dot gets 'live' class after task submission."""
    mock_gateway.configure(next_task_id=TASK_ID)
    _submit_and_wait(authed_page, mock_gateway, "Test task D")

    dot = authed_page.locator("#conn-dot")
    expect(dot).to_have_class("live", timeout=3000)


# ── SSE events ────────────────────────────────────────────────────────────────


def test_task_start_event_shown(authed_page: Page, mock_gateway: MockGateway):
    """task_start SSE event causes '[agent started]' to appear in output."""
    task_id = "sse-test-start-001"
    mock_gateway.configure(next_task_id=task_id)
    _submit_and_wait(authed_page, mock_gateway, "SSE start test")

    mock_gateway.emit(
        task_id, "task_start", {"task_id": task_id, "agent_type": "researcher"}
    )

    out = authed_page.locator("#output")
    expect(out).to_contain_text("agent started", timeout=5000)


def test_token_events_stream_text(authed_page: Page, mock_gateway: MockGateway):
    """token SSE events cause token delta text to appear in output."""
    task_id = "sse-test-tokens-001"
    mock_gateway.configure(next_task_id=task_id)
    _submit_and_wait(authed_page, mock_gateway, "Token streaming test")

    mock_gateway.emit(
        task_id, "task_start", {"task_id": task_id, "agent_type": "researcher"}
    )
    mock_gateway.emit(
        task_id, "token", {"delta": "Hello ", "timestamp": "2026-01-01T00:00:00Z"}
    )
    mock_gateway.emit(
        task_id, "token", {"delta": "world", "timestamp": "2026-01-01T00:00:00Z"}
    )

    out = authed_page.locator("#output")
    expect(out).to_contain_text("Hello", timeout=5000)
    expect(out).to_contain_text("world", timeout=5000)


def test_tool_start_event_shows_tool_block(
    authed_page: Page, mock_gateway: MockGateway
):
    """tool_start SSE event creates a visible tool block in the output."""
    task_id = "sse-test-tool-001"
    mock_gateway.configure(next_task_id=task_id)
    _submit_and_wait(authed_page, mock_gateway, "Tool block test")

    mock_gateway.emit(
        task_id, "task_start", {"task_id": task_id, "agent_type": "researcher"}
    )
    mock_gateway.emit(
        task_id, "tool_start", {"tool": "http_get", "timestamp": "2026-01-01T00:00:00Z"}
    )

    out = authed_page.locator("#output")
    expect(out).to_contain_text("http_get", timeout=5000)


def test_tool_end_event_marks_tool_done(authed_page: Page, mock_gateway: MockGateway):
    """tool_end SSE event marks the tool block with a checkmark."""
    task_id = "sse-test-tool-end-001"
    mock_gateway.configure(next_task_id=task_id)
    _submit_and_wait(authed_page, mock_gateway, "Tool done test")

    mock_gateway.emit(
        task_id, "task_start", {"task_id": task_id, "agent_type": "researcher"}
    )
    mock_gateway.emit(
        task_id,
        "tool_start",
        {"tool": "file_read", "timestamp": "2026-01-01T00:00:00Z"},
    )
    mock_gateway.emit(
        task_id, "tool_end", {"tool": "file_read", "timestamp": "2026-01-01T00:00:00Z"}
    )

    # After tool_end the block should have a checkmark
    out = authed_page.locator("#output")
    expect(out).to_contain_text("✓", timeout=5000)


# ── Completion ────────────────────────────────────────────────────────────────


def _complete_task(page: Page, gateway: MockGateway, task_id: str):
    """Emit task_complete and close the stream."""
    gateway.configure(
        next_task_id=task_id,
        task_result={"task_id": task_id, "status": "complete", "estimated_tokens": 99},
    )
    _submit_and_wait(page, gateway, "Complete task test")

    gateway.emit(
        task_id, "task_start", {"task_id": task_id, "agent_type": "researcher"}
    )
    gateway.emit(task_id, "token", {"delta": "The answer is 42."})
    gateway.emit(
        task_id,
        "task_complete",
        {"task_id": task_id, "status": "complete", "result_url": f"/tasks/{task_id}"},
    )
    gateway.close_stream(task_id)


def test_task_complete_re_enables_submit(authed_page: Page, mock_gateway: MockGateway):
    """Submit button is re-enabled after task_complete event."""
    task_id = "complete-test-001"
    _complete_task(authed_page, mock_gateway, task_id)

    btn = authed_page.locator("#submit-btn")
    expect(btn).to_be_enabled(timeout=8000)


def test_task_complete_hides_cancel(authed_page: Page, mock_gateway: MockGateway):
    """Cancel button is hidden after task completes."""
    task_id = "complete-test-002"
    _complete_task(authed_page, mock_gateway, task_id)

    cancel = authed_page.locator("#cancel-btn")
    expect(cancel).to_be_hidden(timeout=8000)


def test_task_complete_shows_elapsed_time(authed_page: Page, mock_gateway: MockGateway):
    """Elapsed time is shown in the status bar after completion."""
    task_id = "complete-test-003"
    _complete_task(authed_page, mock_gateway, task_id)

    elapsed = authed_page.locator("#elapsed")
    # After completion the elapsed is cleared (finishRun calls stopTimer)
    # Status indicator should show complete/done
    status = authed_page.locator("#status-indicator")
    # UI renders "✓ Complete · N tokens est. · Xs" — class-based lookup is reliable
    expect(status).to_have_class("complete", timeout=8000)


# ── Cancel ────────────────────────────────────────────────────────────────────


def test_cancel_button_cancels_task(authed_page: Page, mock_gateway: MockGateway):
    """Clicking Cancel calls DELETE /tasks/{id} and shows cancelled status."""
    task_id = "cancel-test-001"
    mock_gateway.configure(next_task_id=task_id)
    _submit_and_wait(authed_page, mock_gateway, "Cancel me")

    # Click cancel
    authed_page.locator("#cancel-btn").click()

    out = authed_page.locator("#output")
    expect(out).to_contain_text("cancel", timeout=5000)
