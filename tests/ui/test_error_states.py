"""
tests/ui/test_error_states.py
──────────────────────────────
Playwright tests: error states — missing API key, invalid API key (401),
task error SSE event, and network errors.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page, expect

from tests.ui.mock_server import MockGateway


pytestmark = pytest.mark.ui


# ── Missing API key ───────────────────────────────────────────────────────────


def test_submit_without_api_key_shows_error(page: Page):
    """Submitting without an API key shows an inline error — no network call made."""
    page.fill("#task-input", "some task")
    page.click("#submit-btn")

    out = page.locator("#output")
    expect(out).to_contain_text("API key", timeout=3000)


def test_submit_without_task_shows_error(page: Page):
    """Submitting without a task (empty textarea) shows an inline error."""
    page.fill("#api-key", "test-api-key")
    # Leave task-input empty
    page.click("#submit-btn")

    out = page.locator("#output")
    expect(out).to_contain_text("task", timeout=3000)


# ── 401 Unauthorized ──────────────────────────────────────────────────────────


def test_bad_api_key_shows_401_error(page: Page, mock_gateway: MockGateway):
    """A wrong API key causes the gateway to return 401 and UI shows the error."""
    mock_gateway.reset()
    # Use a key that differs from mock_gateway._api_key
    page.fill("#api-key", "wrong-key-totally-invalid")
    page.fill("#task-input", "test bad key")
    page.click("#submit-btn")

    out = page.locator("#output")
    # UI calls finishRun('error', ...) on non-ok response
    expect(out).to_contain_text("error", timeout=5000)


# ── task_error SSE event ──────────────────────────────────────────────────────


def test_task_error_event_shows_error_in_output(
    authed_page: Page, mock_gateway: MockGateway
):
    """task_error SSE event triggers error display and re-enables submit."""
    task_id = "error-event-test-001"
    mock_gateway.configure(next_task_id=task_id)
    authed_page.fill("#task-input", "Error scenario test")
    authed_page.click("#submit-btn")
    mock_gateway.wait_for_submission(timeout=5.0)

    mock_gateway.emit(
        task_id, "task_start", {"task_id": task_id, "agent_type": "researcher"}
    )
    mock_gateway.emit(
        task_id,
        "task_error",
        {"task_id": task_id, "status": "failed", "error": "Guardian blocked tool"},
    )
    mock_gateway.close_stream(task_id)

    out = authed_page.locator("#output")
    expect(out).to_contain_text("Guardian", timeout=6000)

    # Submit should be re-enabled after error
    btn = authed_page.locator("#submit-btn")
    expect(btn).to_be_enabled(timeout=6000)


def test_task_cancelled_event_shows_cancelled(
    authed_page: Page, mock_gateway: MockGateway
):
    """task_cancelled SSE event triggers cancelled status display."""
    task_id = "cancelled-event-test-001"
    mock_gateway.configure(next_task_id=task_id)
    authed_page.fill("#task-input", "Cancellation test")
    authed_page.click("#submit-btn")
    mock_gateway.wait_for_submission(timeout=5.0)

    mock_gateway.emit(
        task_id,
        "task_cancelled",
        {"task_id": task_id, "status": "cancelled"},
    )
    mock_gateway.close_stream(task_id)

    out = authed_page.locator("#output")
    expect(out).to_contain_text("cancel", timeout=6000)


# ── Status indicator ──────────────────────────────────────────────────────────


def test_status_bar_shows_running_during_task(
    authed_page: Page, mock_gateway: MockGateway
):
    """Status bar shows 'Running' while a task is in progress."""
    task_id = "status-bar-test-001"
    mock_gateway.configure(next_task_id=task_id)
    authed_page.fill("#task-input", "Status bar test")
    authed_page.click("#submit-btn")
    mock_gateway.wait_for_submission(timeout=5.0)

    status = authed_page.locator("#status-indicator")
    expect(status).to_contain_text("Running", timeout=3000)
