"""
tests/ui/test_history.py
────────────────────────
Playwright tests: localStorage persistence, history section updates,
API key restore on page reload.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page, BrowserContext, expect

from tests.ui.mock_server import MockGateway


pytestmark = pytest.mark.ui


# ── API key persistence ───────────────────────────────────────────────────────


def test_api_key_saved_to_localstorage(page: Page):
    """Typing an API key stores it in localStorage under 'lf_api_key'."""
    page.fill("#api-key", "my-secret-key-123")
    # localStorage.setItem is called on the input event
    value = page.evaluate("() => localStorage.getItem('lf_api_key')")
    assert value == "my-secret-key-123"


def test_api_key_restored_on_reload(page: Page, mock_gateway: MockGateway):
    """API key in localStorage is restored when the page reloads."""
    # Set the key
    page.fill("#api-key", "persistent-key-xyz")
    page.evaluate("() => localStorage.setItem('lf_api_key', 'persistent-key-xyz')")

    # Reload
    page.goto(mock_gateway.base_url + "/")
    page.wait_for_load_state("domcontentloaded")

    inp = page.locator("#api-key")
    assert inp.input_value() == "persistent-key-xyz"


def test_clear_api_key_removes_from_localstorage(page: Page):
    """Clicking the clear (✕) button removes the key from localStorage."""
    page.fill("#api-key", "key-to-clear")
    # Click the clear button (second ghost icon button in config card)
    page.locator("#config button.btn.ghost.icon").nth(1).click()

    value = page.evaluate("() => localStorage.getItem('lf_api_key')")
    assert value is None
    assert page.locator("#api-key").input_value() == ""


# ── History section ───────────────────────────────────────────────────────────


def test_history_count_increments_after_task(
    authed_page: Page, mock_gateway: MockGateway
):
    """History (N) counter increments after a task completes."""
    task_id = "history-test-001"
    mock_gateway.configure(
        next_task_id=task_id,
        task_result={"task_id": task_id, "status": "complete", "estimated_tokens": 10},
    )

    authed_page.fill("#task-input", "History increment test")
    authed_page.click("#submit-btn")
    mock_gateway.wait_for_submission(timeout=5.0)

    mock_gateway.emit(
        task_id, "task_start", {"task_id": task_id, "agent_type": "researcher"}
    )
    mock_gateway.emit(
        task_id, "task_complete", {"task_id": task_id, "status": "complete"}
    )
    mock_gateway.close_stream(task_id)

    # Wait for task to finish
    expect(authed_page.locator("#submit-btn")).to_be_enabled(timeout=8000)

    summary = authed_page.locator("#history-summary")
    expect(summary).to_contain_text("History (1)", timeout=3000)


def test_history_item_appears_in_list(authed_page: Page, mock_gateway: MockGateway):
    """After task completion a history entry appears in history-list."""
    task_id = "history-list-test-001"
    mock_gateway.configure(
        next_task_id=task_id,
        task_result={"task_id": task_id, "status": "complete", "estimated_tokens": 5},
    )

    task_text = "History list entry test"
    authed_page.fill("#task-input", task_text)
    authed_page.click("#submit-btn")
    mock_gateway.wait_for_submission(timeout=5.0)

    mock_gateway.emit(
        task_id, "task_start", {"task_id": task_id, "agent_type": "researcher"}
    )
    mock_gateway.emit(
        task_id, "task_complete", {"task_id": task_id, "status": "complete"}
    )
    mock_gateway.close_stream(task_id)

    expect(authed_page.locator("#submit-btn")).to_be_enabled(timeout=8000)

    # Open the history details section
    authed_page.locator("#history-section").evaluate("el => el.open = true")

    hist_list = authed_page.locator("#history-list")
    # history-empty should no longer be the only child
    expect(hist_list).to_contain_text(task_id[:8], timeout=3000)


def test_history_saved_to_localstorage(authed_page: Page, mock_gateway: MockGateway):
    """History is persisted to localStorage after a task completes."""
    task_id = "history-storage-test-001"
    mock_gateway.configure(
        next_task_id=task_id,
        task_result={"task_id": task_id, "status": "complete", "estimated_tokens": 3},
    )

    authed_page.fill("#task-input", "Storage persistence test")
    authed_page.click("#submit-btn")
    mock_gateway.wait_for_submission(timeout=5.0)

    mock_gateway.emit(
        task_id, "task_start", {"task_id": task_id, "agent_type": "researcher"}
    )
    mock_gateway.emit(
        task_id, "task_complete", {"task_id": task_id, "status": "complete"}
    )
    mock_gateway.close_stream(task_id)

    expect(authed_page.locator("#submit-btn")).to_be_enabled(timeout=8000)

    raw = authed_page.evaluate("() => localStorage.getItem('lf_history_v1')")
    assert raw is not None
    import json

    history = json.loads(raw)
    assert len(history) >= 1
    assert any(h.get("task_id") == task_id for h in history)


# ── Key toggle ────────────────────────────────────────────────────────────────


def test_key_toggle_shows_api_key(page: Page):
    """Eye button toggles API key input from password to text type."""
    page.fill("#api-key", "visible-key")
    inp = page.locator("#api-key")
    assert inp.get_attribute("type") == "password"

    # Click the toggle (first ghost icon in the config card)
    page.locator("#key-toggle").click()
    assert inp.get_attribute("type") == "text"

    # Click again to hide
    page.locator("#key-toggle").click()
    assert inp.get_attribute("type") == "password"
