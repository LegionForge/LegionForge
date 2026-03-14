"""
tests/ui/test_page_load.py
──────────────────────────
Playwright tests: page loads correctly, all required elements are present
and have the right initial state.

These tests do NOT submit tasks — they verify static structure and initial JS state.
"""

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


# ── Basic load ────────────────────────────────────────────────────────────────


def test_ui_title(page: Page):
    """Page title is 'LegionForge'."""
    expect(page).to_have_title("LegionForge")


def test_ui_header_text(page: Page):
    """Header contains 'LegionForge' h1 and 'agent gateway' subtitle."""
    h1 = page.locator("h1")
    expect(h1).to_contain_text("LegionForge")
    subtitle = page.locator(".subtitle")
    expect(subtitle).to_contain_text("agent gateway")


# ── Configuration card ────────────────────────────────────────────────────────


def test_ui_api_key_input_present(page: Page):
    """API key password input exists and is empty by default."""
    inp = page.locator("#api-key")
    expect(inp).to_be_visible()
    expect(inp).to_have_attribute("type", "password")
    assert inp.input_value() == ""


def test_ui_agent_type_select_present(page: Page):
    """Agent type <select> is visible with all three options."""
    sel = page.locator("#agent-type")
    expect(sel).to_be_visible()
    options = sel.locator("option").all()
    values = [o.get_attribute("value") for o in options]
    assert "orchestrator" in values
    assert "researcher" in values
    assert "base_agent" in values


def test_ui_agent_type_default_is_orchestrator(page: Page):
    """Default selected agent is 'orchestrator'."""
    sel = page.locator("#agent-type")
    assert sel.input_value() == "orchestrator"


# ── Task card ─────────────────────────────────────────────────────────────────


def test_ui_task_textarea_present(page: Page):
    """Task input textarea exists and is empty."""
    ta = page.locator("#task-input")
    expect(ta).to_be_visible()
    assert ta.input_value() == ""


def test_ui_submit_button_present_and_enabled(page: Page):
    """Submit button is visible and enabled on load."""
    btn = page.locator("#submit-btn")
    expect(btn).to_be_visible()
    expect(btn).to_be_enabled()


def test_ui_cancel_button_hidden_initially(page: Page):
    """Cancel button is hidden before any task is running."""
    btn = page.locator("#cancel-btn")
    expect(btn).to_be_hidden()


def test_ui_char_count_empty_initially(page: Page):
    """Character count is empty on load."""
    cc = page.locator("#char-count")
    assert cc.inner_text() == ""


def test_ui_char_count_updates_on_input(page: Page):
    """Typing in the task textarea updates the char count display."""
    page.fill("#task-input", "Hello world")
    cc = page.locator("#char-count")
    expect(cc).to_contain_text("11 chars")


# ── Output card ───────────────────────────────────────────────────────────────


def test_ui_output_has_ready_placeholder(page: Page):
    """Output area shows 'Ready.' placeholder on load."""
    out = page.locator("#output")
    expect(out).to_contain_text("Ready.")


def test_ui_status_indicator_empty_on_load(page: Page):
    """Status indicator and detail are empty on load."""
    assert page.locator("#status-indicator").inner_text() == ""
    assert page.locator("#status-detail").inner_text() == ""
    assert page.locator("#elapsed").inner_text() == ""


# ── History section ───────────────────────────────────────────────────────────


def test_ui_history_summary_shows_zero(page: Page):
    """History summary starts at 'History (0)'."""
    summary = page.locator("#history-summary")
    expect(summary).to_contain_text("History (0)")


def test_ui_history_empty_message_visible(page: Page):
    """History empty message is present (details closed by default)."""
    # Open the details element so we can see its contents
    page.locator("#history-section").evaluate("el => el.open = true")
    empty = page.locator("#history-empty")
    expect(empty).to_be_visible()
    expect(empty).to_contain_text("No tasks yet")


# ── Connection dot ────────────────────────────────────────────────────────────


def test_ui_conn_dot_present(page: Page):
    """Connection dot element is present (status indicator)."""
    dot = page.locator("#conn-dot")
    expect(dot).to_be_visible()
    # Initial state has no class (idle)
    cls = dot.get_attribute("class") or ""
    assert "live" not in cls
    assert "error" not in cls
