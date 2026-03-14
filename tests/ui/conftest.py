"""
tests/ui/conftest.py
────────────────────
Pytest fixtures for Playwright UI tests.

Fixtures:
  mock_gateway  — session-scoped MockGateway server (started once per session)
  page          — Playwright page pre-navigated to the mock gateway's root URL
  fresh_page    — page with localStorage cleared (clean-slate per test)
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page, sync_playwright

from tests.ui.mock_server import MockGateway

# ── Server fixture (one per session) ──────────────────────────────────────────


@pytest.fixture(scope="session")
def mock_gateway():
    """Start the mock gateway once for the entire test session."""
    server = MockGateway(port=0)  # 0 → OS picks free port
    server.start()
    yield server
    server.stop()


# ── Playwright fixtures ────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def browser_session(mock_gateway):
    """Single browser process for the whole session (faster than per-test launch)."""
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        yield browser, mock_gateway
        browser.close()


@pytest.fixture
def page(browser_session):
    """
    A fresh browser context + page for each test.
    localStorage is cleared between tests automatically (new context).
    """
    browser, gateway = browser_session
    gateway.reset()
    context = browser.new_context(base_url=gateway.base_url)
    pg = context.new_page()
    pg.goto("/")
    pg.wait_for_load_state("domcontentloaded")
    yield pg
    context.close()


@pytest.fixture
def authed_page(page: Page, mock_gateway: MockGateway):
    """Page with the test API key pre-filled in the API key input."""
    page.fill("#api-key", mock_gateway._api_key)
    yield page
