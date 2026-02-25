"""
tests/conftest.py
─────────────────
Pytest configuration and shared fixtures.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (require running services)"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests requiring PostgreSQL and Ollama"
    )
    config.addinivalue_line(
        "markers", "unit: marks pure unit tests with no external dependencies"
    )

    # Inject a deterministic test secret for JWT task tokens so smoke tests that
    # exercise ACL/Guardian token validation never hit the macOS Keychain.
    # This is a test-only value — production always reads from Keychain.
    if not os.environ.get("TASK_TOKEN_SECRET"):
        os.environ.setdefault(
            "TASK_TOKEN_SECRET", "smoke-test-secret-for-legionforge-32!!"
        )


@pytest.fixture(scope="session")
def settings():
    from config.settings import settings as s

    return s
