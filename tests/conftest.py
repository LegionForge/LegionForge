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


@pytest.fixture(scope="session")
def settings():
    from config.settings import settings as s

    return s
