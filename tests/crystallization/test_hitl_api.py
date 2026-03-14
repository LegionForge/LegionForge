"""
tests/crystallization/test_hitl_api.py
───────────────────────────────────────
Tests for the crystallization HITL review HTTP endpoints in src/health.py.

Uses Starlette TestClient (sync) with a patched health token and mocked
database functions.  No PostgreSQL or Keychain required.
"""

import pytest
from unittest.mock import AsyncMock, patch
from starlette.testclient import TestClient

# ── Test client fixture ───────────────────────────────────────────────────────

_TEST_TOKEN = "test-health-token-crystallization"


@pytest.fixture(scope="module")
def client():
    """Starlette TestClient for the health app with a fixed Bearer token."""
    # Patch _get_health_token before the app is imported so all requests
    # use a known token.
    with patch("src.health._get_health_token", return_value=_TEST_TOKEN):
        from src.health import app

        with TestClient(app, raise_server_exceptions=False) as c:
            yield c


@pytest.fixture()
def auth_headers():
    return {"Authorization": f"Bearer {_TEST_TOKEN}"}


# ── Sample data ───────────────────────────────────────────────────────────────

_READY_PACKAGE = {
    "package_id": "pkg_hitl000001",
    "candidate_id": "cand_hitl000001",
    "tool_name": "format_currency",
    "tool_description": "Format a numeric amount as a currency string.",
    "function_code": "def format_currency(amount, currency): return str(amount)",
    "function_signature": "def format_currency(amount: float, currency: str) -> str:",
    "status": "READY_FOR_REVIEW",
    "confidence_score": 0.9,
}

_PENDING_PACKAGE = {
    **_READY_PACKAGE,
    "package_id": "pkg_hitl_pending",
    "status": "PENDING_ANALYSIS",
}

_ANALYSIS = {
    "package_id": "pkg_hitl000001",
    "recommendation": "APPROVE",
    "test_cases_passed": 5,
    "test_cases_failed": 0,
    "security_clean": True,
    "risk_flags": [],
    "forbidden_constructs": [],
    "undeclared_dependencies": [],
}


# ── GET /crystallization/candidates ──────────────────────────────────────────


class TestListCandidates:
    def test_unauthenticated_returns_401(self, client):
        resp = client.get("/crystallization/candidates")
        assert resp.status_code == 401

    def test_authenticated_returns_200(self, client, auth_headers):
        with patch(
            "src.database.get_packages_ready_for_review",
            new=AsyncMock(return_value=[_READY_PACKAGE]),
        ):
            resp = client.get("/crystallization/candidates", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "packages" in body
        assert body["count"] >= 0

    def test_returns_only_ready_for_review_packages(self, client, auth_headers):
        with patch(
            "src.database.get_packages_ready_for_review",
            new=AsyncMock(return_value=[_READY_PACKAGE]),
        ):
            resp = client.get("/crystallization/candidates", headers=auth_headers)
        body = resp.json()
        pkgs = body.get("packages", [])
        for pkg in pkgs:
            assert (
                pkg.get("status") == "READY_FOR_REVIEW"
            ), f"Package {pkg.get('package_id')} has unexpected status: {pkg.get('status')}"

    def test_empty_db_returns_empty_list(self, client, auth_headers):
        with patch(
            "src.database.get_packages_ready_for_review",
            new=AsyncMock(return_value=[]),
        ):
            resp = client.get("/crystallization/candidates", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_db_failure_returns_503(self, client, auth_headers):
        with patch(
            "src.database.get_packages_ready_for_review",
            new=AsyncMock(side_effect=Exception("DB unavailable")),
        ):
            resp = client.get("/crystallization/candidates", headers=auth_headers)
        assert resp.status_code == 503


# ── GET /crystallization/candidates/{id} ─────────────────────────────────────


class TestGetCandidateDetail:
    def test_unauthenticated_returns_401(self, client):
        resp = client.get("/crystallization/candidates/pkg_hitl000001")
        assert resp.status_code == 401

    def test_existing_package_returns_200(self, client, auth_headers):
        with (
            patch(
                "src.database.get_package",
                new=AsyncMock(return_value=_READY_PACKAGE),
            ),
            patch(
                "src.database.get_analysis",
                new=AsyncMock(return_value=_ANALYSIS),
            ),
        ):
            resp = client.get(
                "/crystallization/candidates/pkg_hitl000001", headers=auth_headers
            )
        assert resp.status_code == 200
        body = resp.json()
        assert "package" in body
        assert "analysis" in body

    def test_nonexistent_package_returns_404(self, client, auth_headers):
        with patch(
            "src.database.get_package",
            new=AsyncMock(return_value=None),
        ):
            resp = client.get(
                "/crystallization/candidates/pkg_nonexistent", headers=auth_headers
            )
        assert resp.status_code == 404
        assert "error" in resp.json()

    def test_response_includes_review_actions(self, client, auth_headers):
        with (
            patch(
                "src.database.get_package",
                new=AsyncMock(return_value=_READY_PACKAGE),
            ),
            patch(
                "src.database.get_analysis",
                new=AsyncMock(return_value=_ANALYSIS),
            ),
        ):
            resp = client.get(
                "/crystallization/candidates/pkg_hitl000001", headers=auth_headers
            )
        body = resp.json()
        assert "review_actions" in body
        actions = body["review_actions"]
        assert "approve" in actions
        assert "reject" in actions
        assert "revise" in actions


# ── POST /crystallization/candidates/{id}/approve ────────────────────────────


class TestApproveCandidates:
    def test_unauthenticated_returns_401(self, client):
        resp = client.post("/crystallization/candidates/pkg_hitl000001/approve")
        assert resp.status_code == 401

    def test_approve_ready_package_returns_200(self, client, auth_headers):
        with (
            patch(
                "src.database.approve_package",
                new=AsyncMock(return_value=True),
            ),
            patch(
                "src.database.get_package",
                new=AsyncMock(return_value=_READY_PACKAGE),
            ),
            patch(
                "src.health._sign_and_register",
                new=AsyncMock(return_value={"status": "signed"}),
            ),
        ):
            resp = client.post(
                "/crystallization/candidates/pkg_hitl000001/approve",
                headers=auth_headers,
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body.get("status") == "approved"

    def test_approve_nonexistent_or_wrong_status_returns_404(
        self, client, auth_headers
    ):
        # approve_package returns False when package not found or wrong status
        with patch(
            "src.database.approve_package",
            new=AsyncMock(return_value=False),
        ):
            resp = client.post(
                "/crystallization/candidates/pkg_hitl_pending/approve",
                headers=auth_headers,
            )
        assert resp.status_code == 404
        assert "error" in resp.json()


# ── POST /crystallization/candidates/{id}/reject ─────────────────────────────


class TestRejectCandidates:
    def test_unauthenticated_returns_401(self, client):
        resp = client.post("/crystallization/candidates/pkg_hitl000001/reject")
        assert resp.status_code == 401

    def test_reject_with_reason_returns_200(self, client, auth_headers):
        with patch(
            "src.database.reject_package",
            new=AsyncMock(return_value=True),
        ):
            resp = client.post(
                "/crystallization/candidates/pkg_hitl000001/reject",
                headers=auth_headers,
                json={"reason": "Function is incorrect"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body.get("status") == "rejected"
        assert body.get("reason") == "Function is incorrect"

    def test_reject_without_body_returns_200(self, client, auth_headers):
        # Reason is optional — empty reason is valid
        with patch(
            "src.database.reject_package",
            new=AsyncMock(return_value=True),
        ):
            resp = client.post(
                "/crystallization/candidates/pkg_hitl000001/reject",
                headers=auth_headers,
            )
        assert resp.status_code == 200

    def test_reject_nonexistent_package_returns_404(self, client, auth_headers):
        with patch(
            "src.database.reject_package",
            new=AsyncMock(return_value=False),
        ):
            resp = client.post(
                "/crystallization/candidates/pkg_nonexistent/reject",
                headers=auth_headers,
                json={"reason": "Not valid"},
            )
        assert resp.status_code == 404


# ── POST /crystallization/candidates/{id}/revise ─────────────────────────────


class TestReviseCandidates:
    def test_unauthenticated_returns_401(self, client):
        resp = client.post("/crystallization/candidates/pkg_hitl000001/revise")
        assert resp.status_code == 401

    def test_revise_with_notes_returns_200(self, client, auth_headers):
        with patch(
            "src.database.revise_package",
            new=AsyncMock(return_value=True),
        ):
            resp = client.post(
                "/crystallization/candidates/pkg_hitl000001/revise",
                headers=auth_headers,
                json={"notes": "Handle empty string input"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body.get("status") == "sent_for_revision"
        assert "notes" in body

    def test_revise_nonexistent_package_returns_404(self, client, auth_headers):
        with patch(
            "src.database.revise_package",
            new=AsyncMock(return_value=False),
        ):
            resp = client.post(
                "/crystallization/candidates/pkg_nonexistent/revise",
                headers=auth_headers,
                json={"notes": "fix it"},
            )
        assert resp.status_code == 404

    def test_revise_includes_next_step_hint(self, client, auth_headers):
        with patch(
            "src.database.revise_package",
            new=AsyncMock(return_value=True),
        ):
            resp = client.post(
                "/crystallization/candidates/pkg_hitl000001/revise",
                headers=auth_headers,
                json={"notes": "edge case missing"},
            )
        body = resp.json()
        assert "next_step" in body
