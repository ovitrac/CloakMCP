"""
API endpoint tests for CloakMCP server

Tests the FastAPI server endpoints:
- /health (GET)
- /sanitize (POST)
- /scan (POST)
- Authentication (Bearer token)
- Error handling

Run: pytest -v tests/test_api.py
"""

from __future__ import annotations
import importlib
import os
import pytest
import tempfile
from pathlib import Path

TEST_TOKEN = "test_token_1234567890abcdef"

POLICY_YAML = """\
version: 1
globals:
  default_action: redact
  audit:
    enabled: false
  pseudonymization:
    method: hmac-sha256
    secret_key_file: ./keys/test_hmac_key
    salt: session

detection:
  - id: test_email
    type: regex
    pattern: '(?i)[a-z0-9_.+-]{1,64}@[a-z0-9-]{1,63}(?:\\.[a-z0-9-]{1,63})+'
    action: replace_with_template
    template: '<EMAIL:{hash8}>'
  - id: test_aws
    type: regex
    pattern: '\\b(AKIA|ASIA)[A-Z0-9]{16}\\b'
    action: block
"""


@pytest.fixture(scope="module")
def api_env():
    """Create unified temp environment for API tests.

    Sets up API token, HMAC key, and policy in a single temp dir,
    then reloads mcp.server so module-level globals pick up the
    correct token and default policy path.
    """
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)

        # Create keys
        keys_dir = td_path / "keys"
        keys_dir.mkdir()
        (keys_dir / "mcp_api_token").write_text(TEST_TOKEN)
        (keys_dir / "test_hmac_key").write_bytes(b"a" * 32)

        # Create policy
        policy_path = td_path / "test_policy.yaml"
        policy_path.write_text(POLICY_YAML)

        # chdir so relative paths resolve (token, policy)
        orig_cwd = os.getcwd()
        os.chdir(td)

        # Set MCP_POLICY env var so DEFAULT_POLICY points to our test policy
        os.environ["MCP_POLICY"] = str(policy_path)

        # (Re)load server module so API_TOKEN and DEFAULT_POLICY are set correctly
        import mcp.server
        importlib.reload(mcp.server)

        yield {
            "token": TEST_TOKEN,
            "policy_path": str(policy_path),
            "app": mcp.server.app,
        }

        os.chdir(orig_cwd)
        os.environ.pop("MCP_POLICY", None)


@pytest.fixture
def client(api_env):
    """Create TestClient from the reloaded app"""
    from fastapi.testclient import TestClient
    with TestClient(api_env["app"]) as c:
        yield c


@pytest.fixture
def token(api_env):
    return api_env["token"]


@pytest.fixture
def policy_path(api_env):
    return api_env["policy_path"]


class TestAPIAuthentication:
    def test_health_no_auth(self, client):
        """Test /health without authentication"""
        response = client.get("/health")
        assert response.status_code == 401
        assert "Missing Bearer token" in response.json()["detail"]

    def test_health_invalid_token(self, client):
        """Test /health with invalid token"""
        response = client.get("/health", headers={"Authorization": "Bearer wrong_token"})
        assert response.status_code == 403
        assert "Invalid token" in response.json()["detail"]

    def test_health_valid_token(self, client, token):
        """Test /health with valid token"""
        response = client.get(
            "/health",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "policy_path" in data
        assert "policy_sha256" in data


class TestAPISanitize:
    def test_sanitize_email(self, client, token, policy_path):
        """Test /sanitize with email"""
        response = client.post(
            "/sanitize",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "text": "Contact: alice@example.com",
                "policy_path": policy_path,
                "dry_run": False
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "<EMAIL:" in data["sanitized"]
        assert data["blocked"] is False

    def test_sanitize_blocked_content(self, client, token, policy_path):
        """Test /sanitize with blocked content"""
        response = client.post(
            "/sanitize",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "text": "Key: AKIAIOSFODNN7EXAMPLE",
                "policy_path": policy_path,
                "dry_run": False
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["blocked"] is True

    def test_sanitize_dry_run(self, client, token, policy_path):
        """Test /sanitize with dry_run=true"""
        original_text = "Email: test@example.com"
        response = client.post(
            "/sanitize",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "text": original_text,
                "policy_path": policy_path,
                "dry_run": True
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["sanitized"] == original_text  # Unchanged in dry-run

    def test_sanitize_empty_text(self, client, token, policy_path):
        """Test /sanitize with empty text"""
        response = client.post(
            "/sanitize",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "text": "",
                "policy_path": policy_path,
                "dry_run": False
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["sanitized"] == ""


class TestAPIScan:
    def test_scan_endpoint(self, client, token, policy_path):
        """Test /scan endpoint (always dry-run)"""
        response = client.post(
            "/scan",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "text": "Email: alice@example.com",
                "policy_path": policy_path,
                "dry_run": False  # Ignored; scan always dry-runs
            }
        )
        assert response.status_code == 200
        data = response.json()
        # Scan mode: text should be unchanged
        assert "alice@example.com" in data["sanitized"]


class TestAPIErrors:
    def test_invalid_policy_path(self, client, token):
        """Test /sanitize with non-existent policy"""
        response = client.post(
            "/sanitize",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "text": "test",
                "policy_path": "/nonexistent/policy.yaml",
                "dry_run": False
            }
        )
        assert response.status_code == 500  # Internal server error

    def test_missing_required_fields(self, client, token):
        """Test /sanitize with missing required fields"""
        response = client.post(
            "/sanitize",
            headers={"Authorization": f"Bearer {token}"},
            json={}
        )
        assert response.status_code == 422  # Validation error


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
