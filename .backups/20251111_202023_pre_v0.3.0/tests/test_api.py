"""
API endpoint tests for CloakMCP server

Tests the FastAPI server endpoints:
- /health (GET)
- /sanitize (POST)
- /scan (POST)
- Authentication (Bearer token)
- Error handling

Run: pytest -v tests/test_api.py

Note: Requires running server or using TestClient
"""

from __future__ import annotations
import os
import pytest
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient

# Mock the API token file before importing server
@pytest.fixture(scope="module", autouse=True)
def setup_api_token():
    """Create temporary API token for tests"""
    with tempfile.TemporaryDirectory() as td:
        token_dir = Path(td) / "keys"
        token_dir.mkdir()
        token_file = token_dir / "mcp_api_token"
        token_file.write_text("test_token_1234567890abcdef")

        # Set environment to point to temp key
        orig_cwd = os.getcwd()
        os.chdir(td)

        yield "test_token_1234567890abcdef"

        os.chdir(orig_cwd)


@pytest.fixture
def policy_yaml(tmp_path: Path) -> Path:
    """Create test policy"""
    yaml_content = """
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
    pattern: '(?i)[a-z0-9_.+-]+@[a-z0-9-]+\\.[a-z0-9.-]+'
    action: replace_with_template
    template: '<EMAIL:{hash8}>'
  - id: test_aws
    type: regex
    pattern: '\\b(AKIA|ASIA)[A-Z0-9]{16}\\b'
    action: block
"""
    policy_path = tmp_path / "test_policy.yaml"
    policy_path.write_text(yaml_content)

    # Create keys dir
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    (keys_dir / "test_hmac_key").write_bytes(b"a" * 32)

    return policy_path


@pytest.fixture
def client(setup_api_token, policy_yaml):
    """Create test client"""
    # Change to temp dir where policy exists
    orig_cwd = os.getcwd()
    os.chdir(policy_yaml.parent)

    try:
        # Import after setting up token
        from mcp.server import app
        with TestClient(app) as c:
            yield c
    finally:
        os.chdir(orig_cwd)


class TestAPIAuthentication:
    def test_health_no_auth(self, client: TestClient):
        """Test /health without authentication"""
        response = client.get("/health")
        assert response.status_code == 401
        assert "Missing Bearer token" in response.json()["detail"]

    def test_health_invalid_token(self, client: TestClient):
        """Test /health with invalid token"""
        response = client.get("/health", headers={"Authorization": "Bearer wrong_token"})
        assert response.status_code == 403
        assert "Invalid token" in response.json()["detail"]

    def test_health_valid_token(self, client: TestClient, setup_api_token):
        """Test /health with valid token"""
        response = client.get(
            "/health",
            headers={"Authorization": f"Bearer {setup_api_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "policy_path" in data
        assert "policy_sha256" in data


class TestAPISanitize:
    def test_sanitize_email(self, client: TestClient, setup_api_token, policy_yaml):
        """Test /sanitize with email"""
        response = client.post(
            "/sanitize",
            headers={"Authorization": f"Bearer {setup_api_token}"},
            json={
                "text": "Contact: alice@example.com",
                "policy_path": str(policy_yaml),
                "dry_run": False
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "<EMAIL:" in data["sanitized"]
        assert data["blocked"] is False

    def test_sanitize_blocked_content(self, client: TestClient, setup_api_token, policy_yaml):
        """Test /sanitize with blocked content"""
        response = client.post(
            "/sanitize",
            headers={"Authorization": f"Bearer {setup_api_token}"},
            json={
                "text": "Key: AKIAIOSFODNN7EXAMPLE",
                "policy_path": str(policy_yaml),
                "dry_run": False
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["blocked"] is True

    def test_sanitize_dry_run(self, client: TestClient, setup_api_token, policy_yaml):
        """Test /sanitize with dry_run=true"""
        original_text = "Email: test@example.com"
        response = client.post(
            "/sanitize",
            headers={"Authorization": f"Bearer {setup_api_token}"},
            json={
                "text": original_text,
                "policy_path": str(policy_yaml),
                "dry_run": True
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["sanitized"] == original_text  # Unchanged in dry-run

    def test_sanitize_empty_text(self, client: TestClient, setup_api_token, policy_yaml):
        """Test /sanitize with empty text"""
        response = client.post(
            "/sanitize",
            headers={"Authorization": f"Bearer {setup_api_token}"},
            json={
                "text": "",
                "policy_path": str(policy_yaml),
                "dry_run": False
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["sanitized"] == ""


class TestAPIScan:
    def test_scan_endpoint(self, client: TestClient, setup_api_token, policy_yaml):
        """Test /scan endpoint (always dry-run)"""
        response = client.post(
            "/scan",
            headers={"Authorization": f"Bearer {setup_api_token}"},
            json={
                "text": "Email: alice@example.com",
                "policy_path": str(policy_yaml),
                "dry_run": False  # Ignored; scan always dry-runs
            }
        )
        assert response.status_code == 200
        data = response.json()
        # Scan mode: text should be unchanged
        assert "alice@example.com" in data["sanitized"]


class TestAPIErrors:
    def test_invalid_policy_path(self, client: TestClient, setup_api_token):
        """Test /sanitize with non-existent policy"""
        response = client.post(
            "/sanitize",
            headers={"Authorization": f"Bearer {setup_api_token}"},
            json={
                "text": "test",
                "policy_path": "/nonexistent/policy.yaml",
                "dry_run": False
            }
        )
        assert response.status_code == 500  # Internal server error

    def test_missing_required_fields(self, client: TestClient, setup_api_token):
        """Test /sanitize with missing required fields"""
        response = client.post(
            "/sanitize",
            headers={"Authorization": f"Bearer {setup_api_token}"},
            json={}
        )
        assert response.status_code == 422  # Validation error


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
