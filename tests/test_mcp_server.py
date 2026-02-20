"""Tests for cloakmcp.mcp_server — raw MCP JSON-RPC tool server."""
from __future__ import annotations
import json
import os
import pytest

from cloakmcp.mcp_server import (
    _handle_request,
    _jsonrpc_response,
    _jsonrpc_error,
    TOOLS,
    TOOL_HANDLERS,
)

POLICY_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "examples",
    "mcp_policy.yaml",
)


# ── Protocol tests ──────────────────────────────────────────────

class TestProtocol:
    def test_initialize(self):
        resp = _handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert resp["id"] == 1
        result = resp["result"]
        assert "protocolVersion" in result
        assert result["serverInfo"]["name"] == "cloakmcp"
        assert "tools" in result["capabilities"]

    def test_tools_list(self):
        resp = _handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = resp["result"]["tools"]
        names = {t["name"] for t in tools}
        assert "cloak_scan_text" in names
        assert "cloak_pack_text" in names
        assert "cloak_unpack_text" in names
        assert "cloak_vault_stats" in names
        assert "cloak_pack_dir" in names
        assert "cloak_unpack_dir" in names

    def test_ping(self):
        resp = _handle_request({"jsonrpc": "2.0", "id": 3, "method": "ping"})
        assert resp["id"] == 3
        assert "error" not in resp

    def test_unknown_method(self):
        resp = _handle_request({"jsonrpc": "2.0", "id": 4, "method": "nonexistent"})
        assert "error" in resp
        assert resp["error"]["code"] == -32601

    def test_notification_returns_none(self):
        resp = _handle_request({"jsonrpc": "2.0", "method": "notifications/initialized"})
        assert resp is None

    def test_unknown_tool(self):
        resp = _handle_request({
            "jsonrpc": "2.0", "id": 5,
            "method": "tools/call",
            "params": {"name": "nonexistent_tool", "arguments": {}}
        })
        assert "error" in resp
        assert "Unknown tool" in resp["error"]["message"]


# ── Tool: cloak_scan_text ───────────────────────────────────────

class TestScanText:
    def test_finds_email(self):
        resp = _handle_request({
            "jsonrpc": "2.0", "id": 10,
            "method": "tools/call",
            "params": {
                "name": "cloak_scan_text",
                "arguments": {
                    "text": "Email: alice@example.org",
                    "policy_path": POLICY_PATH,
                },
            },
        })
        result = json.loads(resp["result"]["content"][0]["text"])
        assert result["count"] > 0
        rule_ids = {m["rule_id"] for m in result["matches"]}
        assert "email" in rule_ids

    def test_clean_text(self):
        resp = _handle_request({
            "jsonrpc": "2.0", "id": 11,
            "method": "tools/call",
            "params": {
                "name": "cloak_scan_text",
                "arguments": {
                    "text": "Hello world, no secrets here.",
                    "policy_path": POLICY_PATH,
                },
            },
        })
        result = json.loads(resp["result"]["content"][0]["text"])
        assert result["count"] == 0

    def test_aws_key(self):
        resp = _handle_request({
            "jsonrpc": "2.0", "id": 12,
            "method": "tools/call",
            "params": {
                "name": "cloak_scan_text",
                "arguments": {
                    "text": "key = AKIAABCDEFGHIJKLMNOP",
                    "policy_path": POLICY_PATH,
                },
            },
        })
        result = json.loads(resp["result"]["content"][0]["text"])
        assert result["count"] > 0


# ── Tool: cloak_pack_text / cloak_unpack_text ───────────────────

class TestPackUnpackText:
    def test_pack_replaces_secrets(self, tmp_path):
        resp = _handle_request({
            "jsonrpc": "2.0", "id": 20,
            "method": "tools/call",
            "params": {
                "name": "cloak_pack_text",
                "arguments": {
                    "text": "Email: bob@example.com",
                    "policy_path": POLICY_PATH,
                    "project_root": str(tmp_path),
                },
            },
        })
        result = json.loads(resp["result"]["content"][0]["text"])
        assert result["count"] > 0
        assert "bob@example.com" not in result["packed"]
        assert "TAG-" in result["packed"]

    def test_roundtrip(self, tmp_path):
        # Pack
        pack_resp = _handle_request({
            "jsonrpc": "2.0", "id": 21,
            "method": "tools/call",
            "params": {
                "name": "cloak_pack_text",
                "arguments": {
                    "text": "Email: roundtrip@example.com",
                    "policy_path": POLICY_PATH,
                    "project_root": str(tmp_path),
                },
            },
        })
        pack_result = json.loads(pack_resp["result"]["content"][0]["text"])
        packed = pack_result["packed"]

        # Unpack
        unpack_resp = _handle_request({
            "jsonrpc": "2.0", "id": 22,
            "method": "tools/call",
            "params": {
                "name": "cloak_unpack_text",
                "arguments": {
                    "text": packed,
                    "project_root": str(tmp_path),
                },
            },
        })
        unpack_result = json.loads(unpack_resp["result"]["content"][0]["text"])
        assert "roundtrip@example.com" in unpack_result["unpacked"]

    def test_custom_prefix(self, tmp_path):
        resp = _handle_request({
            "jsonrpc": "2.0", "id": 23,
            "method": "tools/call",
            "params": {
                "name": "cloak_pack_text",
                "arguments": {
                    "text": "Email: prefix@example.com",
                    "policy_path": POLICY_PATH,
                    "project_root": str(tmp_path),
                    "prefix": "SEC",
                },
            },
        })
        result = json.loads(resp["result"]["content"][0]["text"])
        assert "SEC-" in result["packed"]


# ── Tool: cloak_vault_stats ─────────────────────────────────────

class TestVaultStats:
    def test_empty_vault(self, tmp_path):
        resp = _handle_request({
            "jsonrpc": "2.0", "id": 30,
            "method": "tools/call",
            "params": {
                "name": "cloak_vault_stats",
                "arguments": {"project_root": str(tmp_path)},
            },
        })
        result = json.loads(resp["result"]["content"][0]["text"])
        assert result["total_secrets"] == 0

    def test_vault_after_pack(self, tmp_path):
        # Pack something first
        _handle_request({
            "jsonrpc": "2.0", "id": 31,
            "method": "tools/call",
            "params": {
                "name": "cloak_pack_text",
                "arguments": {
                    "text": "Email: stats@example.com",
                    "policy_path": POLICY_PATH,
                    "project_root": str(tmp_path),
                },
            },
        })

        # Check stats
        resp = _handle_request({
            "jsonrpc": "2.0", "id": 32,
            "method": "tools/call",
            "params": {
                "name": "cloak_vault_stats",
                "arguments": {"project_root": str(tmp_path)},
            },
        })
        result = json.loads(resp["result"]["content"][0]["text"])
        assert result["total_secrets"] > 0


# ── Tool: cloak_pack_dir / cloak_unpack_dir ─────────────────────

class TestPackUnpackDir:
    def test_pack_dir(self, tmp_path):
        (tmp_path / "test.txt").write_text("Email: dir@example.com\n")

        resp = _handle_request({
            "jsonrpc": "2.0", "id": 40,
            "method": "tools/call",
            "params": {
                "name": "cloak_pack_dir",
                "arguments": {
                    "dir": str(tmp_path),
                    "policy_path": POLICY_PATH,
                },
            },
        })
        result = json.loads(resp["result"]["content"][0]["text"])
        assert result["status"] == "ok"

        # File should be packed
        content = (tmp_path / "test.txt").read_text()
        assert "dir@example.com" not in content

    def test_unpack_dir(self, tmp_path):
        (tmp_path / "test.txt").write_text("Email: unpackdir@example.com\n")

        # Pack first
        _handle_request({
            "jsonrpc": "2.0", "id": 41,
            "method": "tools/call",
            "params": {
                "name": "cloak_pack_dir",
                "arguments": {
                    "dir": str(tmp_path),
                    "policy_path": POLICY_PATH,
                },
            },
        })

        # Unpack
        resp = _handle_request({
            "jsonrpc": "2.0", "id": 42,
            "method": "tools/call",
            "params": {
                "name": "cloak_unpack_dir",
                "arguments": {"dir": str(tmp_path)},
            },
        })
        result = json.loads(resp["result"]["content"][0]["text"])
        assert result["status"] == "ok"

        # Secret should be restored
        content = (tmp_path / "test.txt").read_text()
        assert "unpackdir@example.com" in content

    def test_invalid_dir(self):
        resp = _handle_request({
            "jsonrpc": "2.0", "id": 43,
            "method": "tools/call",
            "params": {
                "name": "cloak_pack_dir",
                "arguments": {
                    "dir": "/nonexistent/dir",
                    "policy_path": POLICY_PATH,
                },
            },
        })
        assert resp["result"].get("isError") is True


# ── Error handling ──────────────────────────────────────────────

class TestErrorHandling:
    def test_tool_error_returns_isError(self):
        resp = _handle_request({
            "jsonrpc": "2.0", "id": 50,
            "method": "tools/call",
            "params": {
                "name": "cloak_scan_text",
                "arguments": {
                    "text": "test",
                    "policy_path": "/nonexistent/policy.yaml",
                },
            },
        })
        assert resp["result"].get("isError") is True
        assert "Error" in resp["result"]["content"][0]["text"]
