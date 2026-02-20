"""Tests for cloakmcp.hooks — Claude Code hook handlers."""
from __future__ import annotations
import json
import os
import pytest

from cloakmcp.hooks import (
    SESSION_STATE_FILE,
    handle_session_start,
    handle_session_end,
    handle_guard_write,
    handle_recover,
    _write_state,
    _read_state,
    _remove_state,
)
from cloakmcp.storage import Vault


# Absolute path to the policy (works regardless of CWD)
POLICY_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "examples",
    "mcp_policy.yaml",
)


# ── State marker ────────────────────────────────────────────────

class TestStateMarker:
    def test_write_and_read(self, tmp_path):
        _write_state(str(tmp_path), "pol.yaml", "TAG")
        state = _read_state(str(tmp_path))
        assert state is not None
        assert state["policy"] == "pol.yaml"
        assert state["prefix"] == "TAG"

    def test_read_missing(self, tmp_path):
        assert _read_state(str(tmp_path)) is None

    def test_remove(self, tmp_path):
        _write_state(str(tmp_path), "pol.yaml", "TAG")
        _remove_state(str(tmp_path))
        assert _read_state(str(tmp_path)) is None

    def test_remove_missing_is_safe(self, tmp_path):
        _remove_state(str(tmp_path))  # should not raise


# ── session-start ───────────────────────────────────────────────

class TestSessionStart:
    def test_packs_directory(self, tmp_path, monkeypatch):
        # Create a file with a secret
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("Email: alice@example.org\n")

        # Point policy env to our test policy (absolute path)
        monkeypatch.setenv("CLOAK_POLICY", POLICY_PATH)

        result = handle_session_start(str(tmp_path))

        assert "additionalContext" in result
        assert "Session started" in result["additionalContext"]

        # State marker should exist
        assert _read_state(str(tmp_path)) is not None

        # File should be packed (no raw email)
        content = secret_file.read_text()
        assert "alice@example.org" not in content

    def test_stale_state_warns(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CLOAK_POLICY", POLICY_PATH)
        _write_state(str(tmp_path), POLICY_PATH, "TAG")

        result = handle_session_start(str(tmp_path))

        assert "additionalContext" in result
        assert "Stale session state" in result["additionalContext"]

    def test_missing_policy_warns(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CLOAK_POLICY", raising=False)
        # chdir to tmp so default policy path doesn't exist
        monkeypatch.chdir(tmp_path)

        result = handle_session_start(str(tmp_path))

        assert "additionalContext" in result
        assert "No policy file found" in result["additionalContext"]


# ── session-end ─────────────────────────────────────────────────

class TestSessionEnd:
    def test_unpacks_directory(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CLOAK_POLICY", POLICY_PATH)

        # Create a file, pack it, then verify end unpacks
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("Email: bob@example.com\n")

        handle_session_start(str(tmp_path))
        assert "bob@example.com" not in secret_file.read_text()

        handle_session_end(str(tmp_path))

        # State marker should be removed
        assert _read_state(str(tmp_path)) is None
        # Secret should be restored
        assert "bob@example.com" in secret_file.read_text()

    def test_no_state_is_noop(self, tmp_path):
        result = handle_session_end(str(tmp_path))
        assert result == {}


# ── guard-write ─────────────────────────────────────────────────

class TestGuardWrite:
    def test_detects_secrets_in_content(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CLOAK_POLICY", POLICY_PATH)

        # Simulate stdin with Write tool JSON
        hook_json = json.dumps({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/some/file.txt",
                "content": "Email: secret@example.org\nAKIAABCDEFGHIJKLMNOP\n"
            }
        })

        import io
        monkeypatch.setattr("sys.stdin", io.StringIO(hook_json))

        result = handle_guard_write(str(tmp_path))

        assert "additionalContext" in result
        assert "secret(s) detected" in result["additionalContext"]

    def test_clean_content_no_warning(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CLOAK_POLICY", POLICY_PATH)

        hook_json = json.dumps({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/some/file.txt",
                "content": "This is safe text with TAG-aabbccddee11\n"
            }
        })

        import io
        monkeypatch.setattr("sys.stdin", io.StringIO(hook_json))

        result = handle_guard_write(str(tmp_path))

        # No secrets -> no warning (empty dict or no additionalContext)
        assert "additionalContext" not in result or "secret(s) detected" not in result.get("additionalContext", "")

    def test_edit_new_string(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CLOAK_POLICY", POLICY_PATH)

        hook_json = json.dumps({
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/some/file.txt",
                "old_string": "old",
                "new_string": "AKIAABCDEFGHIJKLMNOP"
            }
        })

        import io
        monkeypatch.setattr("sys.stdin", io.StringIO(hook_json))

        result = handle_guard_write(str(tmp_path))

        assert "additionalContext" in result
        assert "secret(s) detected" in result["additionalContext"]

    def test_empty_stdin(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CLOAK_POLICY", POLICY_PATH)

        import io
        monkeypatch.setattr("sys.stdin", io.StringIO(""))

        result = handle_guard_write(str(tmp_path))
        assert result == {}

    def test_invalid_json_stdin(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CLOAK_POLICY", POLICY_PATH)

        import io
        monkeypatch.setattr("sys.stdin", io.StringIO("not json"))

        result = handle_guard_write(str(tmp_path))
        assert result == {}


# ── recover ─────────────────────────────────────────────────────

class TestRecover:
    def test_recover_unpacks(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CLOAK_POLICY", POLICY_PATH)

        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("Email: alice@recover.com\n")

        # Pack then simulate abnormal exit (don't call session-end)
        handle_session_start(str(tmp_path))
        assert "alice@recover.com" not in secret_file.read_text()

        # Recover should restore
        handle_recover(str(tmp_path))
        assert _read_state(str(tmp_path)) is None
        assert "alice@recover.com" in secret_file.read_text()

    def test_recover_no_state(self, tmp_path, capsys):
        handle_recover(str(tmp_path))
        captured = capsys.readouterr()
        assert "Nothing to recover" in captured.err


# ── Full lifecycle ──────────────────────────────────────────────

class TestLifecycle:
    def test_full_session_lifecycle(self, tmp_path, monkeypatch):
        """Start -> verify packed -> end -> verify restored."""
        monkeypatch.setenv("CLOAK_POLICY", POLICY_PATH)

        f1 = tmp_path / "config.txt"
        f2 = tmp_path / "readme.txt"
        f1.write_text("api_key: AKIAABCDEFGHIJKLMNOP\nemail: test@example.org\n")
        f2.write_text("No secrets here, just docs.\n")

        # Start
        result = handle_session_start(str(tmp_path))
        assert "Session started" in result["additionalContext"]

        # Packed: secrets gone
        c1 = f1.read_text()
        assert "AKIAABCDEFGHIJKLMNOP" not in c1
        assert "test@example.org" not in c1

        # Safe file unchanged
        assert f2.read_text() == "No secrets here, just docs.\n"

        # End
        handle_session_end(str(tmp_path))

        # Restored
        c1_restored = f1.read_text()
        assert "AKIAABCDEFGHIJKLMNOP" in c1_restored
        assert "test@example.org" in c1_restored
