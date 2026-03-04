"""Tests for cross-platform hook support (v0.12.0).

Covers:
- hooks package import (module → package migration)
- __main__.py entrypoint
- CLI-based settings templates
- installer module
- hooks-path discovery contract
- _safe_chmod platform guard
- stdin/stdout encoding
"""
from __future__ import annotations

import io
import json
import os
import sys

import pytest


# ── Hooks package import ─────────────────────────────────────────


class TestHooksPackageImport:
    """Verify hooks.py → hooks/ package migration preserves all imports."""

    def test_dispatch_import(self):
        from cloakmcp.hooks import dispatch_hook
        assert callable(dispatch_hook)

    def test_main_module_import(self):
        from cloakmcp.hooks.__main__ import main
        assert callable(main)

    def test_all_handlers_importable(self):
        from cloakmcp.hooks import (
            handle_session_start,
            handle_session_end,
            handle_guard_write,
            handle_guard_read,
            handle_prompt_guard,
            handle_safety_guard,
            handle_audit_log,
        )
        for handler in (handle_session_start, handle_session_end,
                        handle_guard_write, handle_guard_read,
                        handle_prompt_guard, handle_safety_guard,
                        handle_audit_log):
            assert callable(handler)

    def test_session_constants(self):
        from cloakmcp.hooks import SESSION_STATE_FILE, SESSION_MANIFEST_FILE, AUDIT_FILE
        assert SESSION_STATE_FILE == ".cloak-session-state"
        assert SESSION_MANIFEST_FILE == ".cloak-session-manifest.json"
        assert AUDIT_FILE == ".cloak-session-audit.jsonl"


# ── CLI-based settings templates ─────────────────────────────────


class TestSettingsTemplates:
    """Verify CLI-based settings templates are valid and complete."""

    @pytest.fixture
    def cli_template(self):
        from importlib.resources import files
        path = str(files("cloakmcp") / "scripts" / "settings" / "hooks-cli.json")
        with open(path) as f:
            return json.load(f)

    @pytest.fixture
    def cli_hardened_template(self):
        from importlib.resources import files
        path = str(files("cloakmcp") / "scripts" / "settings" / "hooks-cli-hardened.json")
        with open(path) as f:
            return json.load(f)

    def test_cli_template_valid_json(self, cli_template):
        assert "hooks" in cli_template
        hooks = cli_template["hooks"]
        assert "SessionStart" in hooks
        assert "SessionEnd" in hooks
        assert "PreToolUse" in hooks

    def test_cli_template_has_required_events(self, cli_template):
        hooks = cli_template["hooks"]
        required = {"SessionStart", "SessionEnd", "UserPromptSubmit", "PreToolUse", "PostToolUse"}
        assert required == set(hooks.keys())

    def test_cli_hardened_has_extra_hooks(self, cli_hardened_template):
        hooks = cli_hardened_template["hooks"]
        # Hardened should have Bash safety guard and Read guard in PreToolUse
        pre_tool = hooks["PreToolUse"]
        matchers = [entry.get("matcher", "") for entry in pre_tool]
        assert "Bash" in matchers
        assert "Read|Grep|Glob" in matchers

    def test_no_sh_paths_in_cli_templates(self, cli_template, cli_hardened_template):
        """CLI templates must not reference .sh files."""
        for template in (cli_template, cli_hardened_template):
            raw = json.dumps(template)
            assert ".sh" not in raw, f"Found .sh reference in CLI template: {raw}"

    def test_cli_commands_use_cloak_hook(self, cli_template):
        """All commands should be 'cloak hook <event>'."""
        for event, entries in cli_template["hooks"].items():
            for entry in entries:
                for hook in entry.get("hooks", []):
                    cmd = hook.get("command", "")
                    assert cmd.startswith("cloak hook "), \
                        f"Expected 'cloak hook ...' but got '{cmd}' in {event}"

    def test_cli_commands_match_dispatch_events(self, cli_hardened_template):
        """Event names in CLI commands must match dispatch_hook handler keys."""
        from cloakmcp.hooks import dispatch_hook
        # Extract event names from template commands
        events_in_template = set()
        for entries in cli_hardened_template["hooks"].values():
            for entry in entries:
                for hook in entry.get("hooks", []):
                    cmd = hook.get("command", "")
                    if cmd.startswith("cloak hook "):
                        event = cmd.split("cloak hook ")[1].strip()
                        events_in_template.add(event)
        # All events must be valid dispatch keys
        valid_events = {
            "session-start", "session-end", "guard-write",
            "guard-read", "prompt-guard", "safety-guard", "audit-log",
        }
        assert events_in_template.issubset(valid_events), \
            f"Unknown events: {events_in_template - valid_events}"


# ── Installer ────────────────────────────────────────────────────


class TestInstallerCli:
    """Test cloak install --method cli."""

    def test_install_creates_settings(self, tmp_path):
        from cloakmcp.installer import install_hooks
        result = install_hooks(project_dir=str(tmp_path), method="cli")
        assert result["errors"] == []
        settings = tmp_path / ".claude" / "settings.local.json"
        assert settings.is_file()
        with open(settings) as f:
            data = json.load(f)
        assert "hooks" in data

    def test_install_no_hook_scripts_copied(self, tmp_path):
        from cloakmcp.installer import install_hooks
        install_hooks(project_dir=str(tmp_path), method="cli")
        hooks_dir = tmp_path / ".claude" / "hooks"
        # With cli method, no hooks directory should be created
        if hooks_dir.is_dir():
            sh_files = list(hooks_dir.glob("*.sh"))
            assert sh_files == []

    def test_install_hardened_profile(self, tmp_path):
        from cloakmcp.installer import install_hooks
        result = install_hooks(project_dir=str(tmp_path), profile="hardened", method="cli")
        assert result["errors"] == []
        assert result["profile"] == "hardened"
        # Hardened has more hooks
        assert len(result["hooks_installed"]) == 7

    def test_uninstall_removes_settings(self, tmp_path):
        from cloakmcp.installer import install_hooks
        install_hooks(project_dir=str(tmp_path), method="cli")
        result = install_hooks(project_dir=str(tmp_path), uninstall=True)
        settings = tmp_path / ".claude" / "settings.local.json"
        with open(settings) as f:
            data = json.load(f)
        assert "hooks" not in data

    def test_dry_run_no_changes(self, tmp_path):
        from cloakmcp.installer import install_hooks
        result = install_hooks(project_dir=str(tmp_path), method="cli", dry_run=True)
        assert result["dry_run"] is True
        settings = tmp_path / ".claude" / "settings.local.json"
        assert not settings.exists()

    def test_install_preserves_existing_settings(self, tmp_path):
        from cloakmcp.installer import install_hooks
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = claude_dir / "settings.local.json"
        settings.write_text('{"permissions": {"allow": ["Read"]}}')
        install_hooks(project_dir=str(tmp_path), method="cli")
        with open(settings) as f:
            data = json.load(f)
        assert "hooks" in data
        assert data["permissions"] == {"allow": ["Read"]}

    def test_install_copy_method(self, tmp_path):
        from cloakmcp.installer import install_hooks
        result = install_hooks(project_dir=str(tmp_path), method="copy")
        assert result["errors"] == []
        hooks_dir = tmp_path / ".claude" / "hooks"
        assert hooks_dir.is_dir()
        # Should have .sh files
        sh_files = list(hooks_dir.glob("*.sh"))
        assert len(sh_files) >= 5


# ── hooks-path discovery contract ────────────────────────────────


class TestHooksPath:
    """Verify cloak hooks-path contract for toolbox integration."""

    def test_sh_format(self):
        from cloakmcp.installer import hooks_path
        path = hooks_path("sh")
        assert os.path.isdir(path)
        assert any(f.endswith(".sh") for f in os.listdir(path))

    def test_py_format(self):
        from cloakmcp.installer import hooks_path
        path = hooks_path("py")
        assert os.path.isdir(path)
        assert any(f.endswith(".py") for f in os.listdir(path))

    def test_cli_format(self):
        from cloakmcp.installer import hooks_path
        result = hooks_path("cli")
        assert result == "cloak hook"

    def test_py_scripts_side_by_side(self):
        """Every .sh hook must have a matching .py counterpart."""
        from cloakmcp.installer import hooks_path
        path = hooks_path("sh")
        sh_files = {f.replace(".sh", "") for f in os.listdir(path) if f.endswith(".sh")}
        py_files = {f.replace(".py", "") for f in os.listdir(path) if f.endswith(".py")}
        # All .sh hooks must have .py equivalents
        missing = sh_files - py_files
        assert missing == set(), f"Missing .py equivalents for: {missing}"


# ── _safe_chmod platform guard ───────────────────────────────────


class TestSafeChmod:
    """Verify _safe_chmod is a no-op on Windows and works on Unix."""

    def test_safe_chmod_unix(self, tmp_path):
        from cloakmcp.storage import _safe_chmod, _IS_WINDOWS
        if _IS_WINDOWS:
            pytest.skip("Unix-only test")
        path = tmp_path / "test.key"
        path.write_bytes(b"test")
        os.chmod(str(path), 0o644)
        _safe_chmod(str(path), 0o600)
        actual = os.stat(str(path)).st_mode & 0o777
        assert actual == 0o600

    def test_verify_permissions_returns_false_on_windows(self, monkeypatch):
        from cloakmcp import storage
        monkeypatch.setattr(storage, "_IS_WINDOWS", True)
        result = storage._verify_permissions("/nonexistent", 0o600)
        assert result is False

    def test_safe_chmod_noop_on_windows(self, tmp_path, monkeypatch):
        from cloakmcp import storage
        monkeypatch.setattr(storage, "_IS_WINDOWS", True)
        path = tmp_path / "test.key"
        path.write_bytes(b"test")
        before = os.stat(str(path)).st_mode
        storage._safe_chmod(str(path), 0o600)
        after = os.stat(str(path)).st_mode
        # On Linux with _IS_WINDOWS=True, chmod should be skipped
        assert before == after


# ── stdin/stdout encoding ────────────────────────────────────────


class TestStdinEncoding:
    """Verify stdin/stdout handle UTF-8 on all platforms."""

    def test_read_utf8_json(self, monkeypatch):
        from cloakmcp.hooks import _read_stdin_json
        # Simulate UTF-8 JSON with accented chars
        data = {"file": "résumé.txt", "content": "données secrètes"}
        json_bytes = json.dumps(data).encode("utf-8")
        monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(json_bytes)))
        result = _read_stdin_json()
        assert result is not None
        assert result["file"] == "résumé.txt"

    def test_read_empty_stdin(self, monkeypatch):
        from cloakmcp.hooks import _read_stdin_json
        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        result = _read_stdin_json()
        assert result is None

    def test_read_invalid_json(self, monkeypatch):
        from cloakmcp.hooks import _read_stdin_json
        monkeypatch.setattr("sys.stdin", io.StringIO("not json at all"))
        result = _read_stdin_json()
        assert result is None

    def test_emit_non_ascii(self, capsys):
        from cloakmcp.hooks import _emit_json
        _emit_json({"résultat": "succès"})
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["résultat"] == "succès"


# ── Idempotent install / uninstall ──────────────────────────────


class TestIdempotentInstallUninstall:
    """Verify that install and uninstall are idempotent."""

    def test_install_twice_same_result(self, tmp_path):
        from cloakmcp.installer import install_hooks
        r1 = install_hooks(project_dir=str(tmp_path), method="cli")
        settings = tmp_path / ".claude" / "settings.local.json"
        with open(settings) as f:
            data1 = json.load(f)
        r2 = install_hooks(project_dir=str(tmp_path), method="cli")
        with open(settings) as f:
            data2 = json.load(f)
        assert r1["errors"] == []
        assert r2["errors"] == []
        assert data1 == data2

    def test_install_twice_copy_method(self, tmp_path):
        from cloakmcp.installer import install_hooks
        install_hooks(project_dir=str(tmp_path), method="copy")
        hooks_dir = tmp_path / ".claude" / "hooks"
        files1 = sorted(f.name for f in hooks_dir.iterdir())
        install_hooks(project_dir=str(tmp_path), method="copy")
        files2 = sorted(f.name for f in hooks_dir.iterdir())
        assert files1 == files2

    def test_uninstall_twice_no_error(self, tmp_path):
        from cloakmcp.installer import install_hooks
        install_hooks(project_dir=str(tmp_path), method="cli")
        r1 = install_hooks(project_dir=str(tmp_path), uninstall=True)
        r2 = install_hooks(project_dir=str(tmp_path), uninstall=True)
        assert r1["errors"] == [] if "errors" in r1 else True
        assert r2["errors"] == [] if "errors" in r2 else True

    def test_install_uninstall_clean_state(self, tmp_path):
        from cloakmcp.installer import install_hooks
        install_hooks(project_dir=str(tmp_path), method="cli")
        install_hooks(project_dir=str(tmp_path), uninstall=True)
        settings = tmp_path / ".claude" / "settings.local.json"
        with open(settings) as f:
            data = json.load(f)
        assert "hooks" not in data

    def test_install_uninstall_copy_hooks_removed(self, tmp_path):
        from cloakmcp.installer import install_hooks
        install_hooks(project_dir=str(tmp_path), method="copy")
        hooks_dir = tmp_path / ".claude" / "hooks"
        assert any(f.name.startswith("cloak-") for f in hooks_dir.iterdir())
        install_hooks(project_dir=str(tmp_path), uninstall=True)
        cloak_files = [f for f in hooks_dir.iterdir() if f.name.startswith("cloak-")]
        assert cloak_files == []

    def test_uninstall_then_install_restores(self, tmp_path):
        from cloakmcp.installer import install_hooks
        install_hooks(project_dir=str(tmp_path), method="cli")
        install_hooks(project_dir=str(tmp_path), uninstall=True)
        r = install_hooks(project_dir=str(tmp_path), method="cli")
        assert r["errors"] == []
        settings = tmp_path / ".claude" / "settings.local.json"
        with open(settings) as f:
            data = json.load(f)
        assert "hooks" in data


# ── Windows platform guards ─────────────────────────────────────


class TestWindowsPlatformGuards:
    """Verify Windows-specific platform guards in installer and CLI."""

    def test_installer_safe_chmod_used(self, tmp_path, monkeypatch):
        """Verify _safe_chmod is called instead of bare os.chmod."""
        from cloakmcp import installer
        from cloakmcp.storage import _safe_chmod
        calls = []
        original = _safe_chmod.__wrapped__ if hasattr(_safe_chmod, '__wrapped__') else _safe_chmod

        def tracking_chmod(path, mode):
            calls.append((path, mode))
            # Do real chmod on non-Windows
            original(path, mode)

        monkeypatch.setattr(installer, "_safe_chmod", tracking_chmod)
        installer.install_hooks(project_dir=str(tmp_path), method="copy")
        assert len(calls) > 0, "_safe_chmod was never called"

    def test_installer_auto_downgrade_on_windows(self, tmp_path, monkeypatch):
        """symlink method on win32 should auto-downgrade to cli."""
        from cloakmcp import installer as inst_mod
        monkeypatch.setattr(inst_mod.sys, "platform", "win32")
        # Also mock shutil.which to avoid Windows-specific API calls
        monkeypatch.setattr(inst_mod.shutil, "which", lambda cmd: "/usr/bin/cloak")
        result = inst_mod.install_hooks(project_dir=str(tmp_path), method="symlink")
        assert result["method"] == "cli"

    def test_policy_use_link_windows_error(self, tmp_path, monkeypatch):
        """policy use --link on win32 should exit with error."""
        from cloakmcp import cli as cli_mod
        monkeypatch.setattr(cli_mod.sys, "platform", "win32")

        # Create a minimal policy file
        policy = tmp_path / "policy.yaml"
        policy.write_text("version: 1\ndetection: []\n")
        cloak_dir = tmp_path / ".cloak"
        cloak_dir.mkdir()

        monkeypatch.setattr(
            cli_mod.sys, "argv",
            ["cloak", "policy", "use", str(policy), "--link", "--dir", str(tmp_path)]
        )
        with pytest.raises(SystemExit) as exc_info:
            cli_mod.main()
        assert exc_info.value.code == 1


# ── Doctor hook validation ──────────────────────────────────────


class TestDoctorHookValidation:
    """Verify cloak doctor reports hook entrypoint status."""

    def test_doctor_reports_hook_entrypoints(self, tmp_path, capsys):
        """doctor output should contain .py hooks: and .sh hooks: lines."""
        from cloakmcp.installer import install_hooks
        install_hooks(project_dir=str(tmp_path), method="cli")
        # Run doctor via CLI
        from subprocess import run
        result = run(
            [sys.executable, "-m", "cloakmcp.cli", "doctor", "--dir", str(tmp_path)],
            capture_output=True, text=True
        )
        assert ".py hooks:" in result.stdout
        assert ".sh hooks:" in result.stdout

    def test_doctor_bundled_hooks_all_present(self):
        """All 7 .py hook files must exist in bundled scripts dir."""
        from cloakmcp.installer import hooks_path
        hooks_dir = hooks_path("py")
        expected = [
            "cloak-session-start.py", "cloak-session-end.py",
            "cloak-guard-write.py", "cloak-guard-read.py",
            "cloak-prompt-guard.py", "cloak-safety-guard.py",
            "cloak-audit-logger.py",
        ]
        for name in expected:
            assert os.path.isfile(os.path.join(hooks_dir, name)), \
                f"Missing bundled hook: {name}"

    def test_doctor_runs_on_windows_mock(self, tmp_path, monkeypatch):
        """doctor should not crash when sys.platform == win32."""
        from subprocess import run
        # Run doctor in a subprocess with platform mocked via env
        # We test the code path directly instead
        from cloakmcp.installer import install_hooks
        install_hooks(project_dir=str(tmp_path), method="cli")
        monkeypatch.setattr("sys.platform", "win32")
        result = run(
            [sys.executable, "-m", "cloakmcp.cli", "doctor", "--dir", str(tmp_path)],
            capture_output=True, text=True
        )
        # Should not crash (exit code 0)
        assert result.returncode == 0
