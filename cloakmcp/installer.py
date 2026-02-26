"""Cross-platform Claude Code hook installer.

Replaces install_claude.sh with a pure-Python installer that works on
Linux, macOS, and Windows without bash dependency.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from datetime import datetime
from importlib.resources import files as pkg_files
from typing import Dict, List, Optional


def _scripts_dir() -> str:
    """Path to bundled scripts directory."""
    return str(pkg_files("cloakmcp") / "scripts")


def _hooks_source_dir() -> str:
    """Path to bundled hook scripts."""
    return os.path.join(_scripts_dir(), "hooks")


def _settings_source_dir() -> str:
    """Path to bundled settings templates."""
    return os.path.join(_scripts_dir(), "settings")


# Hook scripts per profile
_HOOKS_SECRETS_ONLY = [
    "cloak-session-start",
    "cloak-session-end",
    "cloak-guard-write",
    "cloak-prompt-guard",
    "cloak-audit-logger",
]

_HOOKS_HARDENED = _HOOKS_SECRETS_ONLY + [
    "cloak-safety-guard",
    "cloak-guard-read",
]

# Settings template mapping: (method, profile) -> filename
_TEMPLATES = {
    ("cli", "secrets-only"): "hooks-cli.json",
    ("cli", "hardened"): "hooks-cli-hardened.json",
    ("copy", "secrets-only"): "hooks.json",
    ("copy", "hardened"): "hooks-hardened.json",
    ("symlink", "secrets-only"): "hooks.json",
    ("symlink", "hardened"): "hooks-hardened.json",
}


def _hook_ext(method: str) -> str:
    """File extension for hook scripts based on method."""
    if method == "cli":
        return ".py"  # .py scripts shipped alongside .sh
    return ".sh"


def install_hooks(
    project_dir: str = ".",
    profile: str = "secrets-only",
    method: str = "cli",
    policy: str = "",
    dry_run: bool = False,
    uninstall: bool = False,
) -> Dict:
    """Install or uninstall CloakMCP Claude Code hooks.

    Args:
        project_dir: Project root directory.
        profile: "secrets-only" or "hardened".
        method: "cli" (cross-platform default), "copy", or "symlink" (Unix).
        policy: Optional policy file path to set via cloak policy use.
        dry_run: If True, preview actions without making changes.
        uninstall: If True, remove installed hooks.

    Returns:
        Dict with keys: action, profile, method, hooks_installed, errors.
    """
    project_dir = os.path.abspath(project_dir)
    claude_dir = os.path.join(project_dir, ".claude")
    hooks_dir = os.path.join(claude_dir, "hooks")
    settings_file = os.path.join(claude_dir, "settings.local.json")

    result = {
        "action": "uninstall" if uninstall else "install",
        "profile": profile,
        "method": method,
        "hooks_installed": [],
        "errors": [],
        "dry_run": dry_run,
    }

    if uninstall:
        return _uninstall(hooks_dir, settings_file, dry_run, result)

    # ── Preflight ──────────────────────────────────────────────
    if method in ("copy", "symlink") and sys.platform == "win32":
        print("[WARN] .sh hooks not supported on Windows, using cli method",
              file=sys.stderr)
        method = "cli"
        result["method"] = "cli"

    if method == "cli":
        cloak_path = shutil.which("cloak")
        if not cloak_path:
            result["errors"].append("'cloak' not found in PATH")
            print("[ERROR] 'cloak' not found in PATH. Install: pip install cloakmcp",
                  file=sys.stderr)
            return result

    # ── Backup ──────────────────────────────────────────────────
    if os.path.isfile(settings_file) or os.path.isdir(hooks_dir):
        backup_dir = os.path.join(claude_dir,
                                  f".backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
        if not dry_run:
            os.makedirs(backup_dir, exist_ok=True)
            if os.path.isfile(settings_file):
                shutil.copy2(settings_file, backup_dir)
            if os.path.isdir(hooks_dir):
                shutil.copytree(hooks_dir, os.path.join(backup_dir, "hooks"))
        result["backup_dir"] = backup_dir

    # ── Install hook scripts (copy/symlink only) ────────────────
    hook_names = _HOOKS_HARDENED if profile == "hardened" else _HOOKS_SECRETS_ONLY

    if method in ("copy", "symlink"):
        ext = ".sh"
        if not dry_run:
            os.makedirs(hooks_dir, exist_ok=True)

        source_dir = _hooks_source_dir()
        for name in hook_names:
            src = os.path.join(source_dir, f"{name}{ext}")
            dst = os.path.join(hooks_dir, f"{name}{ext}")
            if not os.path.isfile(src):
                result["errors"].append(f"Source not found: {src}")
                continue
            if not dry_run:
                if method == "symlink":
                    if os.path.exists(dst):
                        os.remove(dst)
                    os.symlink(src, dst)
                else:
                    shutil.copy2(src, dst)
                os.chmod(dst, 0o755)
            result["hooks_installed"].append(f"{name}{ext}")
    else:
        # CLI method: no files to copy, hooks run via `cloak hook <event>`
        for name in hook_names:
            result["hooks_installed"].append(name)

    # ── Merge settings template ──────────────────────────────────
    template_key = (method if method == "cli" else "copy", profile)
    template_name = _TEMPLATES.get(template_key)
    if not template_name:
        result["errors"].append(f"No template for method={method}, profile={profile}")
        return result

    template_path = os.path.join(_settings_source_dir(), template_name)
    if not os.path.isfile(template_path):
        result["errors"].append(f"Template not found: {template_path}")
        return result

    if not dry_run:
        os.makedirs(claude_dir, exist_ok=True)
        with open(template_path, "r") as f:
            template = json.load(f)

        existing = {}
        if os.path.isfile(settings_file):
            with open(settings_file, "r") as f:
                existing = json.load(f)

        existing["hooks"] = template["hooks"]

        fd, tmp = tempfile.mkstemp(dir=claude_dir)
        with os.fdopen(fd, "w") as f:
            json.dump(existing, f, indent=2)
            f.write("\n")
        os.replace(tmp, settings_file)

    result["settings_template"] = template_name

    # ── Ensure .gitignore / .mcpignore entries ────────────────────
    for ignore_name in (".gitignore", ".mcpignore"):
        ignore_path = os.path.join(project_dir, ignore_name)
        if os.path.isfile(ignore_path):
            with open(ignore_path, "r") as f:
                content = f.read()
            if ".cloak-backups/" not in content:
                if not dry_run:
                    with open(ignore_path, "a") as f:
                        f.write(".cloak-backups/\n")

    # ── Set per-project policy (optional) ──────────────────────────
    if policy:
        if not dry_run:
            from .policy import resolve_policy
            # Import cli's policy use logic
            from subprocess import run as _run
            _run(["cloak", "policy", "use", policy, "--dir", project_dir],
                 check=True)
        result["policy"] = policy

    # ── Verify ────────────────────────────────────────────────────
    if not dry_run:
        errors = _verify(settings_file, hooks_dir, method, hook_names)
        result["errors"].extend(errors)

    return result


def _uninstall(hooks_dir: str, settings_file: str, dry_run: bool,
               result: Dict) -> Dict:
    """Remove CloakMCP hooks."""
    # Remove hook scripts
    if os.path.isdir(hooks_dir):
        for f in os.listdir(hooks_dir):
            if f.startswith("cloak-") and (f.endswith(".sh") or f.endswith(".py")):
                path = os.path.join(hooks_dir, f)
                if not dry_run:
                    os.remove(path)
                result["hooks_installed"].append(f"removed: {f}")

    # Remove hooks key from settings
    if os.path.isfile(settings_file):
        if not dry_run:
            with open(settings_file, "r") as f:
                data = json.load(f)
            data.pop("hooks", None)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(settings_file))
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
            os.replace(tmp, settings_file)
        result["hooks_installed"].append("removed: hooks key from settings.local.json")

    return result


def _verify(settings_file: str, hooks_dir: str, method: str,
            hook_names: List[str]) -> List[str]:
    """Post-install verification. Returns list of errors."""
    errors = []

    # Verify settings JSON is valid
    try:
        with open(settings_file, "r") as f:
            data = json.load(f)
        if "hooks" not in data:
            errors.append("settings.local.json missing 'hooks' key")
    except (json.JSONDecodeError, FileNotFoundError) as e:
        errors.append(f"Invalid settings: {e}")

    # Verify hook scripts exist (copy/symlink only)
    if method in ("copy", "symlink"):
        for name in hook_names:
            path = os.path.join(hooks_dir, f"{name}.sh")
            if not os.path.isfile(path):
                errors.append(f"Hook script not found: {path}")
            elif not os.access(path, os.X_OK):
                errors.append(f"Hook script not executable: {path}")

    return errors


def hooks_path(fmt: str = "sh") -> str:
    """Return the directory containing hook scripts in the requested format.

    This is the CloakMCP contract for toolbox integration:
        cloak hooks-path [--format {sh,py,cli}]

    Args:
        fmt: "sh" (POSIX shell), "py" (Python scripts), or "cli" (returns
             the `cloak hook` CLI prefix for direct invocation).

    Returns:
        For sh/py: absolute path to the hooks directory.
        For cli: the string "cloak hook" (toolbox builds the full command).
    """
    if fmt == "cli":
        return "cloak hook"
    return _hooks_source_dir()
