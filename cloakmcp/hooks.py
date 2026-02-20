"""Hook handlers for Claude Code integration.

All JSON parsing and logic lives here. Shell scripts are thin wrappers:
    stdin (Claude JSON) -> cloak hook <event> -> stdout (hook response JSON)

Safety invariants:
- Strict JSON parsing (Python json module, never regex scraping)
- Hard failure = safe: if parsing fails, emit warning additionalContext
- No shell interpolation of extracted content
- Single testable Python path for all hook logic
"""
from __future__ import annotations
import json
import os
import sys
from typing import Any, Dict, Optional, Tuple

from .dirpack import pack_dir, unpack_dir
from .filepack import pack_text, TAG_RE
from .policy import Policy
from .scanner import scan
from .normalizer import normalize
from .storage import Vault

SESSION_STATE_FILE = ".cloak-session-state"
DEFAULT_POLICY = "examples/mcp_policy.yaml"
DEFAULT_PREFIX = "TAG"


def _find_policy() -> str:
    """Find the policy file — check env, then default location."""
    env = os.environ.get("CLOAK_POLICY")
    if env and os.path.isfile(env):
        return env
    if os.path.isfile(DEFAULT_POLICY):
        return DEFAULT_POLICY
    return ""


def _read_stdin_json() -> Optional[Dict[str, Any]]:
    """Read and parse JSON from stdin. Returns None on failure."""
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return None
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _emit_json(data: Dict[str, Any]) -> None:
    """Write JSON response to stdout."""
    json.dump(data, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    sys.stdout.flush()


def _write_state(project_dir: str, policy_path: str, prefix: str) -> None:
    """Write session state marker."""
    state = {
        "policy": policy_path,
        "prefix": prefix,
        "project_dir": os.path.abspath(project_dir),
    }
    state_path = os.path.join(project_dir, SESSION_STATE_FILE)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f)


def _read_state(project_dir: str) -> Optional[Dict[str, Any]]:
    """Read session state marker. Returns None if absent."""
    state_path = os.path.join(project_dir, SESSION_STATE_FILE)
    if not os.path.isfile(state_path):
        return None
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _remove_state(project_dir: str) -> None:
    """Remove session state marker."""
    state_path = os.path.join(project_dir, SESSION_STATE_FILE)
    if os.path.isfile(state_path):
        os.remove(state_path)


# ── Hook handlers ───────────────────────────────────────────────


def handle_session_start(project_dir: str = ".") -> Dict[str, Any]:
    """Handle SessionStart hook: pack directory and write state marker.

    Returns:
        Hook response JSON with additionalContext or error info
    """
    project_dir = os.path.abspath(project_dir)

    # Check for stale session state (abnormal previous exit)
    existing_state = _read_state(project_dir)
    if existing_state is not None:
        # Already packed — skip re-packing, warn user
        return {
            "additionalContext": (
                "[CloakMCP] WARNING: Stale session state detected. "
                "Files may already be packed from a previous session. "
                "Run `cloak recover --dir .` if secrets need restoring."
            )
        }

    # Find policy
    policy_path = _find_policy()
    if not policy_path:
        return {
            "additionalContext": (
                "[CloakMCP] No policy file found. "
                "Set CLOAK_POLICY env or place examples/mcp_policy.yaml. "
                "Secrets are NOT protected this session."
            )
        }

    prefix = os.environ.get("CLOAK_PREFIX", DEFAULT_PREFIX)

    try:
        policy = Policy.load(policy_path)
        pack_dir(project_dir, policy, prefix=prefix, backup=True)
        _write_state(project_dir, policy_path, prefix)
    except Exception as e:
        return {
            "additionalContext": (
                f"[CloakMCP] Pack failed: {e}. "
                "Secrets are NOT protected this session."
            )
        }

    return {
        "additionalContext": (
            "[CloakMCP] Session started. All files have been packed — "
            "secrets replaced by deterministic tags (TAG-xxxxxxxxxxxx). "
            "Do NOT manually alter tag syntax. "
            "Secrets will be restored automatically when the session ends."
        )
    }


def handle_session_end(project_dir: str = ".") -> Dict[str, Any]:
    """Handle SessionEnd hook: unpack directory and remove state marker.

    Returns:
        Hook response JSON (empty on success)
    """
    project_dir = os.path.abspath(project_dir)

    state = _read_state(project_dir)
    if state is None:
        # Not packed — nothing to do
        return {}

    try:
        unpack_dir(project_dir, backup=False)
        _remove_state(project_dir)
    except Exception as e:
        print(
            f"[CloakMCP] Unpack failed: {e}. "
            "Run `cloak recover --dir .` manually.",
            file=sys.stderr,
        )
        return {}

    return {}


def handle_guard_write(project_dir: str = ".") -> Dict[str, Any]:
    """Handle PreToolUse guard for Write/Edit: scan content for raw secrets.

    Reads Claude hook JSON from stdin, extracts file content,
    scans for secrets, and emits a warning if any are found.
    This is advisory only — never blocks the operation.

    Returns:
        Hook response JSON (with additionalContext warning if secrets found)
    """
    project_dir = os.path.abspath(project_dir)

    # Parse hook input JSON
    hook_input = _read_stdin_json()
    if hook_input is None:
        return {}

    # Extract content to scan from the tool input
    tool_input = hook_input.get("tool_input", {})
    content = tool_input.get("content", "")
    new_string = tool_input.get("new_string", "")
    text_to_scan = content or new_string

    if not text_to_scan:
        return {}

    # Find policy
    policy_path = _find_policy()
    if not policy_path:
        return {}

    try:
        policy = Policy.load(policy_path)
        norm = normalize(text_to_scan)
        matches = scan(norm, policy)
    except Exception:
        return {}

    if not matches:
        return {}

    # Build warning with match summary (no secret values exposed)
    rule_ids = sorted({m.rule.id for m in matches})
    return {
        "additionalContext": (
            f"[CloakMCP] WARNING: {len(matches)} potential secret(s) detected "
            f"in content being written (rules: {', '.join(rule_ids)}). "
            "Consider using vault tags instead of raw values."
        )
    }


def handle_recover(project_dir: str = ".") -> None:
    """Detect stale session state and run unpack.

    Used for manual recovery after abnormal session exit.
    """
    project_dir = os.path.abspath(project_dir)

    state = _read_state(project_dir)
    if state is None:
        print("No stale session state found. Nothing to recover.", file=sys.stderr)
        return

    print(f"Found stale session state: {json.dumps(state, indent=2)}", file=sys.stderr)
    print("Unpacking...", file=sys.stderr)

    try:
        unpack_dir(project_dir, backup=False)
        _remove_state(project_dir)
        print("Recovery complete. Secrets restored.", file=sys.stderr)
    except Exception as e:
        print(f"Recovery failed: {e}", file=sys.stderr)
        sys.exit(1)


# ── Main dispatcher (called by `cloak hook <event>`) ────────────


def dispatch_hook(event: str, project_dir: str = ".") -> None:
    """Dispatch hook event to appropriate handler.

    Args:
        event: One of 'session-start', 'session-end', 'guard-write'
        project_dir: Project root directory
    """
    handlers = {
        "session-start": handle_session_start,
        "session-end": handle_session_end,
        "guard-write": handle_guard_write,
    }

    handler = handlers.get(event)
    if handler is None:
        print(f"Unknown hook event: {event}", file=sys.stderr)
        sys.exit(1)

    result = handler(project_dir)
    if result:
        _emit_json(result)
