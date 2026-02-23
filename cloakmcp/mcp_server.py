"""CloakMCP MCP Tool Server — raw JSON-RPC over stdio.

Exposes CloakMCP operations as MCP tools for Claude Code integration.
No external SDK dependency — implements the MCP protocol directly.

Security (G5): Tools do NOT accept policy_path from the LLM.
Policy is resolved at server startup and pinned for all tool calls.

Usage:
    cloak-mcp-server          # launched by Claude Code via .mcp.json
    python -m cloakmcp.mcp_server  # manual testing

Protocol: JSON-RPC 2.0 over stdin/stdout (one JSON object per line).
"""
from __future__ import annotations
import json
import os
import sys
from typing import Any, Dict, List, Optional

from .policy import resolve_policy


# ── G5: Pin policy at module load ─────────────────────────────────

_PINNED_POLICY: Optional[str] = None


def _get_pinned_policy() -> str:
    """Return the pinned policy path, resolving on first call."""
    global _PINNED_POLICY
    if _PINNED_POLICY is None:
        _PINNED_POLICY = resolve_policy()
    return _PINNED_POLICY


# ── Tool definitions (G5: no policy_path parameter) ───────────────

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "cloak_scan_text",
        "description": (
            "Scan text for secrets (emails, AWS keys, JWTs, IPs, etc.) "
            "using the CloakMCP policy engine. Returns matches without modifying text."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to scan for secrets"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "cloak_pack_text",
        "description": (
            "Replace secrets in text with deterministic vault tags (TAG-xxxxxxxxxxxx). "
            "Tags are stored in the encrypted vault for later restoration."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text containing secrets to pack"},
                "prefix": {"type": "string", "description": "Tag prefix (default: TAG)", "default": "TAG"},
                "project_root": {"type": "string", "description": "Project root for vault (default: .)"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "cloak_unpack_text",
        "description": (
            "Restore vault tags (TAG-xxxxxxxxxxxx) in text back to original secrets. "
            "Requires access to the project's encrypted vault."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text containing vault tags to restore"},
                "project_root": {"type": "string", "description": "Project root for vault (default: .)"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "cloak_vault_stats",
        "description": "Get statistics about the project's encrypted vault (total secrets, unique tags).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_root": {"type": "string", "description": "Project root for vault (default: .)"},
            },
            "required": [],
        },
    },
    {
        "name": "cloak_pack_dir",
        "description": (
            "Pack an entire directory: replace all secrets with vault tags across all files. "
            "Respects .mcpignore for file exclusions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "dir": {"type": "string", "description": "Directory to pack"},
                "prefix": {"type": "string", "description": "Tag prefix (default: TAG)", "default": "TAG"},
            },
            "required": ["dir"],
        },
    },
    {
        "name": "cloak_unpack_dir",
        "description": (
            "Unpack an entire directory: restore all vault tags to original secrets. "
            "Requires access to the project's encrypted vault."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "dir": {"type": "string", "description": "Directory to unpack"},
            },
            "required": ["dir"],
        },
    },
]


# ── Protocol helpers ────────────────────────────────────────────

SERVER_INFO = {
    "name": "cloakmcp",
    "version": __import__("cloakmcp").__version__,
}

CAPABILITIES = {
    "tools": {},
}


def _jsonrpc_response(id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id, "result": result}


def _jsonrpc_error(id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": id, "error": err}


def _send(msg: Dict[str, Any]) -> None:
    """Write a JSON-RPC message to stdout."""
    line = json.dumps(msg, ensure_ascii=False)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _log(message: str) -> None:
    """Write a log/notification to stderr (not part of protocol)."""
    print(f"[cloakmcp] {message}", file=sys.stderr, flush=True)


# ── Tool handlers (G5: use pinned policy) ─────────────────────────

def _handle_cloak_scan_text(args: Dict[str, Any]) -> Dict[str, Any]:
    from .policy import Policy
    from .scanner import scan
    from .normalizer import normalize

    text = args["text"]
    policy = Policy.load(_get_pinned_policy())
    norm = normalize(text)
    matches = scan(norm, policy)

    return {
        "count": len(matches),
        "matches": [
            {
                "rule_id": m.rule.id,
                "rule_type": m.rule.type,
                "action": m.rule.action,
                "start": m.start,
                "end": m.end,
                "length": m.end - m.start,
            }
            for m in matches
        ],
    }


def _handle_cloak_pack_text(args: Dict[str, Any]) -> Dict[str, Any]:
    from .filepack import pack_text
    from .policy import Policy
    from .storage import Vault

    text = args["text"]
    prefix = args.get("prefix", "TAG")
    project_root = args.get("project_root", ".")

    policy = Policy.load(_get_pinned_policy())
    vault = Vault(project_root)
    packed, count = pack_text(text, policy, vault, prefix=prefix)

    return {"packed": packed, "count": count}


def _handle_cloak_unpack_text(args: Dict[str, Any]) -> Dict[str, Any]:
    from .filepack import unpack_text
    from .storage import Vault

    text = args["text"]
    project_root = args.get("project_root", ".")

    vault = Vault(project_root)
    unpacked, count = unpack_text(text, vault)

    return {"unpacked": unpacked, "count": count}


def _handle_cloak_vault_stats(args: Dict[str, Any]) -> Dict[str, Any]:
    from .storage import Vault

    project_root = args.get("project_root", ".")
    vault = Vault(project_root)
    stats = vault.get_stats()

    return {
        "total_secrets": stats["total_secrets"],
        "unique_tags": stats["unique_tags"],
        "vault_path": vault.vault_path,
    }


def _handle_cloak_pack_dir(args: Dict[str, Any]) -> Dict[str, Any]:
    from .dirpack import pack_dir
    from .policy import Policy

    dir_path = args["dir"]
    prefix = args.get("prefix", "TAG")

    if not os.path.isdir(dir_path):
        raise ValueError(f"Directory not found: {dir_path}")

    policy = Policy.load(_get_pinned_policy())
    # Pack with no backup (MCP context — hooks handle backups)
    pack_dir(dir_path, policy, prefix=prefix, backup=False)

    return {"status": "ok", "dir": os.path.abspath(dir_path)}


def _handle_cloak_unpack_dir(args: Dict[str, Any]) -> Dict[str, Any]:
    from .dirpack import unpack_dir

    dir_path = args["dir"]
    if not os.path.isdir(dir_path):
        raise ValueError(f"Directory not found: {dir_path}")

    unpack_dir(dir_path, backup=False)

    return {"status": "ok", "dir": os.path.abspath(dir_path)}


TOOL_HANDLERS = {
    "cloak_scan_text": _handle_cloak_scan_text,
    "cloak_pack_text": _handle_cloak_pack_text,
    "cloak_unpack_text": _handle_cloak_unpack_text,
    "cloak_vault_stats": _handle_cloak_vault_stats,
    "cloak_pack_dir": _handle_cloak_pack_dir,
    "cloak_unpack_dir": _handle_cloak_unpack_dir,
}


# ── Request dispatch ────────────────────────────────────────────

def _handle_request(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Handle a single JSON-RPC request. Returns response or None for notifications."""
    method = req.get("method", "")
    req_id = req.get("id")
    params = req.get("params", {})

    # Notifications (no id) — no response expected
    if req_id is None:
        if method == "notifications/initialized":
            _log("Client initialized")
        return None

    # Initialize
    if method == "initialize":
        return _jsonrpc_response(req_id, {
            "protocolVersion": "2024-11-05",
            "serverInfo": SERVER_INFO,
            "capabilities": CAPABILITIES,
        })

    # List tools
    if method == "tools/list":
        return _jsonrpc_response(req_id, {"tools": TOOLS})

    # Call tool
    if method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})

        handler = TOOL_HANDLERS.get(tool_name)
        if handler is None:
            return _jsonrpc_error(req_id, -32601, f"Unknown tool: {tool_name}")

        try:
            result = handler(tool_args)
            return _jsonrpc_response(req_id, {
                "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
            })
        except Exception as e:
            return _jsonrpc_response(req_id, {
                "content": [{"type": "text", "text": f"Error: {e}"}],
                "isError": True,
            })

    # Ping
    if method == "ping":
        return _jsonrpc_response(req_id, {})

    return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")


# ── Main loop ──────────────────────────────────────────────────

def run_server() -> None:
    """Run the MCP stdio server (blocking main loop)."""
    policy = _get_pinned_policy()
    _log(f"Starting CloakMCP MCP server (stdio), policy={policy}")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            _send(_jsonrpc_error(None, -32700, f"Parse error: {e}"))
            continue

        response = _handle_request(req)
        if response is not None:
            _send(response)


def main() -> None:
    """Entry point for cloak-mcp-server."""
    run_server()


if __name__ == "__main__":
    main()
