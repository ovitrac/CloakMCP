"""CloakMCP FastMCP Server — MCP tool server via FastMCP.

Wraps the 6 CloakMCP tools for stdio and network transport.

Usage:
    cloak serve                                    # stdio (default)
    cloak serve --transport sse --port 8766        # SSE network
    cloak serve --check                            # validate and exit
"""
from __future__ import annotations

import argparse
import os
from os.path import isfile, isdir, abspath
from typing import Any, Dict, Optional


_MCP_INSTRUCTIONS = (
    "CloakMCP: local secret sanitization for LLM safety (6 tools).\n"
    "\n"
    "SCAN:   cloak_scan_text  -- detect secrets without modification\n"
    "PACK:   cloak_pack_text / cloak_pack_dir  -- replace secrets with vault tags\n"
    "UNPACK: cloak_unpack_text / cloak_unpack_dir  -- restore from vault\n"
    "STATS:  cloak_vault_stats  -- encrypted vault statistics\n"
    "\n"
    "Rules:\n"
    "- Secrets are replaced with deterministic TAG-xxxxxxxxxxxx tokens\n"
    "- Tags map to encrypted vault entries (Fernet AES-128, HMAC-SHA256)\n"
    "- Same secret always produces the same tag (HMAC determinism)\n"
    "- Vault never leaves the local machine\n"
)


def _resolve_policy(explicit: Optional[str] = None) -> str:
    """Resolve policy path: explicit > CLOAK_POLICY env > default."""
    if explicit and isfile(explicit):
        return explicit
    if explicit:
        raise FileNotFoundError(f"Policy not found: {explicit}")
    env = os.getenv("CLOAK_POLICY")
    if env and isfile(env):
        return env
    default = "examples/mcp_policy.yaml"
    if isfile(default):
        return default
    raise FileNotFoundError(
        "No policy found. Set CLOAK_POLICY env or pass policy_path."
    )


def build_parser() -> argparse.ArgumentParser:
    """Build argument parser for the FastMCP server."""
    p = argparse.ArgumentParser(description="CloakMCP FastMCP server")
    p.add_argument("--policy", default=None,
                   help="Path to YAML policy file")
    p.add_argument("--prefix", default="TAG",
                   help="Tag prefix for pack operations (default: TAG)")
    return p


def create_server(args=None):
    """Create and configure the FastMCP server with CloakMCP tools.

    Returns:
        (mcp_server, None) tuple.
    """
    from mcp.server.fastmcp import FastMCP

    if args is None:
        args = build_parser().parse_args()

    _policy = getattr(args, "policy", None)
    _prefix = getattr(args, "prefix", "TAG")

    mcp = FastMCP(
        name="cloakmcp",
        instructions=_MCP_INSTRUCTIONS,
    )

    # Inject CloakMCP version into MCP server info
    import cloakmcp
    if hasattr(mcp, "_mcp_server"):
        mcp._mcp_server.version = cloakmcp.__version__

    # ── Tool registration ──────────────────────────────────

    @mcp.tool()
    def cloak_scan_text(
        text: str,
        policy_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Scan text for secrets using CloakMCP policy engine.

        Returns matches without modifying text.
        """
        from .policy import Policy
        from .scanner import scan
        from .normalizer import normalize

        pol = Policy.load(_resolve_policy(policy_path or _policy))
        norm = normalize(text)
        matches = scan(norm, pol)
        return {
            "count": len(matches),
            "matches": [
                {
                    "rule_id": r.id,
                    "rule_type": r.type,
                    "action": r.action,
                    "start": m.start,
                    "end": m.end,
                    "length": m.end - m.start,
                }
                for m in matches
                for r in [m.rule]
            ],
        }

    @mcp.tool()
    def cloak_pack_text(
        text: str,
        policy_path: Optional[str] = None,
        prefix: Optional[str] = None,
        project_root: str = ".",
    ) -> Dict[str, Any]:
        """Replace secrets with deterministic vault tags (TAG-xxxxxxxxxxxx).

        Tags are stored in the encrypted vault for later restoration.
        """
        from .filepack import pack_text
        from .policy import Policy
        from .storage import Vault

        pol = Policy.load(_resolve_policy(policy_path or _policy))
        vault = Vault(project_root)
        packed, count = pack_text(text, pol, vault, prefix=prefix or _prefix)
        return {"packed": packed, "count": count}

    @mcp.tool()
    def cloak_unpack_text(
        text: str,
        project_root: str = ".",
    ) -> Dict[str, Any]:
        """Restore vault tags back to original secrets.

        Requires access to the project encrypted vault.
        """
        from .filepack import unpack_text
        from .storage import Vault

        vault = Vault(project_root)
        unpacked, count = unpack_text(text, vault)
        return {"unpacked": unpacked, "count": count}

    @mcp.tool()
    def cloak_vault_stats(
        project_root: str = ".",
    ) -> Dict[str, Any]:
        """Get statistics about the encrypted vault."""
        from .storage import Vault

        vault = Vault(project_root)
        stats = vault.get_stats()
        return {
            "total_secrets": stats["total_secrets"],
            "unique_tags": stats["unique_tags"],
            "vault_path": vault.vault_path,
        }

    @mcp.tool()
    def cloak_pack_dir(
        dir: str,
        policy_path: Optional[str] = None,
        prefix: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Pack entire directory: replace all secrets with vault tags.

        Respects .mcpignore for file exclusions.
        """
        from .dirpack import pack_dir
        from .policy import Policy

        if not isdir(dir):
            raise ValueError(f"Directory not found: {dir}")
        pol = Policy.load(_resolve_policy(policy_path or _policy))
        pack_dir(dir, pol, prefix=prefix or _prefix, backup=False)
        return {"status": "ok", "dir": abspath(dir)}

    @mcp.tool()
    def cloak_unpack_dir(
        dir: str,
    ) -> Dict[str, Any]:
        """Unpack entire directory: restore all vault tags to original secrets.

        Requires access to the project encrypted vault.
        """
        from .dirpack import unpack_dir

        if not isdir(dir):
            raise ValueError(f"Directory not found: {dir}")
        unpack_dir(dir, backup=False)
        return {"status": "ok", "dir": abspath(dir)}

    return mcp, None
