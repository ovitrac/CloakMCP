from __future__ import annotations
from dataclasses import dataclass
from typing import Dict
from .policy import Policy, Rule
from .utils import sha256_hex, base62_short
import hmac, hashlib

# Cache for HMAC keys to avoid repeated disk reads
_key_cache: Dict[str, bytes] = {}

@dataclass
class ActionResult:
    replacement: str
    blocked: bool = False
    value_hash: str | None = None

def _hash_preview(value: str) -> str:
    return sha256_hex(value.encode("utf-8"))[:16]

def _load_hmac_key(key_path: str) -> bytes:
    """Load and cache HMAC key from file."""
    if key_path not in _key_cache:
        with open(key_path, "rb") as f:
            key = f.read().strip()
        # Validate key length (at least 32 bytes for security)
        if len(key) < 32:
            import sys
            print(f"Warning: HMAC key is short ({len(key)} bytes). Recommend >= 32 bytes.", file=sys.stderr)
        _key_cache[key_path] = key
    return _key_cache[key_path]

def _pz(policy: Policy, value: str) -> str:
    # HMAC with cached key
    key = _load_hmac_key(policy.globals.pz.secret_key_file)
    salt = "" if policy.globals.pz.salt == "session" else str(policy.globals.pz.salt)
    digest = hmac.new(key, f"{salt}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"PZ-{base62_short(digest, n=10)}"

def apply_action(rule: Rule, value: str, policy: Policy) -> ActionResult:
    vh = _hash_preview(value) if policy.globals.include_value_hash else None

    if rule.action == "allow":
        return ActionResult(replacement=value, blocked=False, value_hash=vh)
    if rule.action == "block":
        return ActionResult(replacement="", blocked=True, value_hash=vh)
    if rule.action == "redact":
        return ActionResult(replacement=f"<REDACTED:{rule.id}>", blocked=False, value_hash=vh)
    if rule.action == "pseudonymize":
        return ActionResult(replacement=_pz(policy, value), blocked=False, value_hash=vh)
    if rule.action == "hash":
        return ActionResult(replacement=f"HASH-{_hash_preview(value)}", blocked=False, value_hash=vh)
    if rule.action == "replace_with_template":
        h = sha256_hex(value.encode("utf-8"))
        rep = (rule.template or "<REDACTED>").replace("{hash}", h).replace("{hash8}", h[:8]).replace("{len}", str(len(value)))
        return ActionResult(replacement=rep, blocked=False, value_hash=vh)
    return ActionResult(replacement=f"<REDACTED:{rule.id}>", blocked=False, value_hash=vh)
