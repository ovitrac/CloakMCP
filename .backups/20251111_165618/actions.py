\
from __future__ import annotations
from dataclasses import dataclass
from .policy import Policy, Rule
from .utils import sha256_hex, base62_short
import hmac, hashlib

@dataclass
class ActionResult:
    replacement: str
    blocked: bool = False
    value_hash: str | None = None

def _hash_preview(value: str) -> str:
    return sha256_hex(value.encode("utf-8"))[:16]

def _pz(policy: Policy, value: str) -> str:
    # HMAC with user-provided key file path in policy.globals.pz.secret_key_file
    with open(policy.globals.pz.secret_key_file, "rb") as f:
        key = f.read().strip()
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
