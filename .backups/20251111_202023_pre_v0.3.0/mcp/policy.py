from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import yaml

@dataclass
class PseudonymizationCfg:
    method: str
    secret_key_file: str
    salt: str

@dataclass
class GlobalsCfg:
    default_action: str
    audit_enabled: bool
    audit_path: str
    include_value_hash: bool
    pz: PseudonymizationCfg

@dataclass
class Rule:
    id: str
    type: str
    action: str
    pattern: Optional[str] = None
    template: Optional[str] = None
    whitelist: Optional[List[str]] = None
    whitelist_cidrs: Optional[List[str]] = None
    min_entropy: Optional[float] = None
    min_length: Optional[int] = None

class Policy:
    def __init__(self, raw: Dict[str, Any]) -> None:
        self.version = raw.get("version", 1)
        g = raw.get("globals", {})
        audit = g.get("audit", {})
        pz = g.get("pseudonymization", {})
        self.globals = GlobalsCfg(
            default_action=g.get("default_action", "redact"),
            audit_enabled=bool(audit.get("enabled", True)),
            audit_path=audit.get("path", "./audit/audit.jsonl"),
            include_value_hash=bool(audit.get("include_value_hash", True)),
            pz=PseudonymizationCfg(
                method=pz.get("method", "hmac-sha256"),
                secret_key_file=pz.get("secret_key_file", "./keys/mcp_hmac_key"),
                salt=pz.get("salt", "session"),
            ),
        )
        self.whitelist = raw.get("whitelist", {})
        self.blacklist = raw.get("blacklist", {})
        self.rules: List[Rule] = []
        for r in raw.get("detection", []):
            self.rules.append(
                Rule(
                    id=r["id"],
                    type=r["type"],
                    action=r["action"],
                    pattern=r.get("pattern"),
                    template=r.get("template"),
                    whitelist=r.get("whitelist"),
                    whitelist_cidrs=r.get("whitelist_cidrs"),
                    min_entropy=r.get("min_entropy"),
                    min_length=r.get("min_length"),
                )
            )

    @staticmethod
    def load(path: str) -> "Policy":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return Policy(data)

    def cidr_allowed(self, ip: str, cidrs: Optional[List[str]]) -> bool:
        if not cidrs:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            # Invalid IP address
            return False

        for c in cidrs:
            try:
                if ip_obj in ipaddress.ip_network(c, strict=False):
                    return True
            except ValueError:
                # Invalid CIDR notation, skip this entry
                import sys
                print(f"Warning: Invalid CIDR notation in policy: {c}", file=sys.stderr)
                continue
        return False

    def email_whitelisted(self, email: str) -> bool:
        wl = self.whitelist.get("emails", [])
        for pat in wl:
            if pat.startswith("re:"):
                if re.match(pat[3:], email, flags=re.IGNORECASE):
                    return True
            elif pat.startswith("*@"):
                domain = pat[2:].lower()
                if email.lower().endswith("@" + domain):
                    return True
            elif email.lower() == pat.lower():
                return True
        return False
