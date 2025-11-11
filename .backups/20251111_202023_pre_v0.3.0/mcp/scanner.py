from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Iterable, List

from .policy import Policy, Rule

EMAIL_RE = re.compile(r"(?i)[a-z0-9_.+\-]+@[a-z0-9\-]+\.[a-z0-9.\-]+")
JWT_RE = re.compile(r"\b[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b")
PEM_CERT_RE = re.compile(r"(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----")
SSH_PRIV_RE = re.compile(r"(?s)-----BEGIN (?:OPENSSH|RSA|DSA|EC|ED25519) PRIVATE KEY-----.*?-----END .*? PRIVATE KEY-----")
AWS_KEY_RE = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")
GCP_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
AZURE_LIKE_RE = re.compile(r"\b[0-9A-Za-z+/]{43}=\b")
URL_RE = re.compile(r"\b(https?://[^\s)>\]}\"']+)")
IPv4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b")
IPv6_RE = re.compile(r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b", re.I)
BASE64ISH_RE = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")

@dataclass
class Match:
    rule: Rule
    start: int
    end: int
    value: str

def shannon_entropy(s: str) -> float:
    import math
    from collections import Counter
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())

def _iter_regex(pattern: re.Pattern, text: str, rule: Rule) -> Iterable[Match]:
    for m in pattern.finditer(text):
        yield Match(rule, m.start(), m.end(), m.group(0))

def scan(text: str, policy: Policy) -> List[Match]:
    matches: List[Match] = []
    for rule in policy.rules:
        if rule.type == "regex" and rule.pattern:
            pattern = re.compile(rule.pattern)
            matches.extend(_iter_regex(pattern, text, rule))
        elif rule.type == "ipv4":
            for m in IPv4_RE.finditer(text):
                ip = m.group(0)
                if rule.whitelist_cidrs and policy.cidr_allowed(ip, rule.whitelist_cidrs):
                    continue
                matches.append(Match(rule, m.start(), m.end(), ip))
        elif rule.type == "ipv6":
            for m in IPv6_RE.finditer(text):
                matches.append(Match(rule, m.start(), m.end(), m.group(0)))
        elif rule.type == "url":
            for m in URL_RE.finditer(text):
                matches.append(Match(rule, m.start(), m.end(), m.group(0)))
        elif rule.type == "entropy":
            for m in BASE64ISH_RE.finditer(text):
                s = m.group(0)
                if rule.min_length and len(s) < rule.min_length:
                    continue
                if rule.min_entropy and shannon_entropy(s) < float(rule.min_entropy):
                    continue
                matches.append(Match(rule, m.start(), m.end(), s))
    matches.sort(key=lambda x: (x.start, x.end))
    return matches
