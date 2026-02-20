from __future__ import annotations
import hashlib
import hmac
import re
import unicodedata
from typing import Optional

ZERO_WIDTH_RE = re.compile(r"[\u200B\u200C\u200D\uFEFF]")

def nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)

def strip_zero_width(text: str) -> str:
    return ZERO_WIDTH_RE.sub("", text)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def base62_short(hex_str: str, n: int = 8) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    part = hex_str[: n * 2]
    value = int(part, 16) if part else 0
    out = []
    while value > 0:
        value, rem = divmod(value, 62)
        out.append(alphabet[rem])
    s = "".join(reversed(out)) or "0"
    return s[:n]
