from __future__ import annotations
from .utils import nfc, strip_zero_width

def normalize(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = nfc(text)
    text = strip_zero_width(text)
    return text
