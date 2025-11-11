from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any

def ensure_dir(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)

def write_event(path: str, event: Dict[str, Any]) -> None:
    ensure_dir(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()
