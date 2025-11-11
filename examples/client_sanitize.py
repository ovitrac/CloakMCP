from __future__ import annotations
import json, urllib.request

TOKEN = open("keys/mcp_api_token").read().strip()
url = "http://127.0.0.1:8765/sanitize"
payload = {"text": "Email: bob@internal.company\nToken: AKIAABCDEFGHIJKLMNOP\n", "dry_run": False}
req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST")
req.add_header("Content-Type", "application/json")
req.add_header("Authorization", f"Bearer {TOKEN}")
print(urllib.request.urlopen(req).read().decode())
