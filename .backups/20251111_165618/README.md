# CloakMCP — Micro‑Cleanse Preprocessor (Local Secret Removal)

Local-first, deterministic sanitizer that removes or neutralizes secrets (emails, IPs, URLs, tokens, keys, PII) **before** text/code is sent to an unsecured LLM/MLM. Runs as a CLI or an optional localhost API.

- 📜 MIT license, authorship preserved
- ⚙️ YAML policy: whitelist/blacklist and actions (allow, redact, pseudonymize, block, etc.)
- 🧪 Strong tests, type hints, pre-commit friendly
- 🔒 No outbound network calls in the hot path

## Quickstart
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
mkdir -p keys audit && openssl rand -hex 32 > keys/mcp_hmac_key

# dry-run scan (no modification; writes audit logs)
mcp scan --policy examples/mcp_policy.yaml --input examples/client_sanitize.py

# sanitize and print to stdout
mcp sanitize --policy examples/mcp_policy.yaml --input examples/client_sanitize.py --output -
```

## Local API
```bash
openssl rand -hex 32 > keys/mcp_api_token
uvicorn mcp.server:app --host 127.0.0.1 --port 8765
```

Read `examples/mcp_policy.yaml` to tune detection rules and actions.
