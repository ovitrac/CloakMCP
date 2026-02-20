<div align="center">

# CloakMCP Demo

### Your secrets stay home. The AI only sees tags.

</div>

---

## The Problem

Every time you paste code into ChatGPT, Claude, or Copilot, **your secrets go with it**:

```java
private static final String API_KEY  = "sk_live_51Jd9RealKeyGoesHere";
private static final String DB_PASS  = "P@ssw0rd-Pr0duction!";
private static final String AWS_KEY  = "AKIAIOSFODNN7REALKEY1";
```

That API key is now stored on someone else's servers. Forever.

## The Solution

CloakMCP replaces secrets with opaque tags **before** the code leaves your machine. The AI sees the structure, the logic, the architecture — but **zero real credentials**:

```java
private static final String API_KEY  = "https://ops.internal.company.local/webhooks/transfer";
private static final String DB_PASS  = "payments_admin@internal.company";
private static final String AWS_KEY  = "AKIAIOSFODNN7EXAMPLE";
```

When you're done, one command restores everything. **Lossless round-trip. Zero secrets leaked.**

---

## How It Works

```
 YOUR MACHINE                          CLOUD / LLM
 ──────────                            ──────────

 ┌──────────────────┐    cloak pack     ┌─────────────────────┐
 │  Source Code     │ ───────────────►  │  Tagged Code        │
 │                  │                   │                     │
 │  API_KEY="sk_…"  │                   │  API_KEY="TAG-a1b2" │
 │  DB_PASS="P@ss"  │                   │  DB_PASS="TAG-c3d4" │
 │  AWS="AKIA…"     │                   │  AWS="TAG-e5f6"     │
 └────────┬─────────┘                   └──────────┬──────────┘
          │                                        │
          │  secrets                               │  safe to send
          ▼                                        ▼
 ┌──────────────────┐                   ┌─────────────────────┐
 │  Encrypted Vault │                   │  Claude / Codex /   │
 │  ~/.cloakmcp/    │                   │  Copilot / Gemini   │
 │  (AES-128)       │                   │                     │
 │  TAG-a1b2→"sk_…" │                   │  "This code handles │
 │  TAG-c3d4→"P@ss" │                   │   bank transfers…"  │
 └────────┬─────────┘                   └──────────┬──────────┘
          │                                        │
          │  cloak unpack                          │  AI output
          ▼                                        ▼
 ┌──────────────────┐                   ┌─────────────────────┐
 │  Restored Code   │                   │  Refactored code    │
 │  (identical)     │ ◄─── merge ─────  │  (tags preserved)   │
 │  API_KEY="sk_…"  │                   │  API_KEY="TAG-a1b2" │
 └──────────────────┘                   └─────────────────────┘
```

**The vault never leaves your machine. The LLM never sees the secrets. The round-trip is lossless.**

---

## What's In This Demo

A realistic **Spring Boot banking microservice** (`BankTransferService.java`) with:

| Secret Type | Count | Examples |
|---|---|---|
| API keys | 2 | `sk_live_51Jd9FAKE…`, `AKIAIOSFODNN7EXAMPLE` |
| Passwords | 3 | DB, SMTP, webhook secrets |
| SSH private key | 1 | Full PEM block |
| JWT token | 1 | 3-part base64 token |
| Internal URLs | 5 | `https://ops.internal.company.local/…` |
| Email addresses | 4 | `payments_admin@internal.company` |
| IP addresses | 1 | `10.12.34.56` |

**3 config files**: `BankTransferService.java`, `application.properties`, `application.yml`
**Maven scaffold**: `pom.xml` (non-operational, for realism)

---

## Demo Scripts

### 1. Live LLM Demo (the highlight)

Packs the code, asks a **real LLM** to explain it, proves the AI understands the logic without seeing secrets:

```bash
cd demo && bash llm_demo.sh
```

Supports **Ollama** (local) and **Claude Code CLI**:
```bash
bash llm_demo.sh --ollama     # force local Ollama
bash llm_demo.sh --claude     # force Claude Code
```

<details>
<summary><b>Sample output — Qwen2.5-coder explains cloaked banking code</b></summary>

```
▶ Asking Ollama (qwen2.5-coder:14b) to explain the cloaked code...

  This Java class simulates a high-value transfer workflow in a banking
  system, focusing on the handling of sensitive information and secure
  integrations. The business logic involves checking if the transfer
  amount exceeds a threshold for compliance, creating a transfer intent,
  simulating signing with an HSM key, calling a payment gateway,
  persisting data to a database, sending a confirmation email, notifying
  operations via a webhook, and archiving audit trails to AWS S3.
```

**The LLM understood 8 workflow steps, compliance logic, and integrations — zero real credentials seen.**

</details>

### 2. MCP Protocol Demo

Shows CloakMCP working as an **MCP tool server** — the same protocol Claude Code uses:

```bash
cd demo && bash mcp_demo.sh              # raw JSON-RPC protocol
cd demo && bash mcp_demo.sh --claude     # + full hook lifecycle with live LLM
```

**Part 1** (always): raw JSON-RPC handshake: `initialize` → `tools/list` → `cloak_scan_text` → `cloak_pack_text` → `cloak_unpack_text`.

**Part 2** (`--claude`): full hook lifecycle demo — simulates what happens in a real Claude Code session:

1. **SessionStart hook** fires → `cloak pack` (automatic, hidden)
2. An LLM (Ollama or Claude) **explains the cloaked code** — sees only TAG-xxxx tokens
3. **SessionEnd hook** fires → `cloak unpack` (automatic, hidden)

Zero human intervention. Hooks + MCP make secret protection completely transparent.

### 3. Before/After Transcript

Screenshot-friendly, non-interactive output showing exact diffs across all files:

```bash
cd demo && bash transcript.sh            # colored terminal
cd demo && bash transcript.sh > out.txt  # plain text for docs
```

6 phases: ORIGINAL → PACK → DIFF → UNPACK → VERIFY → VAULT STATS

### 4. Interactive Demo

Step-by-step walkthrough with pause-between-acts (for live presentations):

```bash
cd demo && bash run_demo.sh
```

5 acts with colored output and keyboard prompts.

---

## Quick Start

```bash
# From the project root
cd CloakMCP
pip install -e .
mkdir -p keys && openssl rand -hex 32 > keys/mcp_hmac_key

# Run the LLM demo
cd demo && bash llm_demo.sh
```

---

## What Gets Detected

| Secret Type | Example | What the LLM Sees |
|---|---|---|
| AWS keys | `AKIAIOSFODNN7EXAMPLE` | `AKIAIOSFODNN7EXAMPLE` |
| SSH private keys | `-----BEGIN OPENSSH PRIVATE KEY-----` | `-----BEGIN OPENSSH PRIVATE KEY-----\n" +
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\n" +
            "c2gtZWQyNTUxOQAAACDFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAAAAA\n" +
            "-----END OPENSSH PRIVATE KEY-----` |
| URLs (internal) | `https://api.internal.company.local/v2` | `https://ops.internal.company.local/webhooks/transfer` |
| Email addresses | `admin@internal.company` | `payments_admin@internal.company` |
| JWT tokens | `eyJhbGciOi...` | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abcDEF123_fake_payload.abcDEF123_fake_sig` |
| IP addresses | `10.12.34.56` | `10.12.34` |
| High-entropy blobs | `wJalrXUtnFEMI/K7MDENG...` | `TAG-4bbfdab64f59` |
| X.509 certificates | `-----BEGIN CERTIFICATE-----` | Blocked |

**Same secret = same tag** everywhere in the codebase (deterministic HMAC-SHA256).

---

## File Structure

```
demo/
├── README.md                          ← you are here
├── llm_demo.sh                        ← Live LLM demo (Ollama / Claude)
├── mcp_demo.sh                        ← MCP protocol demo (JSON-RPC)
├── transcript.sh                      ← Screenshot-friendly before/after
├── run_demo.sh                        ← Interactive 5-act presentation
├── .mcpignore                         ← Excludes pom.xml from packing
├── pom.xml                            ← Maven scaffold (non-operational)
└── src/
    └── main/
        ├── java/com/acme/payments/
        │   └── BankTransferService.java   ← 113 LOC, 10+ fake secrets
        └── resources/
            ├── application.properties     ← Spring config (fake creds)
            └── application.yml            ← YAML config (fake creds)
```

---

<div align="center">

*"Claude may read, refactor, or reason on tagged data —
but never unmask what the vault keeps safe."*

**[Back to CloakMCP](../README.md)**

</div>
