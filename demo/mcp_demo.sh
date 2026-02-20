#!/bin/bash
# ============================================================================
# CloakMCP — MCP Protocol Demo
# ============================================================================
#
# Demonstrates CloakMCP as an MCP tool server:
#   1. Raw JSON-RPC protocol (initialize → tools/list → scan → pack → unpack)
#   2. Optional: Claude Code CLI using MCP tools live
#
# Usage:
#   cd demo && bash mcp_demo.sh              # raw protocol demo
#   cd demo && bash mcp_demo.sh --claude     # also test with Claude Code CLI
#
# Requirements:
#   - CloakMCP installed: pip install -e ..
#   - For --claude: Claude Code CLI (claude --version)
#
# ============================================================================

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────
if [ -t 1 ]; then
    BOLD='\033[1m'
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    CYAN='\033[0;36m'
    YELLOW='\033[1;33m'
    MAGENTA='\033[0;35m'
    DIM='\033[2m'
    NC='\033[0m'
else
    BOLD='' GREEN='' RED='' CYAN='' YELLOW='' MAGENTA='' DIM='' NC=''
fi

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$DEMO_DIR")"
POLICY="$PROJECT_ROOT/examples/mcp_policy.yaml"

USE_CLAUDE=false
for arg in "$@"; do
    [ "$arg" = "--claude" ] && USE_CLAUDE=true
done

banner() {
    echo ""
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

step() {
    echo -e "${BOLD}${GREEN}▶ $1${NC}"
}

show_json() {
    # Pretty-print JSON with label and color
    local label="$1"
    local json="$2"
    local color="$3"
    echo -e "  ${DIM}$label${NC}"
    echo "$json" | python3 -m json.tool 2>/dev/null | while IFS= read -r line; do
        echo -e "  ${color}$line${NC}"
    done
    echo ""
}

# ── Preflight ───────────────────────────────────────────────────
cd "$PROJECT_ROOT"

if ! command -v cloak-mcp-server &>/dev/null; then
    echo -e "${RED}Error: 'cloak-mcp-server' not found. Run: pip install -e $PROJECT_ROOT${NC}"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════
# PART 1: Raw MCP Protocol Demo
# ══════════════════════════════════════════════════════════════════

banner "MCP Protocol Demo — CloakMCP as Tool Server"

echo -e "  CloakMCP exposes 6 tools via the ${BOLD}Model Context Protocol${NC} (MCP)."
echo -e "  Claude Code connects via ${CYAN}JSON-RPC 2.0 over stdio${NC}."
echo -e "  Let's see the raw protocol in action."
echo ""

# ── Step 1: Initialize ──────────────────────────────────────────

step "Step 1: Initialize handshake"
echo ""

INIT_REQ='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"demo","version":"1.0"}}}'
INIT_NOTIF='{"jsonrpc":"2.0","method":"notifications/initialized"}'

INIT_RESP=$(printf '%s\n' "$INIT_REQ" "$INIT_NOTIF" | cloak-mcp-server 2>/dev/null | head -1)

show_json "→ Client sends: initialize" "$INIT_REQ" "$YELLOW"
show_json "← Server responds:" "$INIT_RESP" "$GREEN"

# ── Step 2: List available tools ────────────────────────────────

step "Step 2: List available tools"
echo ""

TOOLS_REQ='{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
TOOLS_RESP=$(printf '%s\n' "$INIT_REQ" "$INIT_NOTIF" "$TOOLS_REQ" | cloak-mcp-server 2>/dev/null | tail -1)

show_json "→ Client sends: tools/list" "$TOOLS_REQ" "$YELLOW"

# Extract just the tool names
echo -e "  ${DIM}← Server responds with 6 tools:${NC}"
echo "$TOOLS_RESP" | python3 -c "
import json, sys
d = json.load(sys.stdin)
tools = d.get('result', {}).get('tools', [])
for t in tools:
    print(f'     {t[\"name\"]:30s}  {t[\"description\"][:60]}')
" 2>/dev/null | while IFS= read -r line; do
    echo -e "  ${GREEN}$line${NC}"
done
echo ""

# ── Step 3: Scan text for secrets ───────────────────────────────

step "Step 3: Scan text for secrets (cloak_scan_text)"
echo ""

SAMPLE_CODE='DB_URL = \"jdbc:postgresql://10.12.34.56:5432/prod\"\nAWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\nEMAIL = \"admin@internal.company\"\nJWT = \"eyJhbGciOiJIUzI1NiJ9.payload.signature\"'

# Build the JSON-RPC request
SCAN_REQ=$(python3 -c "
import json
print(json.dumps({
    'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
    'params': {
        'name': 'cloak_scan_text',
        'arguments': {
            'text': 'DB_URL = \"jdbc:postgresql://10.12.34.56:5432/prod\"\nAWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\nEMAIL = \"admin@internal.company\"\nJWT = \"eyJhbGciOiJIUzI1NiJ9.payload.signature\"',
            'policy_path': '$POLICY'
        }
    }
}))
")

SCAN_RESP=$(printf '%s\n' "$INIT_REQ" "$INIT_NOTIF" "$SCAN_REQ" | cloak-mcp-server 2>/dev/null | tail -1)

echo -e "  ${DIM}Input text:${NC}"
echo -e "  ${RED}DB_URL = \"jdbc:postgresql://10.12.34.56:5432/prod\"${NC}"
echo -e "  ${RED}AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"${NC}"
echo -e "  ${RED}EMAIL = \"admin@internal.company\"${NC}"
echo -e "  ${RED}JWT = \"eyJhbGciOiJIUzI1NiJ9.payload.signature\"${NC}"
echo ""

# Parse scan results
echo -e "  ${DIM}← Scan results:${NC}"
echo "$SCAN_RESP" | python3 -c "
import json, sys
d = json.load(sys.stdin)
content = d.get('result', {}).get('content', [{}])[0].get('text', '{}')
data = json.loads(content)
print(f'     Found {data[\"count\"]} secrets:')
for m in data.get('matches', []):
    print(f'       [{m[\"rule_id\"]:20s}]  action={m[\"action\"]:15s}  chars {m[\"start\"]}-{m[\"end\"]}')
" 2>/dev/null | while IFS= read -r line; do
    echo -e "  ${GREEN}$line${NC}"
done
echo ""

# ── Step 4: Pack text ───────────────────────────────────────────

step "Step 4: Pack text — replace secrets with tags (cloak_pack_text)"
echo ""

PACK_REQ=$(python3 -c "
import json
print(json.dumps({
    'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call',
    'params': {
        'name': 'cloak_pack_text',
        'arguments': {
            'text': 'DB_URL = \"jdbc:postgresql://10.12.34.56:5432/prod\"\nAWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\nEMAIL = \"admin@internal.company\"\nJWT = \"eyJhbGciOiJIUzI1NiJ9.payload.signature\"',
            'policy_path': '$POLICY',
            'project_root': '$DEMO_DIR'
        }
    }
}))
")

PACK_RESP=$(printf '%s\n' "$INIT_REQ" "$INIT_NOTIF" "$PACK_REQ" | cloak-mcp-server 2>/dev/null | tail -1)

echo -e "  ${DIM}← Packed result:${NC}"
PACKED_TEXT=$(echo "$PACK_RESP" | python3 -c "
import json, sys
d = json.load(sys.stdin)
content = d.get('result', {}).get('content', [{}])[0].get('text', '{}')
data = json.loads(content)
print(data['packed'])
" 2>/dev/null)

PACK_COUNT=$(echo "$PACK_RESP" | python3 -c "
import json, sys
d = json.load(sys.stdin)
content = d.get('result', {}).get('content', [{}])[0].get('text', '{}')
data = json.loads(content)
print(data['count'])
" 2>/dev/null)

echo "$PACKED_TEXT" | while IFS= read -r line; do
    echo -e "  ${GREEN}$line${NC}"
done
echo ""
echo -e "  ${BOLD}$PACK_COUNT secrets replaced with vault tags.${NC}"
echo ""

# ── Step 5: Unpack text ─────────────────────────────────────────

step "Step 5: Unpack text — restore from vault (cloak_unpack_text)"
echo ""

UNPACK_REQ=$(python3 -c "
import json
packed = '''$PACKED_TEXT'''
print(json.dumps({
    'jsonrpc': '2.0', 'id': 5, 'method': 'tools/call',
    'params': {
        'name': 'cloak_unpack_text',
        'arguments': {
            'text': packed,
            'project_root': '$DEMO_DIR'
        }
    }
}))
")

UNPACK_RESP=$(printf '%s\n' "$INIT_REQ" "$INIT_NOTIF" "$UNPACK_REQ" | cloak-mcp-server 2>/dev/null | tail -1)

echo -e "  ${DIM}← Restored result:${NC}"
echo "$UNPACK_RESP" | python3 -c "
import json, sys
d = json.load(sys.stdin)
content = d.get('result', {}).get('content', [{}])[0].get('text', '{}')
data = json.loads(content)
for line in data['unpacked'].strip().split('\n'):
    print(line)
print(f'\n     {data[\"count\"]} secrets restored from vault.')
" 2>/dev/null | while IFS= read -r line; do
    echo -e "  ${CYAN}$line${NC}"
done
echo ""

# ── Summary ─────────────────────────────────────────────────────

banner "MCP Protocol Summary"

echo -e "  ${BOLD}Protocol:${NC}    JSON-RPC 2.0 over stdio"
echo -e "  ${BOLD}Transport:${NC}   stdin/stdout (one JSON per line)"
echo -e "  ${BOLD}Config:${NC}      .mcp.json at project root"
echo -e "  ${BOLD}Tools:${NC}       6 (scan, pack, unpack, vault-stats, pack-dir, unpack-dir)"
echo ""
echo -e "  ${DIM}When Claude Code starts a session, it:${NC}"
echo -e "  ${DIM}  1. Reads .mcp.json → discovers cloak-mcp-server${NC}"
echo -e "  ${DIM}  2. Launches the server as a subprocess${NC}"
echo -e "  ${DIM}  3. Sends initialize + tools/list${NC}"
echo -e "  ${DIM}  4. Uses cloak_scan_text / cloak_pack_text as needed${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════
# PART 2: Full Hook Lifecycle — Claude Code Integration
# ══════════════════════════════════════════════════════════════════
#
# When --claude is passed, demonstrate the complete transparent lifecycle:
#   1. SessionStart hook fires → cloak pack (automatic, hidden)
#   2. Claude sees only tags   → works on cloaked code via MCP
#   3. SessionEnd hook fires   → cloak unpack (automatic, hidden)
#
# This is what happens in a REAL Claude Code session — zero human action.
# ══════════════════════════════════════════════════════════════════

if $USE_CLAUDE; then
    if ! command -v claude &>/dev/null; then
        echo -e "${YELLOW}Claude Code CLI not found — skipping live lifecycle test.${NC}"
    else
        JAVA_FILE="$DEMO_DIR/src/main/java/com/acme/payments/BankTransferService.java"

        banner "Hook Lifecycle Demo — Zero-Intervention Secret Protection"

        echo -e "  In a real Claude Code session, the hooks in ${BOLD}.claude/settings.local.json${NC}"
        echo -e "  fire automatically. The user types nothing — CloakMCP handles everything."
        echo ""
        echo -e "  ${DIM}┌──────────────────────────────────────────────────────────────┐${NC}"
        echo -e "  ${DIM}│  Claude Code starts    →  SessionStart hook  →  cloak pack  │${NC}"
        echo -e "  ${DIM}│  Claude works on code  →  MCP tools available (6 tools)     │${NC}"
        echo -e "  ${DIM}│  Claude Code exits     →  SessionEnd hook    →  cloak unpack│${NC}"
        echo -e "  ${DIM}└──────────────────────────────────────────────────────────────┘${NC}"
        echo ""

        # ── Phase 1: Show original file has real secrets ──────────

        step "Phase 1: Original code — secrets visible"
        echo ""
        echo -e "  ${DIM}--- BankTransferService.java (lines 25-46) ---${NC}"
        sed -n '25,46p' "$JAVA_FILE" | while IFS= read -r line; do
            highlighted=$(echo "$line" | sed \
                -e "s/10\.12\.34\.56/${RED}&${NC}/g" \
                -e "s/payments_admin@internal.company/${RED}&${NC}/g" \
                -e "s/smtp\.internal\.company\.local/${RED}&${NC}/g" \
                -e "s/no-reply@internal.company/${RED}&${NC}/g" \
                -e "s|https://ops\.internal[^\"]*|${RED}&${NC}|g" \
                -e "s/OPENSSH PRIVATE KEY/${RED}&${NC}/g" \
                -e "s/eyJhbGciOi[^\"]*/${RED}&${NC}/g" \
                -e "s/AKIAIOSFODNN7EXAMPLE/${RED}&${NC}/g")
            echo -e "  $highlighted"
        done
        echo ""

        # ── Phase 2: Simulate SessionStart hook → pack ────────────

        step "Phase 2: SessionStart hook fires → pack (automatic, hidden)"
        echo ""
        echo -e "  ${DIM}This is what Claude Code does behind the scenes at session start:${NC}"
        echo -e "  ${YELLOW}  \$ cloak hook session-start${NC}"
        echo ""

        # Actually pack the demo directory
        cloak pack --policy "$POLICY" --dir "$DEMO_DIR" --no-backup 2>&1 | sed 's/^/  /'
        echo ""

        # Show what Claude sees
        step "Claude now sees the cloaked code:"
        echo ""
        echo -e "  ${DIM}--- BankTransferService.java (what Claude receives) ---${NC}"
        sed -n '25,46p' "$JAVA_FILE" | while IFS= read -r line; do
            highlighted=$(echo "$line" | sed "s/TAG-[0-9a-f]\{12\}/${GREEN}${BOLD}&${NC}/g")
            echo -e "  $highlighted"
        done
        echo ""
        echo -e "  ${GREEN}Every secret is now a TAG-xxxxxxxxxxxx token.${NC}"
        echo -e "  ${GREEN}Claude can reason on the code but sees zero credentials.${NC}"
        echo ""

        # Capture packed content for the LLM prompt
        PACKED_JAVA=$(cat "$JAVA_FILE")

        # ── Phase 3: LLM works on the cloaked code ───────────────

        step "Phase 3: LLM explains the cloaked code (live API call)"
        echo ""

        LLM_PROMPT="You are reviewing a Spring Boot banking service. The secrets have been replaced by opaque TAG-xxxx tokens by CloakMCP. Explain what this class does in 4-5 sentences — focus on business logic, workflow steps, and integrations. Do NOT try to guess what the tags contain.

\`\`\`java
$PACKED_JAVA
\`\`\`"

        echo -e "  ${DIM}Prompt: \"Explain this Spring Boot banking service...\"${NC}"
        echo -e "  ${DIM}(LLM sees ONLY tagged code — zero real secrets)${NC}"
        echo ""

        LLM_RESPONSE=""
        LLM_NAME=""

        # Try Ollama first (instant, local, no auth needed)
        if curl -s --max-time 2 http://localhost:11434/api/tags &>/dev/null; then
            AVAILABLE=$(curl -s http://localhost:11434/api/tags | python3 -c "
import json,sys
d=json.load(sys.stdin)
for m in d.get('models',[]):
    print(m['name'])
" 2>/dev/null) || true

            OLLAMA_MODEL=""
            for model in "qwen2.5-coder:14b" "qwen2.5-coder:7b" "deepseek-r1:14b" "mistral:7b-instruct" "llama3:latest" "llama3.2:3b"; do
                if echo "$AVAILABLE" | grep -q "^${model}$"; then
                    OLLAMA_MODEL="$model"
                    break
                fi
            done
            if [ -z "$OLLAMA_MODEL" ] && [ -n "$AVAILABLE" ]; then
                OLLAMA_MODEL=$(echo "$AVAILABLE" | head -1)
            fi

            if [ -n "$OLLAMA_MODEL" ]; then
                LLM_NAME="Ollama ($OLLAMA_MODEL)"
                echo -e "  ${DIM}Using $LLM_NAME...${NC}"
                LLM_RESPONSE=$(curl -s --max-time 120 http://localhost:11434/api/generate \
                    -d "$(python3 -c "
import json
print(json.dumps({
    'model': '$OLLAMA_MODEL',
    'prompt': $(python3 -c "import json; print(json.dumps('''$LLM_PROMPT'''))"),
    'stream': False,
    'options': {'temperature': 0.3, 'num_predict': 400}
}))
")" 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('response', ''))
except:
    pass
" 2>/dev/null) || true
            fi
        fi

        # Fall back to Claude CLI
        if [ -z "$LLM_RESPONSE" ]; then
            LLM_NAME="Claude Code CLI"
            echo -e "  ${DIM}Using $LLM_NAME...${NC}"
            LLM_RESPONSE=$(cd "$PROJECT_ROOT" && echo "$LLM_PROMPT" | timeout 90 claude --print --model haiku 2>/dev/null) || true
        fi

        if [ -n "$LLM_RESPONSE" ]; then
            echo ""
            echo -e "  ${MAGENTA}${BOLD}$LLM_NAME says:${NC}"
            echo ""
            echo "$LLM_RESPONSE" | fold -s -w 72 | while IFS= read -r line; do
                echo -e "  ${MAGENTA}$line${NC}"
            done
            echo ""
            echo -e "  ${GREEN}${BOLD}The LLM understood the architecture without seeing a single secret.${NC}"
        else
            echo -e "  ${YELLOW}No LLM available (Ollama / Claude). The raw protocol demo above proves the same capability.${NC}"
        fi
        echo ""

        # ── Phase 4: Simulate SessionEnd hook → unpack ────────────

        step "Phase 4: SessionEnd hook fires → unpack (automatic, hidden)"
        echo ""
        echo -e "  ${DIM}When Claude Code session ends:${NC}"
        echo -e "  ${YELLOW}  \$ cloak hook session-end${NC}"
        echo ""

        cloak unpack --dir "$DEMO_DIR" --no-backup 2>&1 | sed 's/^/  /'
        echo ""

        step "Secrets restored — file is identical to original:"
        echo ""
        echo -e "  ${DIM}--- BankTransferService.java (secrets restored) ---${NC}"
        sed -n '25,46p' "$JAVA_FILE" | while IFS= read -r line; do
            highlighted=$(echo "$line" | sed \
                -e "s/10\.12\.34\.56/${CYAN}&${NC}/g" \
                -e "s/payments_admin@internal.company/${CYAN}&${NC}/g" \
                -e "s/smtp\.internal\.company\.local/${CYAN}&${NC}/g" \
                -e "s/no-reply@internal.company/${CYAN}&${NC}/g" \
                -e "s|https://ops\.internal[^\"]*|${CYAN}&${NC}|g" \
                -e "s/OPENSSH PRIVATE KEY/${CYAN}&${NC}/g" \
                -e "s/eyJhbGciOi[^\"]*/${CYAN}&${NC}/g" \
                -e "s/AKIAIOSFODNN7EXAMPLE/${CYAN}&${NC}/g")
            echo -e "  $highlighted"
        done
        echo ""

        # ── Summary ───────────────────────────────────────────────

        banner "Hook Lifecycle Summary"

        echo -e "  ${BOLD}What happened:${NC}"
        echo ""
        echo -e "    ${BOLD}1.${NC} SessionStart hook  → ${RED}secrets vanished${NC} (automatic pack)"
        echo -e "    ${BOLD}2.${NC} Claude Code worked  → ${GREEN}saw only TAG-xxxx tokens${NC}"
        echo -e "    ${BOLD}3.${NC} SessionEnd hook     → ${CYAN}secrets restored${NC} (automatic unpack)"
        echo ""
        echo -e "  ${BOLD}${GREEN}The developer did NOTHING. No manual pack/unpack. No config.${NC}"
        echo -e "  ${BOLD}${GREEN}Hooks + MCP make secret protection completely transparent.${NC}"
        echo ""
        echo -e "  ${DIM}Hook config: .claude/settings.local.json${NC}"
        echo -e "  ${DIM}MCP config:  .mcp.json${NC}"
        echo -e "  ${DIM}Vault:       ~/.cloakmcp/ (never leaves your machine)${NC}"
    fi
fi

echo ""
echo -e "  ${DIM}CloakMCP — MCP-native secret protection for Claude Code.${NC}"
echo ""
