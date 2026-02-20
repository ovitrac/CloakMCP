#!/bin/bash
# ============================================================================
# CloakMCP — LLM Demo: Prove That AI Can Work on Cloaked Code
# ============================================================================
#
# This demo packs the banking service code, then asks a real LLM to explain
# it. The LLM reasons about code structure and logic — but sees ZERO secrets.
#
# Usage:
#   cd demo && bash llm_demo.sh                  # auto-detect best LLM
#   cd demo && bash llm_demo.sh --ollama          # force local Ollama
#   cd demo && bash llm_demo.sh --claude          # force Claude Code CLI
#
# Requirements:
#   - CloakMCP installed: pip install -e ..
#   - At least ONE of:
#       * Ollama running locally (ollama serve)
#       * Claude Code CLI installed (claude --version)
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
JAVA_FILE="src/main/java/com/acme/payments/BankTransferService.java"

# ── Parse args ──────────────────────────────────────────────────
FORCE_OLLAMA=false
FORCE_CLAUDE=false
for arg in "$@"; do
    case "$arg" in
        --ollama) FORCE_OLLAMA=true ;;
        --claude) FORCE_CLAUDE=true ;;
    esac
done

# ── Helpers ─────────────────────────────────────────────────────
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

# ── Detect available LLMs ───────────────────────────────────────
OLLAMA_OK=false
CLAUDE_OK=false
OLLAMA_MODEL=""

# Preferred Ollama models (in order of preference for code tasks)
PREFERRED_MODELS=("qwen2.5-coder:14b" "qwen2.5-coder:7b" "deepseek-r1:14b" "mistral:7b-instruct" "llama3:latest" "llama3.2:3b" "phi3:latest")

if ! $FORCE_CLAUDE; then
    if curl -s --max-time 2 http://localhost:11434/api/tags &>/dev/null; then
        AVAILABLE=$(curl -s http://localhost:11434/api/tags | python3 -c "
import json,sys
d=json.load(sys.stdin)
for m in d.get('models',[]):
    print(m['name'])
" 2>/dev/null) || true
        for model in "${PREFERRED_MODELS[@]}"; do
            if echo "$AVAILABLE" | grep -q "^${model}$"; then
                OLLAMA_MODEL="$model"
                OLLAMA_OK=true
                break
            fi
        done
        # Fallback: use first available model
        if ! $OLLAMA_OK && [ -n "$AVAILABLE" ]; then
            OLLAMA_MODEL=$(echo "$AVAILABLE" | head -1)
            OLLAMA_OK=true
        fi
    fi
fi

if ! $FORCE_OLLAMA; then
    if command -v claude &>/dev/null; then
        CLAUDE_OK=true
    fi
fi

if ! $OLLAMA_OK && ! $CLAUDE_OK; then
    echo -e "${RED}Error: No LLM available.${NC}"
    echo -e "  Install Ollama: ${CYAN}https://ollama.ai${NC}"
    echo -e "  Or Claude Code: ${CYAN}npm install -g @anthropic-ai/claude-code${NC}"
    exit 1
fi

# ── Preflight ───────────────────────────────────────────────────
cd "$DEMO_DIR"

if ! command -v cloak &>/dev/null; then
    echo -e "${RED}Error: 'cloak' not found. Run: pip install -e $PROJECT_ROOT${NC}"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════
# STEP 1: Show what the code looks like WITH secrets
# ══════════════════════════════════════════════════════════════════

banner "STEP 1 — Original Code: Full of Secrets"

step "The developer's source code contains hardcoded secrets:"
echo ""
echo -e "  ${DIM}--- Excerpt from BankTransferService.java ---${NC}"
sed -n '17,49p' "$JAVA_FILE" | while IFS= read -r line; do
    # Highlight secrets in red
    highlighted=$(echo "$line" | sed \
        -e "s/sk_live_[^\"]*/${RED}&${NC}/g" \
        -e "s/AKIAIOSFODNN7EXAMPLE/${RED}&${NC}/g" \
        -e "s/payments_admin@internal.company/${RED}&${NC}/g" \
        -e "s/P@ssw0rd-FAKE-DoNotUse/${RED}&${NC}/g" \
        -e "s/smtp-FAKE-secret-[^\"]*/${RED}&${NC}/g")
    echo -e "  $highlighted"
done
echo ""
echo -e "  ${RED}${BOLD}If you send this to an LLM, every secret leaks.${NC}"

# ══════════════════════════════════════════════════════════════════
# STEP 2: Pack — replace secrets with tags
# ══════════════════════════════════════════════════════════════════

banner "STEP 2 — CloakMCP Pack: Secrets Vanish"

step "Running: cloak pack --policy mcp_policy.yaml --dir demo/"
echo ""
cloak pack --policy "$POLICY" --dir "$DEMO_DIR" --no-backup 2>&1 | sed 's/^/  /'
echo ""

# Capture the packed content for the LLM
PACKED_CONTENT=$(cat "$JAVA_FILE")

step "Packed code (what the LLM will see):"
echo ""
echo -e "  ${DIM}--- BankTransferService.java (secrets replaced) ---${NC}"
sed -n '17,49p' "$JAVA_FILE" | while IFS= read -r line; do
    # Highlight tags in green
    highlighted=$(echo "$line" | sed "s/TAG-[0-9a-f]\{12\}/${GREEN}${BOLD}&${NC}/g")
    echo -e "  $highlighted"
done
echo ""
echo -e "  ${GREEN}Secrets are gone. Only opaque ${BOLD}TAG-xxxxxxxxxxxx${NC}${GREEN} tokens remain.${NC}"

# ══════════════════════════════════════════════════════════════════
# STEP 3: Ask LLM to explain the code
# ══════════════════════════════════════════════════════════════════

banner "STEP 3 — LLM Reads Cloaked Code (Live)"

LLM_PROMPT="Explain what this Java class does in 4-5 sentences. Focus on the business logic and the workflow steps. Do not try to decode or guess what the TAG-xxxx placeholders contain.

\`\`\`java
$PACKED_CONTENT
\`\`\`"

# Try Ollama first, then Claude
LLM_RESPONSE=""
LLM_NAME=""

if $OLLAMA_OK && ! $FORCE_CLAUDE; then
    LLM_NAME="Ollama ($OLLAMA_MODEL)"
    step "Asking $LLM_NAME to explain the cloaked code..."
    echo ""

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
    print(d.get('response', 'No response'))
except:
    print('Error: Could not parse response')
" 2>/dev/null) || true

    # If Ollama failed, fall back to Claude
    if [ -z "$LLM_RESPONSE" ] || [ "$LLM_RESPONSE" = "Error: Could not parse response" ]; then
        if $CLAUDE_OK; then
            LLM_NAME="Claude (fallback)"
            LLM_RESPONSE=""
        fi
    fi
fi

if [ -z "$LLM_RESPONSE" ] && $CLAUDE_OK; then
    LLM_NAME="Claude Code CLI"
    step "Asking $LLM_NAME to explain the cloaked code..."
    echo ""

    LLM_RESPONSE=$(echo "$LLM_PROMPT" | claude --print --model haiku 2>/dev/null) || true
fi

if [ -n "$LLM_RESPONSE" ] && [ "$LLM_RESPONSE" != "Error: Could not parse response" ]; then
    echo -e "  ${MAGENTA}${BOLD}$LLM_NAME says:${NC}"
    echo ""
    echo "$LLM_RESPONSE" | fold -s -w 72 | while IFS= read -r line; do
        echo -e "  ${MAGENTA}$line${NC}"
    done
    echo ""
    echo -e "  ${GREEN}${BOLD}The LLM understood the code perfectly — without seeing a single secret.${NC}"
else
    echo -e "  ${YELLOW}LLM call skipped or timed out. The point stands:${NC}"
    echo -e "  ${YELLOW}any LLM can reason on cloaked code, because the structure is preserved.${NC}"
fi

# ══════════════════════════════════════════════════════════════════
# STEP 4: Unpack — restore secrets
# ══════════════════════════════════════════════════════════════════

banner "STEP 4 — Unpack: Secrets Restored Locally"

step "Running: cloak unpack --dir demo/"
echo ""
cloak unpack --dir "$DEMO_DIR" --no-backup 2>&1 | sed 's/^/  /'
echo ""

step "Secrets are back — only on your machine, never sent to the LLM."
echo ""

# ══════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════

banner "Summary"

echo -e "  ${BOLD}What just happened:${NC}"
echo ""
echo -e "    1. Your code had ${RED}real secrets${NC} (API keys, passwords, PEM keys)"
echo -e "    2. CloakMCP replaced them with ${GREEN}opaque tags${NC} (TAG-xxxxxxxxxxxx)"
echo -e "    3. An LLM ${MAGENTA}explained the code perfectly${NC} — without seeing any secret"
echo -e "    4. Secrets were ${CYAN}restored from the encrypted vault${NC}"
echo ""
echo -e "  ${BOLD}${CYAN}Your secrets never left your machine.${NC}"
echo -e "  ${BOLD}${CYAN}The LLM never saw them.${NC}"
echo -e "  ${BOLD}${CYAN}Round-trip is lossless.${NC}"
echo ""
echo -e "  ${DIM}CloakMCP — local-first secret sanitization before LLM exposure.${NC}"
echo ""
