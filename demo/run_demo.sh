#!/bin/bash
# ============================================================================
# CloakMCP Live Demo — Banking Transfer Service
# ============================================================================
#
# Demonstrates the full pack/unpack lifecycle on a realistic Java codebase
# containing multiple secret types (API keys, PEM blocks, SMTP creds, JWTs,
# AWS keys, internal URLs, emails, IPs).
#
# Usage:
#   cd demo && bash run_demo.sh
#
# Requirements:
#   - CloakMCP installed: pip install -e ..
#   - HMAC key: mkdir -p ../keys && openssl rand -hex 32 > ../keys/mcp_hmac_key
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
    DIM='\033[2m'
    NC='\033[0m'
else
    BOLD='' GREEN='' RED='' CYAN='' YELLOW='' DIM='' NC=''
fi

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$DEMO_DIR")"
POLICY="$PROJECT_ROOT/examples/mcp_policy.yaml"
JAVA_FILE="src/main/java/com/acme/payments/BankTransferService.java"
PROPS_FILE="src/main/resources/application.properties"
YAML_FILE="src/main/resources/application.yml"

banner() {
    echo ""
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${NC}"
    echo ""
}

step() {
    echo -e "${BOLD}${GREEN}▶ $1${NC}"
}

pause() {
    echo ""
    echo -e "${DIM}  Press Enter to continue...${NC}"
    read -r
}

# ── Preflight ───────────────────────────────────────────────────

cd "$DEMO_DIR"

if ! command -v cloak &>/dev/null; then
    echo -e "${RED}Error: 'cloak' not found. Run: pip install -e $PROJECT_ROOT${NC}"
    exit 1
fi

if [ ! -f "$POLICY" ]; then
    echo -e "${RED}Error: Policy not found at $POLICY${NC}"
    exit 1
fi

# ── Act 1: Show the secrets ─────────────────────────────────────

banner "ACT 1 — The Problem: Secrets in Source Code"

step "A real-world Java service contains hardcoded secrets:"
echo ""
echo -e "  ${YELLOW}$JAVA_FILE${NC}"
echo ""

# Show secret lines from the Java file
echo -e "  ${DIM}--- Secrets found in BankTransferService.java ---${NC}"
grep -n -E '(API_KEY|PASSWORD|SMTP_|PRIVATE_KEY|JWT|AWS_ACCESS|DB_URL|DB_USER|webhook)' "$JAVA_FILE" \
    | head -20 \
    | while IFS= read -r line; do
        echo -e "  ${RED}$line${NC}"
    done
echo ""

echo -e "  ${DIM}--- Secrets found in application.properties ---${NC}"
grep -n -E '(password|key=|secret|username)' "$PROPS_FILE" \
    | head -15 \
    | while IFS= read -r line; do
        echo -e "  ${RED}$line${NC}"
    done
echo ""

echo -e "  ${DIM}--- Secrets found in application.yml ---${NC}"
grep -n -E '(password|key|secret|username|email|endpoint|url)' "$YAML_FILE" \
    | grep -v '^#' \
    | head -15 \
    | while IFS= read -r line; do
        echo -e "  ${RED}$line${NC}"
    done
echo ""

echo -e "  ${YELLOW}Problem:${NC} If you send this code to Claude/Codex/Gemini for refactoring,"
echo -e "  ${YELLOW}every secret leaks to the LLM provider.${NC}"

pause

# ── Act 2: Pack ─────────────────────────────────────────────────

banner "ACT 2 — CloakMCP Pack: Secrets Replaced by Vault Tags"

step "Running: cloak pack --policy $POLICY --dir . --no-backup"
echo ""

cloak pack --policy "$POLICY" --dir "$DEMO_DIR" --no-backup 2>&1

echo ""
step "Result — Java file now contains only opaque tags:"
echo ""

# Show the same lines, now with tags
echo -e "  ${DIM}--- BankTransferService.java (packed) ---${NC}"
grep -n -E '(API_KEY|PASSWORD|SMTP_|PRIVATE_KEY|JWT|AWS_ACCESS|DB_URL|DB_USER|webhook)' "$JAVA_FILE" \
    | head -20 \
    | while IFS= read -r line; do
        echo -e "  ${GREEN}$line${NC}"
    done
echo ""

echo -e "  ${DIM}--- application.properties (packed) ---${NC}"
grep -n -E '(password|key=|secret|username)' "$PROPS_FILE" \
    | head -15 \
    | while IFS= read -r line; do
        echo -e "  ${GREEN}$line${NC}"
    done
echo ""

echo -e "  ${DIM}--- application.yml (packed) ---${NC}"
grep -n -E '(password|key|secret|username|email|endpoint|url)' "$YAML_FILE" \
    | grep -v '^#' \
    | head -15 \
    | while IFS= read -r line; do
        echo -e "  ${GREEN}$line${NC}"
    done
echo ""

echo -e "  ${GREEN}Secrets are gone.${NC} The LLM sees only ${BOLD}TAG-xxxxxxxxxxxx${NC} placeholders."
echo -e "  The encrypted vault lives in ${CYAN}~/.cloakmcp/vaults/${NC} — never sent to the LLM."

pause

# ── Act 3: What the LLM sees ───────────────────────────────────

banner "ACT 3 — What Claude/Codex Sees (Safe to Refactor)"

step "The LLM can read, refactor, and reason on this code."
step "It sees structure and logic — but ZERO real secrets."
echo ""

echo -e "  ${DIM}--- Sample from packed file ---${NC}"
sed -n '20,35p' "$JAVA_FILE" | while IFS= read -r line; do
    echo -e "  ${CYAN}$line${NC}"
done
echo ""

echo -e "  ${BOLD}The LLM can:${NC}"
echo -e "    - Refactor initiateHighValueTransfer() safely"
echo -e "    - Add error handling, logging, documentation"
echo -e "    - Move constants to a config class"
echo -e "    - All without seeing a single real credential"

pause

# ── Act 4: Unpack ───────────────────────────────────────────────

banner "ACT 4 — CloakMCP Unpack: Secrets Restored from Vault"

step "Running: cloak unpack --dir . --no-backup"
echo ""

cloak unpack --dir "$DEMO_DIR" --no-backup 2>&1

echo ""
step "Result — all original secrets restored:"
echo ""

echo -e "  ${DIM}--- BankTransferService.java (restored) ---${NC}"
grep -n -E '(API_KEY|PASSWORD|SMTP_|PRIVATE_KEY|JWT|AWS_ACCESS|DB_URL|DB_USER|webhook)' "$JAVA_FILE" \
    | head -20 \
    | while IFS= read -r line; do
        echo -e "  ${GREEN}$line${NC}"
    done
echo ""

echo -e "  ${DIM}--- application.properties (restored) ---${NC}"
grep -n -E '(password|key=|secret|username)' "$PROPS_FILE" \
    | head -15 \
    | while IFS= read -r line; do
        echo -e "  ${GREEN}$line${NC}"
    done
echo ""

echo -e "  ${DIM}--- application.yml (restored) ---${NC}"
grep -n -E '(password|key|secret|username|email|endpoint|url)' "$YAML_FILE" \
    | grep -v '^#' \
    | head -15 \
    | while IFS= read -r line; do
        echo -e "  ${GREEN}$line${NC}"
    done

pause

# ── Act 5: Vault stats ─────────────────────────────────────────

banner "ACT 5 — Vault Statistics"

step "The vault is encrypted and lives outside the project:"
echo ""
cloak vault-stats --dir "$DEMO_DIR" 2>&1
echo ""

echo -e "  ${BOLD}Key points:${NC}"
echo -e "    - Vault encrypted with Fernet (AES-128)"
echo -e "    - HMAC-SHA256 tags: same secret = same tag (deterministic)"
echo -e "    - Vault never enters git, never reaches the LLM"
echo -e "    - Restore works on any machine with vault + key files"

echo ""
banner "Demo Complete"
echo -e "  ${BOLD}CloakMCP${NC}: local-first secret sanitization before LLM exposure."
echo -e "  ${DIM}Secrets stay on your machine. The LLM sees only tags.${NC}"
echo ""
