#!/usr/bin/env bash
# VoidAccess — start the full stack and wait until ready.
# Usage: ./start.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Python detection (python3 may be a Windows Store stub in Git Bash) ─────────

if echo '{}' | python3 -c "import sys,json; json.load(sys.stdin)" >/dev/null 2>&1; then
    PYTHON=python3
elif echo '{}' | python -c "import sys,json; json.load(sys.stdin)" >/dev/null 2>&1; then
    PYTHON=python
else
    PYTHON=""
fi

_parse_status() {
    if [ -n "$PYTHON" ]; then
        "$PYTHON" -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null
    else
        grep -o '"status":"ready"' | grep -o 'ready' || true
    fi
}

# ── Preflight ──────────────────────────────────────────────────────────────────

if ! command -v docker >/dev/null 2>&1; then
    echo -e "${RED}✗ Docker not found. Install Docker and try again.${NC}"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/.env" ]; then
    echo -e "${YELLOW}⚠  No .env file found. Run setup.sh first:${NC}"
    echo "   bash setup.sh"
    exit 1
fi

# ── Build & start ──────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}${BOLD}Starting VoidAccess...${NC}"
echo ""

DOCKER_BUILDKIT=1 docker compose -f "$SCRIPT_DIR/infra/docker-compose.yml" \
    --project-directory "$SCRIPT_DIR" \
    --env-file "$SCRIPT_DIR/.env" \
    up --build -d

# ── Wait for API to be ready ───────────────────────────────────────────────────

echo ""
echo -e "Waiting for services to be ready..."
echo -n "  "

STATUS=""
for i in $(seq 1 60); do
    _HEALTH=$(curl -s --max-time 5 http://localhost:8000/healthz/ready 2>/dev/null || echo "")
    STATUS=$(echo "$_HEALTH" | _parse_status)
    if [ "$STATUS" = "ready" ]; then
        break
    fi
    echo -n "."
    sleep 5
done

echo ""

# ── Ready banner ───────────────────────────────────────────────────────────────

if [ "$STATUS" = "ready" ]; then
    echo ""
    echo -e "${GREEN}${BOLD}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║       VoidAccess is ready!             ║${NC}"
    echo -e "${GREEN}${BOLD}╠════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}${BOLD}║${NC}  Web UI:  http://localhost:3001         ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}  API:     http://localhost:8000         ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}║${NC}  API docs: http://localhost:8000/docs   ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╠════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}${BOLD}║${NC}  Stop:  ./stop.sh                      ${GREEN}${BOLD}║${NC}"
    echo -e "${GREEN}${BOLD}╚════════════════════════════════════════╝${NC}"
    echo ""
else
    echo -e "${YELLOW}⚠  Services are taking longer than expected.${NC}"
    echo "   Check status:  docker compose -f infra/docker-compose.yml --project-directory . ps"
    echo "   View logs:     docker compose -f infra/docker-compose.yml --project-directory . logs -f"
fi
