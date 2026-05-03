#!/usr/bin/env bash
# VoidAccess — start the full stack and wait until ready.
# Usage: ./start.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
NC=$'\033[0m'

print_ok()   { printf "${GREEN}  ✓${NC}  %s\n" "$1"; }
print_warn() { printf "${YELLOW}  ⚠${NC}  %s\n" "$1"; }
print_info() { printf "${DIM}  →${NC}  %s\n" "$1"; }

# ── Python detection (python3 may be a Windows Store stub in Git Bash) ────────

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

# ── Banner ────────────────────────────────────────────────────────────────────

printf "\n"
printf "${CYAN}"
printf "  ╔═══════════════════════════════════╗\n"
printf "  ║  VoidAccess  ·  Starting up       ║\n"
printf "  ╚═══════════════════════════════════╝\n"
printf "${NC}\n"

# ── Docker permission check ───────────────────────────────────────────────────

if ! docker info > /dev/null 2>&1; then
    if sudo docker info > /dev/null 2>&1; then
        printf "\n  ${YELLOW}⚠${NC}  Docker requires sudo on this system.\n"
        printf "  ${DIM}→${NC}  Re-run with: ${BOLD}sudo bash start.sh${NC}\n\n"
        exit 1
    else
        printf "\n  ${RED}✗${NC}  Docker not found or not running.\n"
        printf "  ${DIM}→${NC}  Install: ${DIM}https://docs.docker.com/get-docker/${NC}\n\n"
        exit 1
    fi
fi

if [ ! -f "$SCRIPT_DIR/.env" ]; then
    print_warn "No .env file found. Run setup.sh first:"
    printf "    ${DIM}bash setup.sh${NC}\n"
    exit 1
fi

# ── Build & start ─────────────────────────────────────────────────────────────

printf "  ${DIM}→${NC}  Building containers...\n"
DOCKER_BUILDKIT=1 docker compose -f "$SCRIPT_DIR/infra/docker-compose.yml" \
    --project-directory "$SCRIPT_DIR" \
    --env-file "$SCRIPT_DIR/.env" \
    up --build -d \
    > /tmp/va_start.log 2>&1
START_EXIT=$?

if [ $START_EXIT -eq 0 ]; then
    printf "  ${GREEN}✓${NC}  Containers started\n"
else
    printf "  ${RED}✗${NC}  Build failed — check /tmp/va_start.log\n"
    tail -20 /tmp/va_start.log
    exit 1
fi

# ── Service health ────────────────────────────────────────────────────────────

printf "\n"
printf "  ${DIM}→${NC}  Waiting for services...\n"

for SVC in postgres tor fastapi nextjs; do
    FOUND=false
    for i in $(seq 1 30); do
        STATE=$(docker inspect \
            --format='{{.State.Health.Status}}' \
            voidaccess-$SVC 2>/dev/null || echo "starting")
        if [ "$STATE" = "healthy" ] || [ "$STATE" = "running" ]; then
            printf "  ${GREEN}✓${NC}  $SVC\n"
            FOUND=true
            break
        fi
        sleep 2
    done
    if [ "$FOUND" = false ]; then
        printf "  ${YELLOW}⚠${NC}  $SVC (timeout)\n"
    fi
done

# ── Wait for API ready ────────────────────────────────────────────────────────

printf "\n"

STATUS=""
for i in $(seq 1 60); do
    _HEALTH=$(curl -s --max-time 5 http://localhost:8000/healthz/ready 2>/dev/null || echo "")
    STATUS=$(echo "$_HEALTH" | _parse_status)
    if [ "$STATUS" = "ready" ]; then
        break
    fi
    sleep 5
done

# ── Ready banner ──────────────────────────────────────────────────────────────

if [ "$STATUS" = "ready" ]; then
    printf "\n${GREEN}"
    printf "  ╔═══════════════════════════════════╗\n"
    printf "  ║                                   ║\n"
    printf "  ║   ✓  VoidAccess is ready          ║\n"
    printf "  ║                                   ║\n"
    printf "  ╠═══════════════════════════════════╣\n"
    printf "  ║  UI   →  http://localhost:3001    ║\n"
    printf "  ║  API  →  http://localhost:8000    ║\n"
    printf "  ║                                   ║\n"
    printf "  ╚═══════════════════════════════════╝\n"
    printf "${NC}\n"
else
    print_warn "Services are taking longer than expected."
    printf "    ${DIM}docker compose -f infra/docker-compose.yml --project-directory . ps${NC}\n"
    printf "    ${DIM}docker compose -f infra/docker-compose.yml --project-directory . logs -f${NC}\n"
fi
