#!/usr/bin/env bash
# VoidAccess — stop the full stack.
# Usage: ./stop.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${CYAN}${BOLD}Stopping VoidAccess...${NC}"
echo ""

docker compose -f "$SCRIPT_DIR/infra/docker-compose.yml" \
    --project-directory "$SCRIPT_DIR" \
    down

echo ""
echo -e "${GREEN}${BOLD}VoidAccess stopped.${NC}"
echo ""
