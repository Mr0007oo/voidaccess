#!/usr/bin/env bash
# Step 1.1 — Nuke everything
docker compose down --volumes --remove-orphans 2>/dev/null || true
docker compose rm -f 2>/dev/null || true

# Remove all voidaccess containers
CONTAINERS=$(docker ps -a --format "{{.Names}}" | grep -i void)
if [ -n "$CONTAINERS" ]; then
  echo "Removing containers: $CONTAINERS"
  docker rm -f $CONTAINERS
fi

# Remove all voidaccess images
IMAGES=$(docker images --format "{{.Repository}} {{.ID}}" | grep -i void | awk '{get_async_session}')
if [ -n "$IMAGES" ]; then
  echo "Removing images: $IMAGES"
  docker rmi -f $IMAGES
fi

# Remove build cache
docker builder prune -f --all 2>/dev/null || true

# Remove volumes
VOLUMES=$(docker volume ls --format "{{.Name}}" | grep -i void)
if [ -n "$VOLUMES" ]; then
  echo "Removing volumes: $VOLUMES"
  docker volume rm $VOLUMES
fi

echo "✓ Clean slate"

# Step 1.2 — Remove .env to simulate fresh install
cp .env .env.backup 2>/dev/null || true
rm -f .env
echo "✓ .env removed (backed up as .env.backup)"
