#!/usr/bin/env bash
set -euo pipefail

APP_NAME="twynix-proxy"

if [[ ! -f .previous-version ]]; then
  echo "No previous version found."
  exit 1
fi

VERSION="$(cat .previous-version)"

echo "Rolling back ${APP_NAME} to ${VERSION}..."

export TWYNIX_PROXY_VERSION="${VERSION}"
docker compose up -d

sleep 10

HEALTH="$(docker inspect --format='{{.State.Health.Status}}' "${APP_NAME}" 2>/dev/null || echo "unknown")"

echo "Rollback complete."
echo "Image: ${APP_NAME}:${VERSION}"
echo "Health: ${HEALTH}"
