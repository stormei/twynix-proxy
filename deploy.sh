#!/usr/bin/env bash
set -euo pipefail

APP_NAME="twynix-proxy"
BRANCH="main"

echo "Fetching latest code..."
git fetch origin "${BRANCH}"

echo "Resetting local code to origin/${BRANCH}..."
git checkout "${BRANCH}"
git reset --hard "origin/${BRANCH}"

VERSION="$(git rev-parse --short HEAD)"
IMAGE="${APP_NAME}:${VERSION}"

echo "Building image ${IMAGE}..."
docker build --pull -t "${IMAGE}" .

if [[ -f .deployed-version ]]; then
  cp .deployed-version .previous-version
fi

echo "${VERSION}" > .deployed-version

echo "Deploying ${IMAGE}..."
export TWYNIX_PROXY_VERSION="${VERSION}"
docker compose up -d

echo "Waiting for healthcheck..."

for i in {1..30}; do
  HEALTH="$(docker inspect --format='{{.State.Health.Status}}' "${APP_NAME}" 2>/dev/null || echo "unknown")"

  if [[ "${HEALTH}" == "healthy" ]]; then
    echo "Deployment complete."
    echo "Image: ${IMAGE}"
    echo "Health: ${HEALTH}"
    exit 0
  fi

  if [[ "${HEALTH}" == "unhealthy" ]]; then
    echo "Deployment failed. Container is unhealthy."
    docker inspect "${APP_NAME}" --format='{{range .State.Health.Log}}{{.ExitCode}} {{.Output}}{{end}}'
    docker logs --tail=100 "${APP_NAME}"
    exit 1
  fi

  echo "Health status: ${HEALTH}. Waiting..."
  sleep 5
done

echo "Deployment timed out waiting for healthy status."
docker inspect "${APP_NAME}" --format='{{range .State.Health.Log}}{{.ExitCode}} {{.Output}}{{end}}'
docker logs --tail=100 "${APP_NAME}"
exit 1
echo "Deployment complete."
echo "Image: ${IMAGE}"
echo "Health: ${HEALTH}"
