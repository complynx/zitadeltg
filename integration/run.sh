#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
# Each run owns an isolated network and volumes. Never touch other Compose stacks.
export COMPOSE_PROJECT_NAME="zitadeltg-it-${RANDOM}-$$"
compose=(docker compose -f docker-compose.yml)
cleanup() {
  local result=$1
  if (( result != 0 )); then
    "${compose[@]}" logs --no-color zitadel postgres
  fi
  "${compose[@]}" down --volumes --remove-orphans
  exit "$result"
}
trap 'cleanup $?' EXIT
"${compose[@]}" build suite bootstrap
"${compose[@]}" run --rm --use-aliases suite
