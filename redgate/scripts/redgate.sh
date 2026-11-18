#!/usr/bin/env bash
# Docker lifecycle commands that never source .env, print secrets, or delete data.
set -euo pipefail
umask 077
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'HELP'
Redstrike 2.1 operations (Docker Compose v2.20+)
  redgate.sh up [--lite|--full]  Build and start; wait for healthchecks
  redgate.sh down               Stop services; KEEP named volumes and evidence
  redgate.sh status             Show containers, then gateway readiness
  redgate.sh logs [service]     Follow the last 100 log lines (Ctrl-C to stop)
  redgate.sh doctor             Check Docker, Compose config, and credential file modes
  redgate.sh backup [file.gz]   Consistent compressed SQLite backup, mode 0600
  redgate.sh verify             Run local Go/Python/JavaScript/Bash checks

lite omits Go/Node adapter toolchains, not policy checks or HTTP evidence.
It does not support Go/JavaScript script validation or execution.
Compose always disables the unauthenticated demo bootstrap endpoint.
HELP
}

command_name="${1:-help}"
if [[ $# -gt 0 ]]; then shift; fi
case "$command_name" in
  help|--help|-h) usage; exit 0 ;;
  verify) exec "$ROOT_DIR/scripts/verify.sh" "$@" ;;
  backup) exec "$ROOT_DIR/scripts/backup_db.sh" "$@" ;;
  up|down|status|logs|doctor) ;;
  *) usage >&2; exit 2 ;;
esac

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  printf 'ERROR: Docker Engine + Docker Compose v2.20+ are required for this command.\n' >&2
  exit 1
fi
compose=(docker compose --project-directory "$ROOT_DIR" -f "$ROOT_DIR/docker-compose.yml")

case "$command_name" in
  up)
    if [[ $# -gt 1 ]]; then usage >&2; exit 2; fi
    case "${1:-}" in
      --lite) export REDGATE_IMAGE_FLAVOR=lite ;;
      --full) export REDGATE_IMAGE_FLAVOR=full ;;
      "") ;;
      *) usage >&2; exit 2 ;;
    esac
    "${compose[@]}" config --quiet
    "${compose[@]}" up -d --build --wait --wait-timeout 180
    printf '[Redstrike] Services healthy. Use your private operator Bearer token to sign in.\n'
    ;;
  down)
    [[ $# -eq 0 ]] || { usage >&2; exit 2; }
    "${compose[@]}" down
    printf '[Redstrike] Persistent volumes retained. Never use down --volumes to upgrade.\n'
    ;;
  status)
    [[ $# -eq 0 ]] || { usage >&2; exit 2; }
    "${compose[@]}" ps
    "${compose[@]}" exec -T gateway python -c \
      "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=8).read().decode())"
    ;;
  logs)
    [[ $# -le 1 ]] || { usage >&2; exit 2; }
    case "${1:-}" in
      gateway|mcp-server|sandbox-runner|db|ollama) "${compose[@]}" logs --tail 100 --follow "$1" ;;
      "") "${compose[@]}" logs --tail 100 --follow ;;
      *) printf 'ERROR: Unknown service.\n' >&2; exit 2 ;;
    esac
    ;;
  doctor)
    [[ $# -eq 0 ]] || { usage >&2; exit 2; }
    docker info >/dev/null
    "${compose[@]}" config --quiet
    [[ -f .env && -f secrets/llm_api_key ]] || {
      printf 'ERROR: Run ./scripts/bootstrap_env.sh first.\n' >&2; exit 1;
    }
    [[ "$(stat -c '%a' .env)" == 600 ]] || {
      printf 'ERROR: .env must be mode 0600.\n' >&2; exit 1;
    }
    [[ "$(stat -c '%a' secrets/llm_api_key)" =~ ^(600|640)$ ]] || {
      printf 'ERROR: LLM key must be mode 0600 (local) or 0640 (restricted container group).\n' >&2; exit 1;
    }
    printf '[OK] Docker reachable, Compose configuration valid, secret modes restricted.\n'
    printf '[ACTION] Review signed scope, external egress firewall, TLS and backups before live work.\n'
    ;;
esac
