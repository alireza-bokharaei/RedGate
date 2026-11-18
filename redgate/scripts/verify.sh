#!/usr/bin/env bash
# One reproducible entry point for all four language checks. No live assessments.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(dirname "$ROOT_DIR")"
cd "$ROOT_DIR"
[[ $# -eq 0 ]] || { printf 'Usage: %s\n' "$0" >&2; exit 2; }
for tool in python3 go gofmt node npm shellcheck; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'ERROR: Missing tool: %s\n' "$tool" >&2; exit 1; }
done
[[ -x node_modules/.bin/eslint ]] || { printf 'ERROR: Run npm ci in redgate/ first.\n' >&2; exit 1; }
export PATH="$ROOT_DIR/node_modules/.bin:$PATH"
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"

printf '\n[1/5] Bash syntax + ShellCheck\n'
for script in scripts/*.sh; do bash -n "$script"; done
shellcheck scripts/*.sh
printf '\n[2/5] JavaScript syntax, ESLint and graph/controller tests\n'
npm run check
npm run lint
npm test
printf '\n[3/5] Go formatting, unit/race tests and vet\n'
(
  cd sandbox_runner
  [[ -z "$(gofmt -l .)" ]] || { printf 'ERROR: Run gofmt on sandbox_runner/.\n' >&2; exit 1; }
  go test -race ./...
  go vet ./...
  mkdir -p ../bin
  CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o ../bin/sandbox-runner .
)
printf '\n[4/5] Python lint + complete regression/integration suite\n'
python3 -m ruff check --config "$REPO_DIR/pyproject.toml" gateway mcp_server tests
python3 -m pytest -q -c "$REPO_DIR/pyproject.toml" "$ROOT_DIR/tests"
printf '\n[5/5] Compose configuration (when Docker is installed)\n'
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 && [[ -f .env ]]; then
  docker compose config --quiet
else
  printf '[SKIP] Compose CLI and/or .env unavailable; no Docker build/run is claimed.\n'
fi
printf '\n[OK] Local verification finished. Docker runtime and performance need separate measurement.\n'
