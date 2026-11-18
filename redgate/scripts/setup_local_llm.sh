#!/usr/bin/env bash
# Configure a local inference runtime explicitly for host OR Compose networking.
# No downloads unless --pull is requested; never source .env or leave key backups.
set -euo pipefail
umask 077
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
DEPLOYMENT=compose
PULL=false
BASE_URL=""
usage() {
  cat <<'HELP'
Usage: setup_local_llm.sh [--compose|--local] [--pull] [--base-url URL]
                          <ollama|lm_studio> [hf_org/repo-GGUF] [quantization]
Default: --compose, configure only (no model download).
  --compose Ollama uses http://ollama:11434/v1 (not container localhost).
  --local   Ollama/LM Studio use loopback on the HOST running the gateway.
  --pull    Explicitly fetch model files (potentially many GB) and prepare runtime.
LM Studio in Compose requires --base-url and operator-configured host routing.
Changes .env for INITIAL database setup only. For an existing database update
Local AI > Runtime in the admin console; saved runtime settings take precedence.
HELP
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --compose) DEPLOYMENT=compose; shift ;;
    --local) DEPLOYMENT=local; shift ;;
    --pull) PULL=true; shift ;;
    --base-url)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      BASE_URL="$2"; shift 2 ;;
    --*) usage >&2; exit 2 ;;
    *) break ;;
  esac
done
[[ $# -ge 1 && $# -le 3 ]] || { usage >&2; exit 2; }
PROVIDER="$1"
HF_REPO="${2:-Qwen/Qwen2.5-Coder-14B-Instruct-GGUF}"
QUANT="${3:-Q4_K_M}"
[[ "$PROVIDER" == ollama || "$PROVIDER" == lm_studio ]] || { usage >&2; exit 2; }
[[ "$HF_REPO" =~ ^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$ ]] || { printf 'ERROR: Invalid Hugging Face org/repository.\n' >&2; exit 2; }
case "$QUANT" in Q3_K_M|Q4_K_M|Q5_K_M|Q6_K|Q8_0|FP16) ;; *) printf 'ERROR: Unsupported quantization.\n' >&2; exit 2 ;; esac
[[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || { printf 'ERROR: Run bootstrap_env.sh first; .env must be a regular private file.\n' >&2; exit 1; }
[[ "$(stat -c '%a' "$ENV_FILE")" == 600 ]] || { printf 'ERROR: .env must have mode 0600.\n' >&2; exit 1; }
if [[ -z "$BASE_URL" ]]; then
  if [[ "$DEPLOYMENT" == compose ]]; then
    [[ "$PROVIDER" == ollama ]] || { printf 'ERROR: LM Studio in Compose requires --base-url reachable FROM the gateway container.\n' >&2; exit 2; }
    BASE_URL=http://ollama:11434/v1
  elif [[ "$PROVIDER" == ollama ]]; then BASE_URL=http://127.0.0.1:11434/v1
  else BASE_URL=http://127.0.0.1:1234/v1; fi
fi
# Validate prior to any download or .env mutation. No DNS/network access here.
BASE_URL="$(python3 - "$BASE_URL" "$DEPLOYMENT" <<'PY'
import ipaddress, re, sys
from urllib.parse import urlsplit, urlunsplit
url, deployment = sys.argv[1:]
try:
    p = urlsplit(url)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username is not None or p.password is not None or p.query or p.fragment or any(c.isspace() or ord(c) < 32 for c in url):
        raise ValueError('use an HTTP(S) URL without credentials, query or fragment')
    if p.port is not None and not 1 <= p.port <= 65535:
        raise ValueError('invalid port')
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]+', p.hostname) or not re.fullmatch(r'[a-zA-Z0-9_./-]*', p.path):
        raise ValueError('unsupported hostname/path characters')
    try:
        ip = ipaddress.ip_address(p.hostname)
    except ValueError:
        ip = None
    if ip is not None:
        ip = getattr(ip, 'ipv4_mapped', None) or ip
        if ip.is_unspecified or ip.is_link_local or ip.is_multicast or str(ip) == '100.100.100.200':
            raise ValueError('metadata/link-local/unspecified destinations are prohibited')
    if deployment == 'compose' and ((ip is not None and ip.is_loopback) or p.hostname.lower() == 'localhost'):
        raise ValueError('container localhost is NOT the host inference server')
    path = p.path.rstrip('/')
    if not path.endswith('/v1'):
        path += '/v1'
    print(urlunsplit((p.scheme, p.netloc, path, '', '')))
except ValueError as exc:
    raise SystemExit(f'ERROR: {exc}') from exc
PY
)"
HF_TAG="hf.co/${HF_REPO}:${QUANT}"
MODEL=redgate-analyst
[[ "$PROVIDER" != lm_studio ]] || MODEL="$HF_REPO"
TMP_MODELFILE=""
cleanup() { if [[ -n "$TMP_MODELFILE" ]]; then rm -f -- "$TMP_MODELFILE"; fi; }
trap cleanup EXIT
if [[ "$PULL" == true ]]; then
  if [[ "$PROVIDER" == ollama ]]; then
    TMP_MODELFILE="$(mktemp "${TMPDIR:-/tmp}/redgate-modelfile.XXXXXX")"
    sed "s|^FROM .*|FROM ${HF_TAG}|" "$ROOT_DIR/config/Modelfile.redgate" > "$TMP_MODELFILE"
    if [[ "$DEPLOYMENT" == compose ]]; then
      [[ "$BASE_URL" == http://ollama:11434/v1 ]] || { printf 'ERROR: --pull supports only the bundled Compose Ollama; prepare custom endpoints separately.\n' >&2; exit 2; }
      command -v docker >/dev/null 2>&1 || { printf 'ERROR: Docker Compose required for --compose --pull.\n' >&2; exit 1; }
      compose=(docker compose --project-directory "$ROOT_DIR" -f "$ROOT_DIR/docker-compose.yml")
      "${compose[@]}" --profile ollama up -d ollama
      "${compose[@]}" exec -T ollama ollama pull "$HF_TAG"
      # A private, nonsecret Modelfile is copied, never shell-interpolated remotely.
      "${compose[@]}" cp "$TMP_MODELFILE" ollama:/tmp/Modelfile.redgate-setup
      "${compose[@]}" exec -T ollama ollama create "$MODEL" -f /tmp/Modelfile.redgate-setup
      "${compose[@]}" exec -T ollama rm -f /tmp/Modelfile.redgate-setup
    else
      command -v ollama >/dev/null 2>&1 || { printf 'ERROR: Install the Ollama CLI before --pull.\n' >&2; exit 1; }
      # Respect the same explicit native endpoint when talking to the Ollama CLI.
      OLLAMA_HOST="${BASE_URL%/v1}" ollama pull "$HF_TAG"
      OLLAMA_HOST="${BASE_URL%/v1}" ollama create "$MODEL" -f "$TMP_MODELFILE"
    fi
  else
    command -v lms >/dev/null 2>&1 || { printf 'ERROR: Install the LM Studio CLI before --pull.\n' >&2; exit 1; }
    lms get "${HF_REPO}@${QUANT}"
    printf '[ACTION] Load the model in LM Studio and start its server; verify the exact model ID via /v1/models.\n'
  fi
fi
python3 - "$ENV_FILE" "$PROVIDER" "$BASE_URL" "$MODEL" "$QUANT" <<'PY'
import os, stat, sys, tempfile
from pathlib import Path
file = Path(sys.argv[1])
if file.is_symlink() or stat.S_IMODE(file.stat().st_mode) != 0o600:
    raise SystemExit('ERROR: .env must be a regular file with mode 0600.')
updates = dict(zip(('REDGATE_LLM_MODE', 'REDGATE_LLM_BASE_URL', 'REDGATE_LLM_MODEL', 'REDGATE_LLM_QUANT'), sys.argv[2:]))
lines = []
for line in file.read_text(encoding='utf-8').splitlines():
    key = line.partition('=')[0]
    if key in updates:
        continue
    lines.append(line)
lines.extend(f'{key}={value}' for key, value in updates.items())
fd, name = tempfile.mkstemp(prefix='.env.update.', dir=file.parent)
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        output.write('\n'.join(lines) + '\n')
        output.flush()
        os.fsync(output.fileno())
    os.replace(name, file)
finally:
    if os.path.exists(name):
        os.unlink(name)
PY
printf '[CONFIGURED] %s networking; .env updated privately.\n' "$DEPLOYMENT"
if [[ "$PULL" == false ]]; then printf '[ACTION] No model downloaded. Prepare the runtime yourself or rerun with --pull.\n'; fi
printf '[IMPORTANT] Existing SQLite runtime settings take precedence: select provider, base URL and model in the admin Runtime panel.\n'
printf '[SAFETY] Local inference needs downloaded weights and compute; no privacy or performance guarantee is implied.\n'
