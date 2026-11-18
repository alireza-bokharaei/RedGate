#!/usr/bin/env bash
# =============================================================================
# RedGate Zero-Downtime LLM API Key Rotation Helper
# Gateway reads REDGATE_LLM_API_KEY_FILE per request, so atomically replacing
# the secret file rotates credentials immediately without restarting containers.
# =============================================================================
set -euo pipefail

SECRET_DIR="${REDGATE_SECRET_DIR:-$(cd "$(dirname "$0")/.." && pwd)/secrets}"
SECRET_FILE="${SECRET_DIR}/llm_api_key"

mkdir -p "$SECRET_DIR"
chmod 700 "$SECRET_DIR"

if [[ -t 0 ]]; then
  read -r -s -p "Enter new LLM API key (input hidden): " NEW_KEY
  printf '\n'
else
  IFS= read -r NEW_KEY
fi

if [[ ${#NEW_KEY} -lt 12 ]]; then
  printf 'ERROR: Refusing key shorter than 12 characters.\n' >&2
  exit 1
fi

TMP_FILE="$(mktemp "${SECRET_DIR}/.llm_key.XXXXXX")"
chmod 600 "$TMP_FILE"
printf '%s' "$NEW_KEY" > "$TMP_FILE"

OLD_FP="none"
if [[ -f "$SECRET_FILE" ]]; then
  OLD_FP="$(sha256sum "$SECRET_FILE" | awk '{print substr($1,1,12)}')"
fi
NEW_FP="$(sha256sum "$TMP_FILE" | awk '{print substr($1,1,12)}')"

# Atomic rename ensures in-flight gateway reads never observe a partial key.
mv -f "$TMP_FILE" "$SECRET_FILE"
chmod 600 "$SECRET_FILE"

printf '[RedGate] LLM API key rotated atomically (%s -> %s) at %s\n' \
  "$OLD_FP" "$NEW_FP" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
