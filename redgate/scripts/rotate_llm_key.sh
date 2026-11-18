#!/usr/bin/env bash
# Rotate through a directory bind mount. Single-file Docker binds retain the old
# inode across a rename; Compose intentionally mounts /run/secrets as a directory.
set -euo pipefail
umask 077
SECRET_DIR="${REDGATE_SECRET_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/secrets}"
SECRET_FILE="$SECRET_DIR/llm_api_key"
mkdir -p "$SECRET_DIR"
chmod 750 "$SECRET_DIR"
if [[ -t 0 ]]; then
  read -r -s -p 'Enter new LLM API key (hidden): ' NEW_KEY
  printf '\n'
else
  IFS= read -r NEW_KEY || [[ -n "${NEW_KEY:-}" ]]
fi
[[ ${#NEW_KEY} -ge 12 ]] || { printf 'ERROR: Key must be at least 12 characters.\n' >&2; exit 1; }
TMP_FILE="$(mktemp "$SECRET_DIR/.llm_key.XXXXXX")"
trap 'rm -f -- "$TMP_FILE"' EXIT
printf '%s' "$NEW_KEY" > "$TMP_FILE"
unset NEW_KEY
OLD_FP=none
if [[ -f "$SECRET_FILE" ]]; then
  # Preserve the restricted host group used by the non-root Compose gateway.
  chgrp --reference="$SECRET_FILE" "$TMP_FILE"
  OLD_FP="$(sha256sum "$SECRET_FILE" | awk '{print substr($1,1,12)}')"
fi
chmod 640 "$TMP_FILE"
NEW_FP="$(sha256sum "$TMP_FILE" | awk '{print substr($1,1,12)}')"
mv -f -- "$TMP_FILE" "$SECRET_FILE"
trap - EXIT
printf '[RedGate] LLM key rotated (%s -> %s) at %s. Revoke the old provider key separately.\n' \
  "$OLD_FP" "$NEW_FP" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
