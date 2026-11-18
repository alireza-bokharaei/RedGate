#!/usr/bin/env bash
# =============================================================================
# RedGate Local AI Setup Helper (Ollama / LM Studio / Hugging Face GGUF)
# Connects RedGate to a 100% private, offline, zero-API-cost local quantized LLM.
#
# Usage examples:
#   ./scripts/setup_local_llm.sh ollama Qwen/Qwen2.5-Coder-14B-Instruct-GGUF Q4_K_M
#   ./scripts/setup_local_llm.sh lm_studio Qwen/Qwen2.5-Coder-7B-Instruct-GGUF Q5_K_M
# =============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROVIDER="${1:-ollama}"
HF_REPO="${2:-Qwen/Qwen2.5-Coder-14B-Instruct-GGUF}"
QUANT="${3:-Q4_K_M}"
ENV_FILE="${ROOT_DIR}/.env"

update_env_var() {
  local key="$1"
  local val="$2"
  if [[ ! -f "$ENV_FILE" ]]; then
    return 0
  fi
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i.bak "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
    rm -f "${ENV_FILE}.bak"
  else
    printf '%s=%s\n' "$key" "$val" >> "$ENV_FILE"
  fi
}

case "$PROVIDER" in
  ollama)
    HF_TAG="hf.co/${HF_REPO}:${QUANT}"
    CUSTOM_NAME="redgate-analyst"
    printf '[RedGate] Provider: Ollama | Quantized HF GGUF: %s\n' "$HF_TAG"

    if command -v ollama >/dev/null 2>&1; then
      printf '[1/2] Pulling quantized GGUF model from Hugging Face...\n'
      ollama pull "$HF_TAG"

      TMP_MODELFILE="$(mktemp /tmp/redgate-modelfile.XXXXXX)"
      sed "s|^FROM .*|FROM ${HF_TAG}|" "${ROOT_DIR}/config/Modelfile.redgate" > "$TMP_MODELFILE"
      printf '[2/2] Building personalized local model "%s"...\n' "$CUSTOM_NAME"
      ollama create "$CUSTOM_NAME" -f "$TMP_MODELFILE"
      rm -f "$TMP_MODELFILE"
    else
      printf '[INFO] ollama CLI not detected yet. Install from https://ollama.com then run:\n'
      printf '  ollama pull %s\n' "$HF_TAG"
      printf '  ollama create %s -f config/Modelfile.redgate\n' "$CUSTOM_NAME"
    fi

    update_env_var "REDGATE_LLM_MODE" "ollama"
    update_env_var "REDGATE_LLM_BASE_URL" "http://127.0.0.1:11434/v1"
    update_env_var "REDGATE_LLM_MODEL" "$CUSTOM_NAME"
    update_env_var "REDGATE_LLM_QUANT" "$QUANT"
    printf '[OK] Configured RedGate for local Ollama model "%s" (%s, zero API cost).\n' "$CUSTOM_NAME" "$QUANT"
    ;;

  lm_studio)
    printf '[RedGate] Provider: LM Studio | Quantized HF GGUF: %s@%s\n' "$HF_REPO" "$QUANT"
    if command -v lms >/dev/null 2>&1; then
      lms get "${HF_REPO}@${QUANT}"
      lms server start --port 1234
    else
      printf '[INFO] In LM Studio GUI or CLI:\n'
      printf '  1. Search Hugging Face for "%s" and download the %s GGUF file\n' "$HF_REPO" "$QUANT"
      printf '  2. Start Local Server on http://127.0.0.1:1234\n'
    fi

    update_env_var "REDGATE_LLM_MODE" "lm_studio"
    update_env_var "REDGATE_LLM_BASE_URL" "http://127.0.0.1:1234/v1"
    update_env_var "REDGATE_LLM_MODEL" "${HF_REPO}"
    update_env_var "REDGATE_LLM_QUANT" "$QUANT"
    printf '[OK] Configured RedGate for local LM Studio server on :1234 (%s).\n' "$QUANT"
    ;;

  *)
    printf 'Usage: %s <ollama|lm_studio> [hf_org/repo-GGUF] [Q4_K_M|Q5_K_M|Q6_K|Q8_0]\n' "$0" >&2
    exit 1
    ;;
esac
