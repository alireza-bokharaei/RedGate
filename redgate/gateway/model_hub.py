"""Local AI Model Hub: Ollama, LM Studio, Hugging Face GGUF & Quantization Advisor.

Enables 100% private, offline, zero-API-cost inference by connecting RedGate to
local runtimes (Ollama on :11434, LM Studio on :1234, vLLM/llama.cpp) and helping
operators choose optimal GGUF quantizations (Q3_K_M..Q8_0/FP16) for their hardware.

Security Invariant:
  Regardless of which local model is attached (standard or custom open-weight),
  RedGate never bypasses allowlists, non-exploitation checks, 4-language static
  validation, Go sandbox isolation, Two-Person approval, or append-only audit logs.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

import httpx

SAFE_HF_REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,62}/[A-Za-z0-9][A-Za-z0-9._\-]{0,95}$")
SAFE_MODEL_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/:@]{1,179}$")
BLOCKED_METADATA_IPS = {"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"}


def validate_llm_endpoint_url(raw_url: str, provider: str) -> tuple[str, str]:
    """Validate an LLM base URL against SSRF/metadata abuse and derive native URL."""
    if provider == "mock":
        return "offline://mock", "offline://mock"

    parsed = urlparse(raw_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Invalid LLM endpoint URL '{raw_url}'; expected http(s)://host[:port]/v1.")
    if parsed.username or parsed.password:
        raise ValueError("LLM endpoint URL must not embed credentials; use rotate_llm_key.sh instead.")

    host = parsed.hostname.lower()
    if host in BLOCKED_METADATA_IPS:
        raise ValueError("Cloud metadata endpoint is permanently prohibited as an LLM URL.")
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_link_local or ip_obj.is_multicast:
            raise ValueError(f"Disallowed link-local/multicast LLM endpoint address '{host}'.")
    except ValueError as exc:
        if "Disallowed" in str(exc):
            raise

    port_suffix = f":{parsed.port}" if parsed.port else ""
    native_url = f"{parsed.scheme}://{host}{port_suffix}"
    clean_path = parsed.path.rstrip("/")
    openai_url = f"{native_url}{clean_path}" if clean_path.endswith("/v1") else f"{native_url}/v1"
    return openai_url, native_url


def validate_model_identifier(raw_model: str) -> str:
    """Validate Ollama, LM Studio, or Hugging Face `hf.co/<org>/<repo>:<quant>` tag."""
    cleaned = raw_model.strip()
    if not SAFE_MODEL_TAG_RE.match(cleaned) or ".." in cleaned:
        raise ValueError(f"Invalid model identifier '{raw_model}'.")
    return cleaned


def estimate_quantized_memory_gb(
    params_b: float, bits_per_weight: float, context_length: int
) -> dict[str, float]:
    """Estimate GGUF weight size, KV-cache footprint, and total runtime memory in GB."""
    weights_gb = params_b * (bits_per_weight / 8.0) * 1.08
    # Empirical KV-cache scaling across context length and model size (FP16/Q8 cache).
    kv_cache_gb = (context_length / 8192.0) * max(0.45, params_b * 0.085)
    compute_overhead_gb = 0.65
    total_gb = round(weights_gb + kv_cache_gb + compute_overhead_gb, 2)
    return {
        "weights_gb": round(weights_gb, 2),
        "kv_cache_gb": round(kv_cache_gb, 2),
        "total_required_gb": total_gb,
    }


class LocalModelHub:
    """Manages local LLM runtimes, Hugging Face GGUF catalog, and quantization sizing."""

    def __init__(self, models_cfg: dict[str, Any]) -> None:
        self.providers: dict[str, dict[str, Any]] = dict(models_cfg.get("providers", {}))
        self.quant_profiles: list[dict[str, Any]] = list(
            models_cfg.get("quantization_profiles", [])
        )
        self.catalog: list[dict[str, Any]] = list(models_cfg.get("huggingface_catalog", []))
        self.governance: dict[str, Any] = dict(models_cfg.get("custom_model_governance", {}))
        self._quant_by_code = {str(q["code"]).upper(): q for q in self.quant_profiles}

    def default_urls_for_provider(self, provider: str) -> tuple[str, str]:
        spec = self.providers.get(provider)
        if not spec:
            raise ValueError(f"Unknown LLM provider '{provider}'.")
        return str(spec["openai_base_url"]), str(spec["native_base_url"])

    async def probe_local_runtimes(self, active_cfg: dict[str, Any]) -> dict[str, Any]:
        """Non-destructively probe Ollama and LM Studio local servers for loaded models."""
        probes: dict[str, Any] = {}

        # 1. Probe Ollama native /api/tags
        ollama_url = (
            str(active_cfg["native_url"])
            if active_cfg.get("active_provider") == "ollama"
            else str(self.providers.get("ollama", {}).get("native_base_url", "http://127.0.0.1:11434"))
        )
        probes["ollama"] = await self._probe_ollama(ollama_url)

        # 2. Probe LM Studio /v1/models
        lms_url = (
            str(active_cfg["base_url"])
            if active_cfg.get("active_provider") == "lm_studio"
            else str(self.providers.get("lm_studio", {}).get("openai_base_url", "http://127.0.0.1:1234/v1"))
        )
        probes["lm_studio"] = await self._probe_openai_models(lms_url)

        return probes

    async def _probe_ollama(self, native_url: str) -> dict[str, Any]:
        if native_url.startswith("offline://"):
            return {"reachable": False, "url": native_url, "installed_models": []}
        try:
            async with httpx.AsyncClient(timeout=1.2) as client:
                resp = await client.get(f"{native_url.rstrip('/')}/api/tags")
                resp.raise_for_status()
                models = [
                    {
                        "name": m.get("name"),
                        "size_gb": round(int(m.get("size", 0)) / (1024**3), 2),
                        "quantization": (m.get("details") or {}).get("quantization_level"),
                        "parameter_size": (m.get("details") or {}).get("parameter_size"),
                    }
                    for m in resp.json().get("models", [])
                ]
                return {"reachable": True, "url": native_url, "installed_models": models}
        except Exception as exc:  # noqa: BLE001
            return {
                "reachable": False,
                "url": native_url,
                "installed_models": [],
                "hint": f"Not running locally ({type(exc).__name__}). Start with `ollama serve`.",
            }

    async def _probe_openai_models(self, openai_url: str) -> dict[str, Any]:
        if openai_url.startswith("offline://"):
            return {"reachable": False, "url": openai_url, "installed_models": []}
        try:
            async with httpx.AsyncClient(timeout=1.2) as client:
                resp = await client.get(f"{openai_url.rstrip('/')}/models")
                resp.raise_for_status()
                models = [{"name": m.get("id")} for m in resp.json().get("data", [])]
                return {"reachable": True, "url": openai_url, "installed_models": models}
        except Exception as exc:  # noqa: BLE001
            return {
                "reachable": False,
                "url": openai_url,
                "installed_models": [],
                "hint": f"Not running locally ({type(exc).__name__}). Start with `lms server start --port 1234`.",
            }

    def recommend_quantized_models(
        self,
        *,
        vram_gb: float,
        system_ram_gb: float,
        context_length: int = 8192,
        task: str = "recon_triage",
        custom_hf_repo: str | None = None,
        custom_params_b: float | None = None,
    ) -> dict[str, Any]:
        """Rank Hugging Face GGUF models + quantizations that fit operator hardware."""
        candidates = list(self.catalog)
        if custom_hf_repo:
            clean_repo = custom_hf_repo.strip().removeprefix("https://huggingface.co/").removeprefix("hf.co/").strip("/")
            if not SAFE_HF_REPO_RE.match(clean_repo):
                raise ValueError(
                    f"Invalid Hugging Face repo '{custom_hf_repo}'. Expected '<org>/<repo-GGUF>'."
                )
            est_params = float(custom_params_b or 8.0)
            candidates.insert(
                0,
                {
                    "id": "custom-hf-model",
                    "name": f"Custom HF GGUF ({clean_repo})",
                    "params_b": est_params,
                    "hf_repo": clean_repo,
                    "ollama_tag": f"hf.co/{clean_repo}",
                    "specialty": "Operator-selected open-weight GGUF model (runs under full RedGate sandbox & policy gates)",
                    "recommended_quants": ["Q4_K_M", "Q5_K_M", "Q6_K", "Q8_0"],
                    "role_fit": [task],
                },
            )

        usable_cpu_ram = max(2.0, system_ram_gb - 3.5)  # Leave OS + sandbox headroom.
        recommendations: list[dict[str, Any]] = []

        for model in candidates:
            params_b = float(model["params_b"])
            hf_repo = str(model["hf_repo"])
            role_bonus = 12 if task in model.get("role_fit", []) else 0

            best_option: dict[str, Any] | None = None
            for q_code in model.get("recommended_quants", ["Q4_K_M"]):
                q = self._quant_by_code.get(q_code.upper())
                if not q:
                    continue
                mem = estimate_quantized_memory_gb(params_b, float(q["bits_per_weight"]), context_length)
                req_gb = mem["total_required_gb"]

                if vram_gb > 0 and req_gb <= vram_gb * 0.92:
                    exec_mode = "full_gpu_vram"
                    fit_score = 40
                elif (vram_gb + usable_cpu_ram) >= req_gb and vram_gb >= req_gb * 0.4:
                    exec_mode = "hybrid_gpu_cpu_offload"
                    fit_score = 26
                elif usable_cpu_ram >= req_gb:
                    exec_mode = "cpu_quantized_viable"
                    fit_score = 16
                else:
                    continue

                score = round(
                    fit_score + role_bonus + min(28.0, params_b * 1.1) + float(q["quality_retention_pct"]) * 0.2,
                    1,
                )
                ollama_hf_ref = f"hf.co/{hf_repo}:{q_code}"
                option = {
                    "model_id": model["id"],
                    "name": model["name"],
                    "params_b": params_b,
                    "hf_repo": hf_repo,
                    "hf_url": f"https://huggingface.co/{hf_repo}",
                    "quantization": q_code,
                    "bits_per_weight": q["bits_per_weight"],
                    "quality_retention_pct": q["quality_retention_pct"],
                    "memory_estimate_gb": mem,
                    "execution_mode": exec_mode,
                    "specialty": model["specialty"],
                    "score": score,
                    "ollama_hf_model": ollama_hf_ref,
                    "commands": {
                        "ollama_pull_hf": f"ollama pull {ollama_hf_ref}",
                        "ollama_custom_analyst": (
                            f"ollama create redgate-{model['id']} -f config/Modelfile.redgate"
                        ),
                        "lm_studio_cli": f"lms get {hf_repo}@{q_code} && lms server start --port 1234",
                    },
                    "modelfile_snippet": self.render_modelfile(ollama_hf_ref, context_length),
                }
                if best_option is None or option["score"] > best_option["score"]:
                    best_option = option

            if best_option is not None:
                recommendations.append(best_option)

        recommendations.sort(key=lambda item: float(item["score"]), reverse=True)
        return {
            "hardware": {
                "vram_gb": vram_gb,
                "system_ram_gb": system_ram_gb,
                "usable_ram_after_os_gb": round(usable_cpu_ram, 1),
                "context_length": context_length,
                "task": task,
            },
            "governance_note": (
                "All local models (including custom open-weight Hugging Face GGUF builds) run 100% "
                "privately with zero API cost while remaining bound by RedGate allowlist, static "
                "validation, Go sandbox, and human-judgment controls."
            ),
            "recommendations": recommendations,
            "quantization_reference": self.quant_profiles,
        }

    @staticmethod
    def render_modelfile(from_model: str, context_length: int = 8192) -> str:
        """Build a ready-to-use Ollama Modelfile tuned for RedGate recon & script tasks."""
        return (
            f"FROM {from_model}\n"
            "PARAMETER temperature 0.12\n"
            "PARAMETER top_p 0.9\n"
            f"PARAMETER num_ctx {int(context_length)}\n"
            'SYSTEM "You are RedGate Analyst: perform precise, evidence-backed security '
            "recon triage, respect operator Skills and false-positive Memory rules, flag "
            'uncertain findings for human judgment, and stay within authorized read-only scope."\n'
        )
