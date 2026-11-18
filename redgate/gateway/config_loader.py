"""Externalized YAML configuration loader and database policy synchronizer."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from gateway.db import Database
from gateway.skills import seed_builtin_skills


@dataclass
class PlatformConfig:
    """Typed aggregate of separated YAML configuration files."""

    allowlist: dict[str, Any]
    tool_policy: dict[str, Any]
    script_policy: dict[str, Any]
    llm_proxy: dict[str, Any]
    operators: dict[str, Any]
    local_models: dict[str, Any]


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Required configuration file missing: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Configuration file {path} must contain a top-level YAML mapping.")
    return data


def load_platform_config(config_dir: str | Path) -> PlatformConfig:
    """Load separated allowlist, tool, script, llm_proxy, operators, and local_models YAMLs."""
    base = Path(config_dir)
    local_models_path = base / "local_models.yaml"
    local_models = _read_yaml(local_models_path) if local_models_path.exists() else {}
    return PlatformConfig(
        allowlist=_read_yaml(base / "allowlist.yaml"),
        tool_policy=_read_yaml(base / "tool_policy.yaml"),
        script_policy=_read_yaml(base / "script_policy.yaml"),
        llm_proxy=_read_yaml(base / "llm_proxy.yaml"),
        operators=_read_yaml(base / "operators.yaml"),
        local_models=local_models,
    )


def seed_database_from_config(
    db: Database,
    cfg: PlatformConfig,
    skills_dir: str | Path | None = None,
) -> None:
    """Synchronize declarative YAML policies, skills, model config, and scopes into SQLite."""
    for eng in cfg.allowlist.get("engagements", []):
        db.upsert_engagement(
            engagement_id=str(eng["id"]),
            name=str(eng.get("name", eng["id"])),
            description=str(eng.get("description", "")),
            valid_from=str(eng["valid_from"]),
            valid_until=str(eng["valid_until"]),
            active=bool(eng.get("active", True)),
        )
        for tgt in eng.get("targets", []):
            db.seed_allowlist_target(
                engagement_id=str(eng["id"]),
                target=str(tgt["target"]),
                description=str(tgt.get("description", "")),
                created_by=str(tgt.get("created_by", "config-seed")),
                active=bool(tgt.get("active", True)),
            )

    for tool in cfg.tool_policy.get("tools", []):
        db.upsert_tool_policy(
            tool_name=str(tool["tool_name"]),
            enabled=bool(tool.get("enabled", False)),
            max_timeout=int(tool.get("max_timeout", 30)),
            allowed_params=dict(tool.get("allowed_params", {})),
            risk_level=str(tool.get("risk_level", "high")),
            requires_approval=bool(tool.get("requires_approval", True)),
            description=str(tool.get("description", "")),
        )

    for lang, spec in cfg.script_policy.get("languages", {}).items():
        db.upsert_script_policy(
            language=str(lang).lower(),
            enabled=bool(spec.get("enabled", True)),
            allowed_imports=list(spec.get("allowed_imports", [])),
            forbidden_imports=list(spec.get("forbidden_imports", [])),
            forbidden_patterns=list(spec.get("forbidden_patterns", [])),
            max_runtime_sec=int(spec.get("max_runtime_sec", 15)),
            network_egress_allowlist=bool(spec.get("network_egress_allowlist", True)),
        )

    default_quota = cfg.llm_proxy.get("default_quota", {})
    for op in cfg.operators.get("operators", []):
        q = op.get("quota", default_quota)
        db.get_or_init_quota(
            operator_id=str(op["operator_id"]),
            period=str(q.get("period", "daily")),
            max_calls=int(q.get("max_calls", 50)),
            max_tokens=int(q.get("max_tokens", 40000)),
        )

    prov_cfg = cfg.llm_proxy.get("provider", {})
    init_mode = os.environ.get("REDGATE_LLM_MODE", str(prov_cfg.get("default_mode", "mock"))).lower()
    init_base = os.environ.get(
        "REDGATE_LLM_BASE_URL", str(prov_cfg.get("default_base_url", "http://127.0.0.1:11434/v1"))
    )
    init_model = os.environ.get(
        "REDGATE_LLM_MODEL", str(prov_cfg.get("default_model", "qwen2.5-coder:14b"))
    )
    db.get_or_init_llm_runtime(
        default_provider=init_mode,
        default_base_url=init_base,
        default_native_url=init_base.removesuffix("/v1"),
        default_model=init_model,
        default_quant=os.environ.get("REDGATE_LLM_QUANT", "Q4_K_M"),
    )

    if skills_dir is not None:
        seed_builtin_skills(db, skills_dir)
