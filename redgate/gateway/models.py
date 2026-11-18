"""Typed Pydantic v2 schemas for the Redstrike Gateway API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

ScriptLanguage = Literal["python", "bash", "go", "javascript"]
RiskLevel = Literal["low", "medium", "high", "critical"]


class ScanRequest(BaseModel):
    """Request to run a policy-whitelisted Layer 2 MCP tool against an in-scope target."""

    engagement_id: str = Field(..., min_length=3, max_length=64, examples=["ENG-2026-001"])
    target: str = Field(..., min_length=1, max_length=253, examples=["example.com"])
    tool_name: str = Field(..., min_length=2, max_length=64, examples=["http_headers"])
    params: dict[str, Any] = Field(default_factory=dict)
    timeout_sec: int | None = Field(default=None, ge=1, le=300)


class ScriptGenerateRequest(BaseModel):
    """Request for AI-assisted generation and static validation of a verification script."""

    engagement_id: str = Field(..., min_length=3, max_length=64, examples=["ENG-2026-001"])
    target: str = Field(..., min_length=1, max_length=253, examples=["example.com"])
    language: ScriptLanguage = Field(..., examples=["python"])
    objective: str = Field(
        ...,
        min_length=8,
        max_length=1500,
        description="Plain-language description of the benign security verification check.",
    )
    auto_run: bool = Field(
        default=False,
        description="If true and validation passes (and risk is not high), run in Go sandbox immediately.",
    )


class ScriptValidateRequest(BaseModel):
    """Request to validate an operator-supplied script and register it if approved."""

    engagement_id: str = Field(..., min_length=3, max_length=64)
    target: str = Field(..., min_length=1, max_length=253)
    language: ScriptLanguage
    script: str = Field(..., min_length=1, max_length=32768)
    risk_notes: str = Field(default="Operator-submitted verification script", max_length=500)


class ScriptRunRequest(BaseModel):
    """Request to execute a previously validated, SHA-256-pinned script in Layer 3 Go Sandbox."""

    script_id: str = Field(..., min_length=6, max_length=64)
    timeout_sec: int | None = Field(default=None, ge=1, le=60)


class ApprovalDecisionRequest(BaseModel):
    """Two-person approval or rejection decision submitted by an approver or admin."""

    decision: Literal["approved", "rejected"]
    note: str = Field(default="", max_length=500)
    execute_immediately: bool = Field(
        default=True,
        description="When approved, dispatch the queued scan/script immediately.",
    )


class AllowlistCreateRequest(BaseModel):
    """Add an IP, CIDR, or domain target to an engagement's scope allowlist."""

    engagement_id: str = Field(..., min_length=3, max_length=64)
    target: str = Field(..., min_length=2, max_length=253)
    description: str = Field(..., min_length=3, max_length=300)


class AllowlistPatchRequest(BaseModel):
    """Activate or deactivate an existing allowlist target entry."""

    active: bool


class ToolPolicyPatchRequest(BaseModel):
    """Administrative toggle for tool policy enablement, timeout, and approval gate."""

    enabled: bool | None = None
    requires_approval: bool | None = None
    max_timeout: int | None = Field(default=None, ge=5, le=300)


# ---------------------------------------------------------------------------
# Iteration 2: Local Model Hub, Quantization, Skills, Memory & Recon Agent
# ---------------------------------------------------------------------------

LLMProviderType = Literal["ollama", "lm_studio", "openai_compatible", "mock"]
MemoryType = Literal[
    "methodology", "preference", "false_positive_rule", "target_note", "run_summary"
]
AnalystVerdict = Literal[
    "unreviewed", "confirmed", "false_positive", "accepted_risk", "escalated"
]


class QuantizationRecommendRequest(BaseModel):
    """Hardware specification used to recommend quantized Hugging Face GGUF models."""

    vram_gb: float = Field(default=8.0, ge=0.0, le=512.0)
    system_ram_gb: float = Field(default=16.0, ge=4.0, le=1024.0)
    context_length: int = Field(default=8192, ge=2048, le=65536)
    task: Literal["recon_triage", "script_generation", "prioritization", "report_writing"] = (
        "recon_triage"
    )
    custom_hf_repo: str | None = Field(
        default=None,
        max_length=160,
        description="Optional custom Hugging Face GGUF repo, e.g. 'Qwen/Qwen2.5-Coder-14B-Instruct-GGUF'.",
    )
    custom_params_b: float | None = Field(default=None, ge=0.5, le=200.0)


class LLMRuntimeUpdateRequest(BaseModel):
    """Switch active local LLM runtime (Ollama, LM Studio, vLLM/OpenAI-compat, or mock)."""

    provider: LLMProviderType
    base_url: str | None = Field(default=None, max_length=256)
    model: str = Field(..., min_length=2, max_length=180, examples=["qwen2.5-coder:14b"])
    quantization: str = Field(default="Q4_K_M", max_length=24)
    context_length: int = Field(default=8192, ge=2048, le=65536)


class SkillStepInput(BaseModel):
    """Single bounded step inside a personalized recon skill."""

    stage: str = Field(..., min_length=2, max_length=48)
    tool: Literal["dns_lookup", "tcp_port_probe", "http_headers", "tls_inspect", "sandbox_script", "nmap"]
    params: dict[str, Any] = Field(default_factory=dict)
    mode: Literal["execute", "recommend_approval"] = "execute"
    rationale: str = Field(default="", max_length=240)


class SkillCreateRequest(BaseModel):
    """Register or update a personalized operator Skill playbook."""

    skill_id: str = Field(..., min_length=3, max_length=48, pattern=r"^[a-z0-9][a-z0-9\-]{2,47}$")
    name: str = Field(..., min_length=3, max_length=96)
    category: str = Field(default="custom", max_length=40)
    description: str = Field(..., min_length=8, max_length=400)
    expand_wildcard_subdomains: bool = False
    subdomain_prefixes: list[str] = Field(default_factory=list, max_length=8)
    steps: list[SkillStepInput] = Field(..., min_length=1, max_length=6)
    prioritization_rules: dict[str, Any] = Field(default_factory=dict)
    report_focus: str = Field(default="", max_length=400)


class MemoryCreateRequest(BaseModel):
    """Store a personalized methodology note, preference, or false-positive rule."""

    engagement_id: str | None = Field(
        default=None,
        description="Null for global operator methodology/preferences; set for engagement-scoped notes.",
    )
    memory_type: Literal["methodology", "preference", "false_positive_rule", "target_note"]
    title: str = Field(..., min_length=3, max_length=120)
    content: str = Field(..., min_length=5, max_length=1000)
    tags: list[str] = Field(default_factory=list, max_length=10)
    pattern_key: str | None = Field(
        default=None,
        max_length=80,
        description="For false_positive_rule: finding key or header name (e.g. 'missing:content-security-policy').",
    )


class MemoryPatchRequest(BaseModel):
    """Activate or deactivate a stored memory item."""

    active: bool


class ReconRunRequest(BaseModel):
    """Launch a policy-bounded, memory-aware automated recon & triage pipeline."""

    engagement_id: str = Field(..., min_length=3, max_length=64)
    target: str = Field(..., min_length=1, max_length=253)
    skill_id: str = Field(default="perimeter-recon-pipeline", min_length=3, max_length=64)
    candidate_subdomains: list[str] = Field(
        default_factory=list,
        max_length=10,
        description="Optional subdomain candidates verified strictly against the engagement allowlist.",
    )
    http_port_override: int | None = Field(default=None, ge=1, le=65535)
    http_scheme_override: Literal["http", "https"] | None = None
    http_path_override: str | None = Field(default=None, max_length=128)
    queue_gated_followups: bool = Field(
        default=True,
        description="Enqueue medium-risk follow-up tools (e.g. nmap -T2) into approval_queue.",
    )
    operator_focus: str = Field(
        default="",
        max_length=500,
        description="Optional run-specific focus merged with operator Skills and Memory.",
    )


class FindingReviewRequest(BaseModel):
    """Human-in-the-loop analyst verdict on an AI-triaged recon finding."""

    verdict: AnalystVerdict
    note: str = Field(default="", max_length=500)
    learn_false_positive_rule: bool = Field(
        default=False,
        description="When verdict='false_positive', automatically save a rule into operator Memory.",
    )
