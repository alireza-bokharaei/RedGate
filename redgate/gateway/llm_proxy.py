"""Restricted LLM Proxy Layer: secret stripping, quota guard, and script synthesis.

Supports:
- `openai_compatible`: Connects to any OpenAI-compatible gateway (local Ollama/vLLM
  for air-gapped Red Team enclaves, LiteLLM proxy, or cloud endpoints). API keys are
  read dynamically per request so key rotation takes effect with zero downtime.
- `mock`: Offline deterministic generator for CI tests and air-gapped lab demos,
  exercising the exact same secret scrubber, policy guard, quota accounting,
  multi-language static validation pipeline, and Go sandbox runner.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

# Hard guardrail rejecting exploit-authoring or stealth/evasion prompts before LLM invocation.
PROHIBITED_OBJECTIVE_RE = re.compile(
    r"\b(?:reverse\s*shell|bind\s*shell|exploit|payload|ransomware|keylogger|rootkit|"
    r"brute[\s\-]*force|credential\s*stuff|ddos|flood|fork\s*bomb|priv(?:ilege)?\s*esc|"
    r"evade\s*(?:ids|edr|av|waf)|bypass\s*(?:edr|av|waf)|os-shell|meterpreter|shellcode|"
    r"exfiltrat(?:e|ion)|rm\s+-rf)\b",
    re.IGNORECASE,
)


class LLMProxyError(RuntimeError):
    """Raised when the LLM proxy rejects or fails to fulfill a generation request."""


@dataclass
class GeneratedScriptArtifact:
    """Untrusted script + metadata returned by the LLM layer BEFORE validation."""

    language: str
    script: str
    dependencies: list[str]
    expected_runtime_sec: int
    risk_level: str
    risk_notes: str
    tokens_used: int
    provider_mode: str
    model: str
    scrubbed_secrets: list[str] = field(default_factory=list)
    sanitized_objective: str = ""


class LLMProxyGateway:
    """Enforces secret redaction, restricted prompt templates, and structured output."""

    def __init__(self, llm_cfg: dict[str, Any], runtime_getter: Any | None = None) -> None:
        self._cfg = llm_cfg
        self._runtime_getter = runtime_getter
        self._provider_cfg = dict(llm_cfg.get("provider", {}))
        scrub_cfg = dict(llm_cfg.get("secret_scrubbing", {}))
        self._scrub_enabled = bool(scrub_cfg.get("enabled", True))
        self._replacement = str(scrub_cfg.get("replacement", "[REDACTED_SECRET]"))
        self._scrub_rules: list[tuple[str, re.Pattern[str]]] = [
            (str(item["name"]), re.compile(str(item["regex"])))
            for item in scrub_cfg.get("patterns", [])
        ]
        tmpl = dict(llm_cfg.get("restricted_prompt_template", {}))
        self._system_tmpl = str(tmpl.get("system", ""))
        self._user_tmpl = str(tmpl.get("user", ""))

    def _active_runtime(self) -> tuple[str, str, str]:
        """Return (provider, openai_base_url, model) from live DB config or env."""
        if self._runtime_getter is not None:
            rt = self._runtime_getter()
            if rt:
                return (
                    str(rt.get("active_provider", "mock")).lower(),
                    str(rt.get("base_url", "http://127.0.0.1:11434/v1")).rstrip("/"),
                    str(rt.get("active_model", "qwen2.5-coder:14b")),
                )
        env_mode = str(self._provider_cfg.get("mode_env", "REDGATE_LLM_MODE"))
        env_url = str(self._provider_cfg.get("base_url_env", "REDGATE_LLM_BASE_URL"))
        env_model = str(self._provider_cfg.get("model_env", "REDGATE_LLM_MODEL"))
        return (
            os.environ.get(env_mode, str(self._provider_cfg.get("default_mode", "mock"))).strip().lower(),
            os.environ.get(env_url, str(self._provider_cfg.get("default_base_url", "http://127.0.0.1:11434/v1"))).rstrip("/"),
            os.environ.get(env_model, str(self._provider_cfg.get("default_model", "qwen2.5-coder:14b"))).strip(),
        )

    @property
    def current_mode(self) -> str:
        return self._active_runtime()[0]

    @property
    def current_model(self) -> str:
        return self._active_runtime()[2]

    def _read_api_key(self) -> str:
        """Read API key from Docker secret file or env var (supports hot rotation)."""
        key_file = os.environ.get("REDGATE_LLM_API_KEY_FILE", "").strip()
        if key_file and Path(key_file).is_file():
            return Path(key_file).read_text(encoding="utf-8").strip()
        env_name = str(self._provider_cfg.get("api_key_env", "REDGATE_LLM_API_KEY"))
        return os.environ.get(env_name, "").strip()

    def scrub_secrets(self, text: str) -> tuple[str, list[str]]:
        """Redact API keys, JWTs, Bearer tokens, PEM blocks, and passwords."""
        if not self._scrub_enabled:
            return text, []
        sanitized = text
        triggered: list[str] = []
        for rule_name, pattern in self._scrub_rules:
            sanitized, count = pattern.subn(self._replacement, sanitized)
            if count > 0:
                triggered.append(f"{rule_name}({count})")
        return sanitized, triggered

    def check_objective_policy(self, objective: str) -> None:
        """Reject requests for exploits, brute force, destructive actions, or evasion."""
        match = PROHIBITED_OBJECTIVE_RE.search(objective)
        if match:
            raise LLMProxyError(
                f"Objective rejected by non-exploitation policy (matched '{match.group(0)}'). "
                "RedGate only generates benign, auditable security verification scripts."
            )

    def build_restricted_messages(
        self,
        *,
        engagement_id: str,
        target: str,
        language: str,
        sanitized_objective: str,
        allowed_imports: list[str],
        max_runtime_sec: int,
    ) -> list[dict[str, str]]:
        """Render the locked system and user prompt with zero secrets or extra scope."""
        system_msg = self._system_tmpl.format(
            language=language,
            target=target,
            allowed_imports=", ".join(allowed_imports),
            max_runtime_sec=max_runtime_sec,
        )
        user_msg = self._user_tmpl.format(
            engagement_id=engagement_id,
            target=target,
            language=language,
            sanitized_objective=sanitized_objective,
        )
        return [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_msg},
        ]

    async def generate_script(
        self,
        *,
        engagement_id: str,
        target: str,
        language: str,
        objective: str,
        script_policy: dict[str, Any],
    ) -> GeneratedScriptArtifact:
        """Scrub secrets, enforce prompt policy, call LLM gateway, and return untrusted script."""
        sanitized_obj, scrubbed = self.scrub_secrets(objective)
        self.check_objective_policy(sanitized_obj)

        allowed_imports = list(script_policy.get("allowed_imports", []))
        max_runtime = int(script_policy.get("max_runtime_sec", 15))
        messages = self.build_restricted_messages(
            engagement_id=engagement_id,
            target=target,
            language=language,
            sanitized_objective=sanitized_obj,
            allowed_imports=allowed_imports,
            max_runtime_sec=max_runtime,
        )

        mode, base_url, model = self._active_runtime()
        if mode in {"ollama", "lm_studio", "openai_compatible"}:
            artifact = await self._call_openai_compatible(
                messages, language, max_runtime, provider_name=mode, base_url=base_url, model=model
            )
        elif mode == "mock":
            artifact = self._synthesize_mock(messages, target, language, sanitized_obj, max_runtime)
        else:
            raise LLMProxyError(
                f"Unsupported LLM provider '{mode}'. Expected 'ollama', 'lm_studio', 'openai_compatible', or 'mock'."
            )

        artifact.scrubbed_secrets = scrubbed
        artifact.sanitized_objective = sanitized_obj
        return artifact

    async def synthesize_recon_triage(
        self,
        *,
        engagement_id: str,
        target: str,
        skill_name: str,
        report_focus: str,
        memory_context: str,
        findings: list[dict[str, Any]],
        discovered_assets: list[dict[str, Any]],
    ) -> tuple[str, int, str, str]:
        """Synthesize personalized recon triage via local Ollama/LM Studio/vLLM or mock.

        Returns `(synthesis_markdown, tokens_used, provider_mode, model_name)`.
        """
        mode, base_url, model = self._active_runtime()
        compact_findings = [
            {
                "title": f["title"],
                "severity": f["severity"],
                "priority_score": f["priority_score"],
                "confidence": f["ai_confidence"],
                "dual_verified": f.get("dual_verified", False),
                "suppressed_by_memory": f.get("suppressed_by_memory"),
                "requires_human_judgment": f.get("requires_human_judgment", True),
            }
            for f in findings[:12]
        ]
        messages = [
            {
                "role": "system",
                "content": (
                    "You are RedGate Local Security Triage Analyst. Produce a concise, high-signal "
                    "3-paragraph analysis covering: (1) top prioritized technical exposure, "
                    "(2) how the operator's Skill and saved Memory rules reduced noise, and "
                    "(3) exact areas where human judgment is irreplaceable (business logic, auth, "
                    "WAF/CDN compensating controls). Never propose exploit payloads."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Engagement: {engagement_id}\nTarget: {target}\nActive Skill: {skill_name}\n"
                    f"Focus: {report_focus}\nOperator Memory:\n{memory_context}\n"
                    f"Assets: {len(discovered_assets)}\nFindings JSON:\n{json.dumps(compact_findings)}"
                ),
            },
        ]

        if mode in {"ollama", "lm_studio", "openai_compatible"}:
            headers: dict[str, str] = {"Content-Type": "application/json"}
            api_key = self._read_api_key()
            if api_key and mode == "openai_compatible":
                headers["Authorization"] = f"Bearer {api_key}"
            try:
                async with httpx.AsyncClient(timeout=35.0) as client:
                    resp = await client.post(
                        f"{base_url}/chat/completions",
                        headers=headers,
                        json={
                            "model": model,
                            "messages": messages,
                            "temperature": 0.15,
                            "max_tokens": 600,
                        },
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    text = str(data["choices"][0]["message"]["content"]).strip()
                    used = int((data.get("usage") or {}).get("total_tokens") or _estimate_tokens(messages, text))
                    return text, used, mode, model
            except Exception as exc:  # noqa: BLE001
                fallback_note = (
                    f"> *Local runtime `{mode}` (`{base_url}`) unreachable ({type(exc).__name__}); "
                    "generated via offline deterministic triage engine.*\n\n"
                )
                synth = fallback_note + _offline_triage_summary(
                    target, skill_name, findings, memory_context, discovered_assets
                )
                return synth, _estimate_tokens(messages, synth), f"{mode}->mock_fallback", model

        synth = _offline_triage_summary(target, skill_name, findings, memory_context, discovered_assets)
        return synth, _estimate_tokens(messages, synth), "mock", "redgate-offline-triage-v2"

    async def _call_openai_compatible(
        self,
        messages: list[dict[str, str]],
        language: str,
        max_runtime: int,
        *,
        provider_name: str = "openai_compatible",
        base_url: str = "http://127.0.0.1:11434/v1",
        model: str = "qwen2.5-coder:14b",
    ) -> GeneratedScriptArtifact:
        api_key = self._read_api_key()
        timeout_sec = float(self._provider_cfg.get("request_timeout_sec", 45))
        max_tokens = int(self._provider_cfg.get("max_completion_tokens", 1400))
        temperature = float(self._provider_cfg.get("temperature", 0.1))

        headers: dict[str, str] = {"Content-Type": "application/json"}
        # Ollama and LM Studio run locally without API keys; send Bearer only if configured.
        if api_key and not api_key.startswith("mock-mode-placeholder"):
            headers["Authorization"] = f"Bearer {api_key}"

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        # Ollama & OpenAI support response_format json_object; LM Studio accepts prompt-guided JSON.
        if provider_name in {"ollama", "openai_compatible"}:
            payload["response_format"] = {"type": "json_object"}

        async with httpx.AsyncClient(timeout=timeout_sec) as client:
            resp = await client.post(f"{base_url}/chat/completions", headers=headers, json=payload)
        if resp.status_code >= 400:
            raise LLMProxyError(
                f"Upstream LLM gateway returned HTTP {resp.status_code}: {resp.text[:240]}"
            )

        data = resp.json()
        try:
            content = data["choices"][0]["message"]["content"]
            parsed = _extract_json_object(content)
        except Exception as exc:  # noqa: BLE001
            raise LLMProxyError(f"LLM returned malformed structured response: {exc}") from exc

        usage = data.get("usage") or {}
        total_tokens = int(usage.get("total_tokens") or _estimate_tokens(messages, content))
        risk = str(parsed.get("risk_level", "medium")).lower()
        if risk not in {"low", "medium", "high"}:
            risk = "medium"

        return GeneratedScriptArtifact(
            language=language,
            script=str(parsed["script"]),
            dependencies=[str(d) for d in parsed.get("dependencies", [])],
            expected_runtime_sec=max(1, min(int(parsed.get("expected_runtime_sec", 10)), max_runtime)),
            risk_level=risk,
            risk_notes=str(parsed.get("risk_notes", "AI-generated script — treat as untrusted.")),
            tokens_used=total_tokens,
            provider_mode=provider_name,
            model=model,
        )

    def _synthesize_mock(
        self,
        messages: list[dict[str, str]],
        target: str,
        language: str,
        sanitized_objective: str,
        max_runtime: int,
    ) -> GeneratedScriptArtifact:
        """Generate clean, runnable verification scripts in Python, Bash, Go, or JS."""
        local_gw_port = int(os.environ.get("REDGATE_GATEWAY_PORT", "8000"))
        if target.startswith(("http://", "https://")):
            url = target
        elif target == "127.0.0.1":
            url = f"http://{target}:{local_gw_port}/probe/headers"
        else:
            url = f"https://{target}/"
        short_obj = re.sub(r"[^A-Za-z0-9 .,_\-:/]", "", sanitized_objective)[:90]

        if language == "python":
            script = (
                '"""RedGate generated HTTP defensive header verification script."""\n'
                "import json\n"
                "import urllib.error\n"
                "import urllib.request\n\n"
                f'TARGET_URL = "{url}"\n'
                "REQUIRED_HEADERS = [\n"
                '    "strict-transport-security",\n'
                '    "content-security-policy",\n'
                '    "x-frame-options",\n'
                '    "x-content-type-options",\n'
                '    "referrer-policy",\n'
                "]\n\n"
                "def main() -> None:\n"
                '    req = urllib.request.Request(TARGET_URL, method="GET", headers={"User-Agent": "RedGate-Sandbox/1.0"})\n'
                "    report = {\n"
                f'        "objective": "{short_obj}",\n'
                '        "target_url": TARGET_URL,\n'
                '        "language": "python",\n'
                '        "present": {},\n'
                '        "missing": [],\n'
                "    }\n"
                "    try:\n"
                "        with urllib.request.urlopen(req, timeout=5) as resp:\n"
                '            report["status_code"] = resp.status\n'
                "            lower = {k.lower(): v for k, v in resp.headers.items()}\n"
                "            for name in REQUIRED_HEADERS:\n"
                "                if name in lower:\n"
                '                    report["present"][name] = lower[name]\n'
                "                else:\n"
                '                    report["missing"].append(name)\n'
                "    except (urllib.error.URLError, TimeoutError) as exc:\n"
                '        report["network_note"] = str(exc)\n'
                "    print(json.dumps(report, indent=2))\n\n"
                'if __name__ == "__main__":\n'
                "    main()\n"
            )
            deps = ["json", "urllib.request", "urllib.error"]

        elif language == "bash":
            script = (
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n\n"
                f'TARGET_URL="{url}"\n'
                f'printf \'[RedGate Bash Check] objective="%s" url="%s"\\n\' "{short_obj}" "$TARGET_URL"\n\n'
                'if HEADERS="$(curl -sS -I --max-time 5 "$TARGET_URL" 2>/dev/null)"; then\n'
                '  printf "%s\\n" "$HEADERS" | head -n 1 | tr -d \'\\r\'\n'
                '  for hdr in strict-transport-security content-security-policy x-frame-options x-content-type-options referrer-policy; do\n'
                '    if printf "%s\\n" "$HEADERS" | grep -qi "^${hdr}:"; then\n'
                '      printf "  [PRESENT] %s\\n" "$hdr"\n'
                "    else\n"
                '      printf "  [MISSING] %s\\n" "$hdr"\n'
                "    fi\n"
                "  done\n"
                "else\n"
                '  printf "  [INFO] Target %s unreachable within 5s timeout.\\n" "$TARGET_URL"\n'
                "fi\n"
            )
            deps = ["curl", "grep", "head", "printf"]

        elif language == "go":
            script = (
                "package main\n\n"
                "import (\n"
                '\t"encoding/json"\n'
                '\t"fmt"\n'
                '\t"net/http"\n'
                '\t"time"\n'
                ")\n\n"
                "type HeaderReport struct {\n"
                '\tObjective  string            `json:"objective"`\n'
                '\tTargetURL  string            `json:"target_url"`\n'
                '\tLanguage   string            `json:"language"`\n'
                '\tStatusCode int               `json:"status_code,omitempty"`\n'
                '\tPresent    map[string]string `json:"present"`\n'
                '\tMissing    []string          `json:"missing"`\n'
                '\tNote       string            `json:"network_note,omitempty"`\n'
                "}\n\n"
                "func main() {\n"
                f'\ttargetURL := "{url}"\n'
                "\trequired := []string{\n"
                '\t\t"Strict-Transport-Security",\n'
                '\t\t"Content-Security-Policy",\n'
                '\t\t"X-Frame-Options",\n'
                '\t\t"X-Content-Type-Options",\n'
                '\t\t"Referrer-Policy",\n'
                "\t}\n"
                "\treport := HeaderReport{\n"
                f'\t\tObjective: "{short_obj}",\n'
                "\t\tTargetURL: targetURL,\n"
                '\t\tLanguage:  "go",\n'
                "\t\tPresent:   map[string]string{},\n"
                "\t\tMissing:   []string{},\n"
                "\t}\n"
                "\tclient := &http.Client{Timeout: 5 * time.Second}\n"
                "\tresp, err := client.Get(targetURL)\n"
                "\tif err != nil {\n"
                "\t\treport.Note = err.Error()\n"
                "\t} else {\n"
                "\t\tdefer resp.Body.Close()\n"
                "\t\treport.StatusCode = resp.StatusCode\n"
                "\t\tfor _, h := range required {\n"
                "\t\t\tif val := resp.Header.Get(h); val != \"\" {\n"
                "\t\t\t\treport.Present[h] = val\n"
                "\t\t\t} else {\n"
                "\t\t\t\treport.Missing = append(report.Missing, h)\n"
                "\t\t\t}\n"
                "\t\t}\n"
                "\t}\n"
                "\tout, _ := json.MarshalIndent(report, \"\", \"  \")\n"
                "\tfmt.Println(string(out))\n"
                "}\n"
            )
            deps = ["encoding/json", "fmt", "net/http", "time"]

        elif language == "javascript":
            mod_name = "node:http" if url.startswith("http://") else "node:https"
            script = (
                f'const client = require("{mod_name}");\n\n'
                f'const targetUrl = "{url}";\n'
                "const requiredHeaders = [\n"
                '  "strict-transport-security",\n'
                '  "content-security-policy",\n'
                '  "x-frame-options",\n'
                '  "x-content-type-options",\n'
                '  "referrer-policy",\n'
                "];\n\n"
                "const req = client.get(targetUrl, { timeout: 5000 }, (res) => {\n"
                "  const present = {};\n"
                "  const missing = [];\n"
                "  for (const name of requiredHeaders) {\n"
                "    if (res.headers[name]) {\n"
                "      present[name] = String(res.headers[name]);\n"
                "    } else {\n"
                "      missing.push(name);\n"
                "    }\n"
                "  }\n"
                "  res.resume();\n"
                "  console.log(\n"
                "    JSON.stringify(\n"
                "      {\n"
                f'        objective: "{short_obj}",\n'
                "        target_url: targetUrl,\n"
                '        language: "javascript",\n'
                "        status_code: res.statusCode,\n"
                "        present,\n"
                "        missing,\n"
                "      },\n"
                "      null,\n"
                "      2\n"
                "    )\n"
                "  );\n"
                "});\n\n"
                'req.on("timeout", () => {\n'
                '  req.destroy(new Error("request timeout after 5000ms"));\n'
                "});\n\n"
                'req.on("error", (err) => {\n'
                "  console.log(\n"
                "    JSON.stringify(\n"
                '      { target_url: targetUrl, language: "javascript", network_note: err.message },\n'
                "      null,\n"
                "      2\n"
                "    )\n"
                "  );\n"
                "});\n"
            )
            deps = [mod_name]
        else:
            raise LLMProxyError(f"Unsupported generation language '{language}'.")

        tokens = _estimate_tokens(messages, script)
        return GeneratedScriptArtifact(
            language=language,
            script=script,
            dependencies=deps,
            expected_runtime_sec=min(6, max_runtime),
            risk_level="low",
            risk_notes=(
                "Single read-only HTTP request with 5s timeout; no state mutation. "
                "May produce one standard web access log entry on target."
            ),
            tokens_used=tokens,
            provider_mode="mock",
            model="redgate-offline-synthesizer-v1",
        )


def _extract_json_object(raw: str) -> dict[str, Any]:
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    obj = json.loads(cleaned)
    if not isinstance(obj, dict) or "script" not in obj:
        raise ValueError("JSON response missing required 'script' field.")
    return obj


def _estimate_tokens(messages: list[dict[str, str]], completion: str) -> int:
    total_chars = sum(len(m.get("content", "")) for m in messages) + len(completion)
    return max(64, total_chars // 4)


def _offline_triage_summary(
    target: str,
    skill_name: str,
    findings: list[dict[str, Any]],
    memory_context: str,
    assets: list[dict[str, Any]],
) -> str:
    in_scope = sum(1 for a in assets if a.get("in_scope"))
    blocked = sum(1 for a in assets if not a.get("in_scope"))
    suppressed = [f for f in findings if f.get("suppressed_by_memory")]
    dual = [f for f in findings if f.get("dual_verified")]
    active = [f for f in findings if not f.get("suppressed_by_memory")]
    top_titles = ", ".join(f["title"] for f in active[:3]) or "no elevated misconfigurations"

    mem_line = (
        f"Applied operator Memory rules to auto-downgrade **{len(suppressed)}** known false-positive item(s), keeping attention on actionable controls."
        if suppressed
        else (
            "Incorporated saved operator methodology & preference memories into priority ranking."
            if "No saved operator" not in memory_context
            else "Tip: save false-positive rules or methodology notes in Agent Memory to further sharpen future runs."
        )
    )
    dual_line = (
        f" **{len(dual)}** finding(s) were independently cross-confirmed via a statically validated Go script inside the Layer 3 Sandbox (confidence raised to 95%)."
        if dual
        else ""
    )
    return (
        f"**Priority Exposure**: Executed playbook **{skill_name}** across **{in_scope}** authorized asset(s) "
        f"(blocked **{blocked}** out-of-scope candidate(s)) targeting `{target}`. Highest-priority items: **{top_titles}**.{dual_line}\n\n"
        f"**Personalization & Noise Reduction**: {mem_line}\n\n"
        "**Human Judgment Boundary**: Automated recon verifies observable surface posture (DNS, ports, headers, TLS) "
        "but cannot judge business-logic flaws, authentication/authorization boundaries (IDOR/BOLA), or upstream "
        "CDN/WAF compensating controls. Manually validate each `REQUIRED` item below before final reporting."
    )
