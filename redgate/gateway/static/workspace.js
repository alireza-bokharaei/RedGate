/* RedGate 2.1 mission console. All data stays same-origin; no tokens in URLs. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const ACTIVE = new Set(["running", "pausing", "cancelling"]);
  let host = null, selectedId = null, snapshot = null, mode = "assets";
  let timer = null, generation = 0, sequence = 0, evidenceId = null;

  function element(name, text, className) {
    const node = document.createElement(name);
    if (text !== undefined) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }
  function badge(status) {
    const safe = /^[a-z_]+$/.test(status || "") ? status : "draft";
    return element("span", String(status || "draft").replaceAll("_", " "), `tag tag-${safe}`);
  }
  function empty(container, text) { container.replaceChildren(element("div", text, "ws-empty")); }
  function message(text, isError = false) {
    $("wsMessage").textContent = text;
    $("wsMessage").className = `status-banner status-${isError ? "err" : "ok"}`;
    $("wsMessage").hidden = !text;
  }
  function failed(result) {
    const detail = result.data?.detail;
    const text = typeof detail === "string" ? detail : JSON.stringify(detail || result.data || "Request failed");
    message(`HTTP ${result.status || "network error"}: ${text.slice(0, 700)}`, true);
  }
  function visible() { return !document.hidden && $("tab-workspace").classList.contains("active"); }
  function cancelTimer() { clearTimeout(timer); timer = null; }
  function schedule() {
    cancelTimer();
    if (visible() && snapshot?.missions?.some((m) => ACTIVE.has(m.status))) {
      timer = setTimeout(() => refresh(), 10000);
    }
  }
  function inspect(value, id = null) {
    evidenceId = id;
    $("wsInspector").textContent = JSON.stringify(value, null, 2);
    $("wsEvidenceExport").hidden = !id;
  }
  function skills() {
    const list = host.getContext().skills || [];
    const select = $("wsSkill"), prior = select.value || "web-surface-audit";
    const options = list.filter((s) => s.enabled).map((s) => {
      const option = element("option", s.name);
      option.value = s.skill_id;
      return option;
    });
    select.replaceChildren(...options);
    if (options.some((o) => o.value === prior)) select.value = prior;
  }
  function reset() {
    generation += 1;
    cancelTimer();
    selectedId = null; snapshot = null; evidenceId = null;
    if (!$("wsMissionList")) return;
    empty($("wsMissionList"), "Authenticate and select an engagement to load missions.");
    empty($("wsEvidenceList"), "No captured evidence selected.");
    empty($("wsFindingList"), "Run a mission to inspect its findings.");
    $("wsGraph").replaceChildren(); $("wsGraph").setAttribute("hidden", ""); $("wsGraphEmpty").hidden = false;
    $("wsInspector").textContent = "Select graph nodes, evidence, or a retest to inspect its record.";
    $("wsEvidenceExport").hidden = true;
    $("wsMissionCount").textContent = "0"; $("wsCoverage").textContent = "0 / 0";
    $("wsEvidenceCount").textContent = "0"; $("wsBudget").textContent = "—";
    renderSelected(null);
    message("");
  }
  async function refresh(force = false) {
    if (!host || (!visible() && !force)) return;
    const ctx = host.getContext();
    if (!ctx.operatorId) return;
    skills();
    const epoch = generation, requestSequence = ++sequence;
    const query = new URLSearchParams({ engagement_id: ctx.engagementId });
    if (selectedId) query.set("mission_id", selectedId);
    const result = await host.request(`/api/v1/workspace?${query}`);
    if (epoch !== generation || requestSequence !== sequence || host.getContext().engagementId !== ctx.engagementId) return;
    if (!result.ok) {
      if (result.status === 404 && selectedId) { selectedId = null; return refresh(force); }
      failed(result); cancelTimer(); return;
    }
    snapshot = result.data;
    selectedId = snapshot.selected_mission?.mission_id || null;
    $("wsMissionCount").textContent = String(snapshot.missions.length);
    const coverage = snapshot.asset_graph?.coverage || { tested: 0, total: 0 };
    $("wsCoverage").textContent = `${coverage.tested} / ${coverage.total}`;
    $("wsEvidenceCount").textContent = String(snapshot.evidence.length);
    renderMissionList(snapshot.missions);
    renderSelected(snapshot.selected_mission);
    renderGraph(); renderEvidence(snapshot.evidence); renderFindings();
    schedule();
  }
  function renderMissionList(missions) {
    if (!missions.length) {
      empty($("wsMissionList"), "No missions yet. Save a scope-checked plan, then explicitly start it."); return;
    }
    $("wsMissionList").replaceChildren(...missions.map((mission) => {
      const button = element("button", undefined, "ws-mission");
      button.type = "button";
      button.setAttribute("aria-current", String(mission.mission_id === selectedId));
      button.append(element("strong", mission.name), badge(mission.status),
        element("small", `${mission.completed_intents}/${mission.total_intents} intents · ${mission.used_actions}/${mission.max_actions} actions`));
      button.addEventListener("click", () => { selectedId = mission.mission_id; message(""); refresh(true); });
      return button;
    }));
  }
  function renderSelected(mission) {
    const ctx = host?.getContext() || {};
    const canControl = Boolean(mission && (mission.requested_by === ctx.operatorId || ctx.role === "admin"));
    $("wsMissionId").textContent = mission?.mission_id || "NO MISSION SELECTED";
    $("wsSelectedName").textContent = mission?.name || "An auditable path from scope to report";
    $("wsSelectedGoal").textContent = mission ? `${mission.goal}${mission.error ? " · " + mission.error : ""}` : "Completed intents survive restarts. Interrupted work requires explicit resume.";
    $("wsStatus").replaceWith(Object.assign(badge(mission?.status || "draft"), { id: "wsStatus" }));
    $("wsBudget").textContent = mission ? `${mission.used_actions} / ${mission.max_actions}` : "—";
    $("wsStart").textContent = mission?.status === "paused" ? "Resume mission" : "Start mission";
    $("wsStart").disabled = !canControl || !["draft", "paused"].includes(mission?.status);
    $("wsPause").disabled = !canControl || mission?.status !== "running";
    $("wsCancel").disabled = !canControl || !["draft", "paused", "running", "pausing"].includes(mission?.status);
    $("wsReport").disabled = !mission; $("wsExport").disabled = !mission;
    if (!mission) {
      const row = element("tr"), cell = element("td", "No intents yet.", "ws-subtle"); cell.colSpan = 4;
      row.append(cell); $("wsIntents").replaceChildren(row); return;
    }
    $("wsIntents").replaceChildren(...mission.intents.map((intent) => {
      const row = element("tr"), target = element("td"), state = element("td");
      target.append(element("div", intent.target), element("div", intent.intent_id, "ws-row-meta"));
      state.append(badge(intent.status));
      row.append(target, state, element("td", intent.attempts), element("td", [intent.run_id, intent.error].filter(Boolean).join(" · ") || "Awaiting execution"));
      return row;
    }));
  }
  function renderGraph() {
    if (!snapshot) return;
    const graph = mode === "assets" ? snapshot.asset_graph : snapshot.exploration_graph;
    const data = window.RedGateGraph.render($("wsGraph"), graph, (node) => {
      if (node.kind === "evidence") {
        const epoch = generation;
        host.request(`/api/v1/evidence/${encodeURIComponent(node.id)}`).then((res) => {
          if (epoch !== generation) return;
          if (res.ok) inspect(res.data.evidence, node.id); else failed(res);
        });
      } else inspect(node);
    });
    // SVGElement has no HTMLElement.hidden setter in real browsers.
    $("wsGraph").toggleAttribute("hidden", !data.nodes.length);
    $("wsGraphEmpty").hidden = Boolean(data.nodes.length);
    $("wsGraphNote").textContent = data.truncated ? "Graph view is capped at 120 nodes; use the paginated APIs for the complete inventory." : "Select a node to inspect its reference. Coverage is an observation ledger, not proof of security.";
    for (const [id, selected] of [["wsAssetMode", mode === "assets"], ["wsExplorationMode", mode === "exploration"]]) {
      $(id).classList.toggle("active", selected); $(id).setAttribute("aria-pressed", String(selected));
    }
  }
  function renderEvidence(evidence) {
    if (!evidence.length) { empty($("wsEvidenceList"), "No evidence yet. Enable anonymous HEAD collection when planning a mission."); return; }
    $("wsEvidenceList").replaceChildren(...evidence.map((entry) => {
      const button = element("button", undefined, "ws-evidence-row"), body = element("div", undefined, "ws-row-body");
      button.type = "button";
      const payload = entry.payload;
      body.append(element("div", `${payload.method} ${payload.url}`, "ws-row-title"),
        element("div", `${entry.sha256.slice(0, 16)}… · ${entry.integrity_valid ? "intact" : "INTEGRITY FAILED"} · pin ${payload.connected_ip}`, "ws-row-meta"));
      button.append(element("span", payload.status_code, "ws-http-code"), body);
      button.addEventListener("click", () => inspect(entry, entry.evidence_id));
      return button;
    }));
  }
  function renderFindings() {
    const findings = (snapshot?.exploration_graph?.nodes || []).filter((node) => node.kind === "finding");
    if (!findings.length) { empty($("wsFindingList"), "No findings are bound to this mission yet. Absence of findings is not assurance of security."); return; }
    $("wsFindingList").replaceChildren(...findings.slice(0, 60).map((finding) => {
      const row = element("div", undefined, "ws-finding-row"), body = element("div", undefined, "ws-row-body");
      body.append(element("div", finding.label, "ws-row-title"), element("div", `${finding.severity} · ${finding.status.replaceAll("_", " ")}`, "ws-row-meta"));
      const button = element("button", finding.retest_supported ? "Retest header" : "Manual review", "btn btn-secondary btn-xs");
      button.disabled = !finding.retest_supported;
      button.addEventListener("click", async () => {
        button.disabled = true;
        const epoch = generation;
        try {
          const result = await host.request(`/api/v1/recon/findings/${finding.finding_id}/retest`, { method: "POST", body: JSON.stringify({ note: "" }) });
          if (epoch !== generation) return;
          if (!result.ok) { failed(result); return; }
          inspect(result.data);
          message(`Retest: ${result.data.retest.outcome.replaceAll("_", " ")}. Original verdict unchanged; human review is still required.`);
          await refresh(true);
        } finally { if (button.isConnected) button.disabled = false; }
      });
      row.append(body, button); return row;
    }));
  }
  async function control(action) {
    if (!selectedId) return;
    const epoch = generation, id = selectedId;
    for (const button of [$("wsStart"), $("wsPause"), $("wsCancel")]) button.disabled = true;
    const result = await host.request(`/api/v1/missions/${encodeURIComponent(id)}/control`, { method: "POST", body: JSON.stringify({ action }) });
    if (epoch !== generation) return;
    if (!result.ok) failed(result);
    else message(action === "pause" ? "Pause requested. The current read-only intent will drain before the mission pauses." : action === "cancel" ? "Cancellation requested. No new action will start after the next checkpoint." : "Mission started with finite budgets and live scope enforcement.");
    await refresh(true);
  }
  async function download(path, filename, markdown = false) {
    const epoch = generation;
    const result = await host.request(path);
    if (epoch !== generation) return;
    if (!result.ok) { failed(result); return; }
    const body = markdown ? result.data.raw || "" : JSON.stringify(result.data, null, 2);
    const url = URL.createObjectURL(new Blob([body], { type: markdown ? "text/markdown;charset=utf-8" : "application/json" }));
    const link = element("a"); link.href = url; link.download = filename;
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function init(adapter) {
    host = adapter;
    $("wsRefresh").addEventListener("click", () => refresh(true));
    $("wsNewMission").addEventListener("click", () => { $("wsPlanPanel").open = true; skills(); $("wsName").focus(); });
    $("wsScheme").addEventListener("change", () => { $("wsPort").value = $("wsScheme").value === "https" ? 443 : 80; });
    $("wsAssetMode").addEventListener("click", () => { mode = "assets"; renderGraph(); });
    $("wsExplorationMode").addEventListener("click", () => { mode = "exploration"; renderGraph(); });
    $("wsStart").addEventListener("click", () => control(snapshot?.selected_mission?.status === "paused" ? "resume" : "start"));
    $("wsPause").addEventListener("click", () => control("pause"));
    $("wsCancel").addEventListener("click", () => control("cancel"));
    $("wsReport").addEventListener("click", () => download(`/api/v1/missions/${selectedId}/report.md`, `${selectedId}.md`, true));
    $("wsExport").addEventListener("click", () => download(`/api/v1/missions/${selectedId}/export.json`, `${selectedId}.json`));
    $("wsEvidenceExport").addEventListener("click", () => evidenceId && download(`/api/v1/evidence/${evidenceId}/export.json`, `${evidenceId}.json`));
    $("wsPlanForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const ctx = host.getContext(), epoch = generation;
      const targets = $("wsTargets").value.split(/[\n,]+/).map((target) => target.trim()).filter(Boolean);
      if (!targets.length || targets.length > 8) { message("Supply one to eight explicitly approved hosts or IPs.", true); return; }
      $("wsPlanSubmit").disabled = true;
      try {
        const result = await host.request("/api/v1/missions", { method: "POST", body: JSON.stringify({
          engagement_id: ctx.engagementId, name: $("wsName").value.trim(), goal: $("wsGoal").value.trim(), targets,
          skill_id: $("wsSkill").value, http: { scheme: $("wsScheme").value, port: Number($("wsPort").value), path: $("wsPath").value, method: "HEAD" },
          capture_evidence: $("wsCapture").checked, max_actions: Number($("wsMaxActions").value), max_seconds: Number($("wsMaxSeconds").value),
        }) });
        if (epoch !== generation) return;
        if (!result.ok) { failed(result); return; }
        selectedId = result.data.mission.mission_id; $("wsPlanPanel").open = false;
        message("Plan saved. No target has been contacted. Review the plan, then press Start mission.");
        await refresh(true);
      } finally { $("wsPlanSubmit").disabled = false; }
    });
    document.querySelectorAll(".nav-item").forEach((button) => button.addEventListener("click", () => {
      cancelTimer(); if (button.dataset.tab === "workspace") refresh(true);
    }));
    document.addEventListener("visibilitychange", () => { cancelTimer(); if (visible()) refresh(); });
    window.addEventListener("pagehide", cancelTimer);
  }
  window.RedGateWorkspace = { init, refresh, reset };
})();
