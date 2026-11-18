"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { parseHTML } = require("linkedom");
const graph = require("../gateway/static/graph.js");
const source = fs.readFileSync(path.join(__dirname, "../gateway/static/workspace.js"), "utf8");
const markup = fs.readFileSync(path.join(__dirname, "../gateway/static/index.html"), "utf8");
const tick = () => new Promise(setImmediate);

function snapshot(status = "draft") {
  const mission = { mission_id: "msn-one", engagement_id: "ENG-A", requested_by: "owner", name: "<img src=x> baseline", goal: "Read-only fixture.",
    status, max_actions: 12, used_actions: 0, completed_intents: 0, total_intents: 1, intents: [{ intent_id: "int-one", target: "127.0.0.1", status: "pending", attempts: 0 }] };
  return {
    missions: [mission], selected_mission: mission,
    asset_graph: { nodes: [{ id: "asset-one", kind: "ip", label: "127.0.0.1", status: "untested" }], edges: [], coverage: { tested: 0, total: 1 } },
    exploration_graph: { nodes: [{ id: "finding:1", kind: "finding", label: "Missing CSP", finding_id: 1, status: "unreviewed", severity: "low", retest_supported: true },
      { id: "evd-one", kind: "evidence", label: "evd-one", status: "intact" }], edges: [] },
    evidence: [{ evidence_id: "evd-one", sha256: "a".repeat(64), integrity_valid: true, payload: { method: "HEAD", url: "http://127.0.0.1/", connected_ip: "127.0.0.1", status_code: 200 } }],
  };
}

function consoleFixture() {
  const { window, document } = parseHTML(markup);
  // LinkeDOM deliberately omits a few live browser-control properties.
  for (const select of document.querySelectorAll("select")) {
    Object.defineProperty(select, "value", {
      get() { return this.querySelector("option[selected]")?.value || this.querySelector("option")?.value || ""; },
      set(value) { for (const option of this.querySelectorAll("option")) { option.toggleAttribute("selected", option.value === String(value)); } },
    });
  }
  document.hidden = false;
  window.RedGateGraph = graph;
  const timers = new Map(), calls = [], downloads = [];
  let counter = 0, data = snapshot(), handler = null;
  let context = { engagementId: "ENG-A", operatorId: "owner", role: "operator", skills: [{ skill_id: "web-surface-audit", name: "Header check", enabled: true }] };
  const adapter = {
    getContext: () => context,
    request: async (url, options = {}) => {
      calls.push({ url, options });
      if (handler) return handler(url, options);
      if (url.includes("/control")) { data = snapshot("running"); return { ok: true, status: 200, data: { mission: data.selected_mission } }; }
      if (url.endsWith("/retest")) return { ok: true, status: 201, data: { retest: { outcome: "still_present" } } };
      if (url.endsWith("/report.md")) return { ok: true, status: 200, data: { raw: "# Fixture Markdown\n" } };
      if (url.includes("/evidence/")) return { ok: true, status: 200, data: { evidence: data.evidence[0] } };
      return { ok: true, status: 200, data };
    },
  };
  vm.runInNewContext(source, { window, document, URLSearchParams, Blob,
    URL: { createObjectURL(blob) { downloads.push(blob); return "blob:fixture"; }, revokeObjectURL() {} },
    setTimeout(fn, duration) { const id = ++counter; timers.set(id, { fn, duration }); return id; },
    clearTimeout(id) { timers.delete(id); },
  });
  const controller = window.RedGateWorkspace;
  controller.init(adapter);
  return { controller, window, document, calls, timers, downloads,
    setHandler(value) { handler = value; }, setContext(value) { context = { ...context, ...value }; },
    setData(value) { data = value; },
  };
}

test("workspace refresh renders real references as text without starting a scan", async () => {
  const fixture = consoleFixture();
  await fixture.controller.refresh(true);
  assert.equal(fixture.document.getElementById("wsMissionCount").textContent, "1");
  assert.equal(fixture.document.getElementById("wsGraph").hasAttribute("hidden"), false);
  assert.equal(fixture.document.querySelectorAll("img").length, 0);
  assert.ok(fixture.document.getElementById("wsSelectedName").textContent.startsWith("<img"));
  assert.equal(fixture.document.getElementById("wsStart").disabled, false);
  assert.ok(fixture.calls.every((call) => !call.options.method));
  fixture.setContext({ operatorId: "peer" });
  await fixture.controller.refresh(true);
  assert.equal(fixture.document.getElementById("wsStart").disabled, true);
  fixture.controller.reset();
});

test("start is explicit, finite state controls update, and polling stops on reset", async () => {
  const fixture = consoleFixture();
  await fixture.controller.refresh(true);
  fixture.document.getElementById("wsStart").click();
  await tick();
  const control = fixture.calls.find((call) => call.url.endsWith("/control"));
  assert.equal(control.options.method, "POST");
  assert.deepEqual(JSON.parse(control.options.body), { action: "start" });
  assert.equal(fixture.document.getElementById("wsPause").disabled, false);
  assert.ok(Array.from(fixture.timers.values()).some((timer) => timer.duration === 10000));
  fixture.controller.reset();
  assert.equal(fixture.timers.size, 0);
});

test("old workspace response cannot repopulate data after identity/engagement reset", async () => {
  const fixture = consoleFixture();
  let resolve;
  fixture.setHandler(() => new Promise((done) => { resolve = done; }));
  const pending = fixture.controller.refresh(true);
  fixture.controller.reset();
  fixture.setContext({ engagementId: "ENG-B", operatorId: "another" });
  resolve({ ok: true, status: 200, data: snapshot() });
  await pending;
  assert.equal(fixture.document.getElementById("wsMissionCount").textContent, "0");
  assert.equal(fixture.document.getElementById("wsGraph").childNodes.length, 0);
});

test("old evidence request cannot leak into a new engagement's inspector", async () => {
  const fixture = consoleFixture();
  await fixture.controller.refresh(true);
  fixture.document.getElementById("wsExplorationMode").click();
  let resolve;
  fixture.setHandler(() => new Promise((done) => { resolve = done; }));
  fixture.document.querySelector('#wsGraph [aria-label^="evidence:"]').dispatchEvent(new fixture.window.Event("click"));
  fixture.controller.reset();
  resolve({ ok: true, status: 200, data: { evidence: { private: "old-engagement-only" } } });
  await tick();
  assert.ok(!fixture.document.getElementById("wsInspector").textContent.includes("old-engagement-only"));
});

test("header retest is explicit and Markdown download is not parsed as JSON", async () => {
  const fixture = consoleFixture();
  await fixture.controller.refresh(true);
  fixture.document.querySelector("#wsFindingList button").click();
  await tick();
  assert.ok(fixture.calls.some((call) => call.url.endsWith("/findings/1/retest") && call.options.method === "POST"));
  assert.ok(fixture.document.getElementById("wsMessage").textContent.includes("Original verdict unchanged"));
  fixture.document.getElementById("wsReport").click();
  await tick();
  assert.equal(await fixture.downloads[0].text(), "# Fixture Markdown\n");
  fixture.controller.reset();
});
