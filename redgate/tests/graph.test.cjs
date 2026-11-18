"use strict";
const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const { parseHTML } = require("linkedom");
const graph = require("../gateway/static/graph.js");

test("graph projection is deterministic, non-mutating, layered and bounded", () => {
  const source = {
    nodes: Array.from({ length: 150 }, (_, i) => ({ id: `n${i}`, kind: i ? "endpoint" : "ip", label: `Asset ${i}` })),
    edges: [{ source: "n0", target: "n1" }, { source: "n0", target: "n1" },
      { source: "n0", target: "n149" }, { source: "missing", target: "n1" }, { source: "n0", target: "n0" }],
  };
  const original = JSON.stringify(source);
  const first = graph.project(source);
  assert.deepEqual(first, graph.project(source));
  assert.equal(JSON.stringify(source), original);
  assert.equal(first.nodes.length, graph.MAX_NODES);
  assert.equal(first.edges.length, 1);
  assert.equal(first.truncated, true);
  assert.ok(first.nodes[0].x < first.nodes[1].x);
  assert.ok(first.nodes.every((node) => Number.isFinite(node.x) && Number.isFinite(node.y)));
});

test("graph handles empty, duplicate, unexpected and prototype-like node kinds", () => {
  assert.equal(graph.project(null).nodes.length, 0);
  const value = graph.project({ nodes: [null, {}, { id: "a", kind: "__proto__" }, { id: "a" }, { id: "b", kind: "constructor" }], edges: [null] });
  assert.equal(value.nodes.length, 2);
  assert.ok(value.nodes.every((node) => Number.isFinite(node.x)));
  assert.equal(value.edges.length, 0);
  assert.equal(graph.color({ in_scope: false, status: "tested" }), "#a1a1aa");
  assert.equal(graph.color({ status: "tested" }), "#34d399");
  assert.equal(graph.color({ status: "integrity_error" }), "#f87171");
});

test("SVG renderer treats hostile labels as text and supports keyboard activation", () => {
  const { document, Event } = parseHTML('<svg id="graph"></svg>');
  const svg = document.getElementById("graph");
  let selected = null;
  graph.render(svg, { nodes: [{ id: "safe-ref", kind: "endpoint", label: '<img src=x onerror="alert(1)">', status: "tested" }] }, (node) => { selected = node.id; });
  assert.equal(svg.querySelectorAll("img").length, 0);
  assert.ok(svg.textContent.includes("<img"));
  const button = svg.querySelector('[role="button"]');
  assert.equal(button.getAttribute("tabindex"), "0");
  const event = new Event("keydown", { cancelable: true });
  event.key = "Enter";
  button.dispatchEvent(event);
  assert.equal(selected, "safe-ref");
  graph.render(svg, { nodes: [] });
  assert.equal(svg.childNodes.length, 0);
});

test("workspace markup has unique IDs, local assets and complete controller hooks", () => {
  const root = path.join(__dirname, "..");
  const html = fs.readFileSync(path.join(root, "gateway/static/index.html"), "utf8");
  const { document } = parseHTML(html);
  const ids = Array.from(document.querySelectorAll("[id]"), (node) => node.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(document.querySelector('#tab-workspace.active'));
  const controller = fs.readFileSync(path.join(root, "gateway/static/workspace.js"), "utf8");
  for (const [, id] of controller.matchAll(/\$\("([^"]+)"\)/g)) assert.ok(document.getElementById(id), `Missing UI hook ${id}`);
  const scripts = Array.from(document.querySelectorAll("script[src]"), (node) => node.getAttribute("src"));
  assert.deepEqual(scripts, ["/static/graph.js", "/static/workspace.js", "/static/app.js"]);
  for (const asset of document.querySelectorAll("script[src],link[href]")) {
    const url = asset.getAttribute("src") || asset.getAttribute("href");
    assert.ok(url.startsWith("/static/"), `Nonlocal asset ${url}`);
    assert.ok(fs.existsSync(path.join(root, "gateway", url)));
  }
});
