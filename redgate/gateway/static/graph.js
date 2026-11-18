/* Small deterministic graph projection. No graph engine, build step, or CDN. */
(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.RedstrikeGraph = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";
  const MAX_NODES = 120;
  const LAYERS = { domain: 0, ip: 0, service: 1, endpoint: 2, goal: 0, intent: 1, fact: 2, finding: 3, evidence: 3 };

  function project(graph) {
    const seen = new Set();
    const nodes = [];
    for (const source of Array.isArray(graph?.nodes) ? graph.nodes : []) {
      if (!source || typeof source.id !== "string" || !source.id || seen.has(source.id)) continue;
      seen.add(source.id);
      if (nodes.length < MAX_NODES) nodes.push({ ...source, label: String(source.label ?? source.id) });
    }
    const ids = new Set(nodes.map((n) => n.id));
    const edgeKeys = new Set();
    const edges = [];
    for (const edge of Array.isArray(graph?.edges) ? graph.edges : []) {
      if (!edge || !ids.has(edge.source) || !ids.has(edge.target) || edge.source === edge.target) continue;
      const key = JSON.stringify([edge.source, edge.target, edge.relation]);
      if (edgeKeys.has(key)) continue;
      edgeKeys.add(key);
      edges.push({ source: edge.source, target: edge.target, relation: String(edge.relation || "links") });
    }
    const columns = new Map();
    for (const node of nodes) {
      const layer = Object.hasOwn(LAYERS, node.kind) ? LAYERS[node.kind] : 2;
      if (!columns.has(layer)) columns.set(layer, []);
      columns.get(layer).push(node);
    }
    const maxRows = Math.max(1, ...Array.from(columns.values(), (col) => col.length));
    const height = Math.max(260, maxRows * 76 + 48);
    const layers = Math.max(3, ...columns.keys()) + 1;
    const width = layers * 246 + 24;
    for (const [layer, column] of columns) {
      column.forEach((node, index) => {
        node.x = 18 + layer * 246;
        node.y = (height - column.length * 76) / 2 + index * 76 + 8;
      });
    }
    return { nodes, edges, width, height, truncated: Boolean(graph?.truncated) || seen.size > MAX_NODES };
  }

  function color(node) {
    if (node.in_scope === false) return "#a1a1aa";
    if (node.kind === "finding") return { critical: "#f87171", high: "#f87171", medium: "#fbbf24", low: "#60a5fa" }[node.severity] || "#c4b5fd";
    if (["completed", "tested", "intact", "confirmed"].includes(node.status)) return "#34d399";
    if (["failed", "cancelled", "integrity_error", "budget_exhausted"].includes(node.status)) return "#f87171";
    return node.kind === "goal" ? "#c4b5fd" : "#64748b";
  }

  function render(svg, graph, onSelect) {
    const data = project(graph);
    svg.replaceChildren();
    svg.setAttribute("viewBox", `0 0 ${data.width} ${data.height}`);
    svg.style.minHeight = `${Math.min(560, data.height)}px`;
    const positions = new Map(data.nodes.map((node) => [node.id, node]));
    function el(name, attributes, parent) {
      const result = svg.ownerDocument.createElementNS(NS, name);
      for (const [key, value] of Object.entries(attributes || {})) result.setAttribute(key, String(value));
      (parent || svg).appendChild(result);
      return result;
    }
    for (const edge of data.edges) {
      const a = positions.get(edge.source), b = positions.get(edge.target);
      const x1 = a.x + 212, y1 = a.y + 27, x2 = b.x, y2 = b.y + 27;
      el("path", { d: `M${x1},${y1} C${x1 + 25},${y1} ${x2 - 25},${y2} ${x2},${y2}`, class: "graph-edge" });
    }
    for (const node of data.nodes) {
      const group = el("g", { transform: `translate(${node.x},${node.y})`, class: "graph-node", tabindex: 0, role: "button", "aria-label": `${node.kind}: ${node.label}, ${node.status || "observed"}` });
      el("title", {}, group).textContent = `${node.label}\n${node.status || "observed"}${node.in_scope === false ? " · scope revoked" : ""}`;
      el("rect", { width: 212, height: 55, rx: 8, fill: "#151d2b", stroke: color(node) }, group);
      el("circle", { cx: 14, cy: 17, r: 3, fill: color(node) }, group);
      el("text", { x: 24, y: 21, class: "graph-label" }, group).textContent = node.label.length > 27 ? node.label.slice(0, 26) + "…" : node.label;
      el("text", { x: 12, y: 41, class: "graph-meta" }, group).textContent = `${node.kind} · ${node.in_scope === false ? "scope revoked" : node.status || "observed"}`;
      if (typeof onSelect === "function") {
        group.addEventListener("click", () => onSelect(node));
        group.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onSelect(node); }
        });
      }
    }
    return data;
  }
  return { project, color, render, MAX_NODES };
});
