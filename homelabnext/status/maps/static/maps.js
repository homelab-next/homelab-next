// SPDX-License-Identifier: Apache-2.0
// The interactive maps of the status hub (Topology and Dataflow; ADR-0018, docs/status.md).
// The page is complete without this file (server-rendered cards, rows and tables); the script
// adds pan and zoom, the flow overlay, the detail panel, tooltips, the filter, collapsing lanes
// and groups, and the theme switch.  Rules it keeps (the CSP and CodeQL hold it to them):
//  * data comes only from the page's JSON data element and data-* attributes, and
//    reaches the page only through textContent and setAttribute on non-script attributes --
//    never through a property or call that parses a string as HTML, never as code;
//  * no inline style attributes: geometry goes through element.style properties (CSSOM, which
//    a style-src policy does not block) and SVG attributes.
(function () {
  "use strict";

  const SVG_NS = "http://www.w3.org/2000/svg";
  const root = document.querySelector(".hx");
  if (!root) return;
  root.classList.add("js");

  function readJson(id) {
    const el = document.getElementById(id);
    if (!el) return null;
    try {
      return JSON.parse(el.textContent || "null");
    } catch (err) {
      return null;
    }
  }

  function make(tag, cls, text) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    if (text !== undefined && text !== null) el.textContent = String(text);
    return el;
  }

  // ── Theme (dark by default; remembered per browser when storage is allowed) ──
  const themeBtn = document.getElementById("theme-toggle");
  function setTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    if (themeBtn) themeBtn.textContent = theme === "dark" ? "Light theme" : "Dark theme";
  }
  try {
    const saved = window.localStorage.getItem("hnx-map-theme");
    if (saved === "light" || saved === "dark") setTheme(saved);
  } catch (err) {
    /* storage blocked: keep the page's default */
  }
  if (themeBtn) {
    setTheme(document.documentElement.getAttribute("data-theme") || "dark");
    themeBtn.addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      setTheme(next);
      try {
        window.localStorage.setItem("hnx-map-theme", next);
      } catch (err) {
        /* not remembered */
      }
    });
  }

  // ── Filter box (shared): Esc clears, Ctrl/Cmd+F focuses ──
  const filterInput = document.getElementById("filter-input");
  const filterTargets = [];
  function onFilter(fn) {
    filterTargets.push(fn);
  }
  function runFilter() {
    const q = filterInput ? filterInput.value.toLowerCase().trim() : "";
    filterTargets.forEach((fn) => fn(q));
  }
  if (filterInput) {
    filterInput.addEventListener("input", runFilter);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        filterInput.value = "";
        runFilter();
        closeDetail();
      }
      if ((e.ctrlKey || e.metaKey) && (e.key === "f" || e.key === "F")) {
        e.preventDefault();
        filterInput.focus();
      }
    });
  }

  // ── Detail panel (shared container; the topology fills it) ──
  const detailPanel = document.getElementById("detail-panel");
  const detailContent = document.getElementById("detail-content");
  const closeHandlers = [];
  function closeDetail() {
    if (!detailPanel) return;
    detailPanel.classList.remove("open");
    closeHandlers.forEach((fn) => fn());
  }
  const closeBtn = document.getElementById("detail-close");
  if (closeBtn) closeBtn.addEventListener("click", closeDetail);

  // ── Collapsible sections (lanes and dataflow groups): a button controls one element ──
  const afterToggle = [];
  document.querySelectorAll("[data-collapse]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = document.getElementById(btn.getAttribute("data-collapse"));
      if (!target) return;
      const collapsed = target.classList.toggle("collapsed");
      btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
      const chev = btn.querySelector(".vlan-chevron");
      if (chev) chev.textContent = collapsed ? "▸" : "▾";
      afterToggle.forEach((fn) => fn());
    });
  });

  const topo = document.getElementById("topo-canvas");
  if (topo) initTopology(topo);
  const df = document.getElementById("df-groups");
  if (df) initDataflow(df);

  // ─────────────────────────────────────────────────────────────────── Topology
  function initTopology(wrap) {
    // Every const/let the drawing functions use is declared here, BEFORE the first call to
    // resetView() at the bottom: resetView() draws the arrows synchronously, and a binding
    // declared after that call would still be in its temporal dead zone (ReferenceError on load).
    const inner = document.getElementById("topo-inner");
    const svg = document.getElementById("flow-svg");
    const flowToggle = document.getElementById("flow-toggle");
    const powerToggle = document.getElementById("power-toggle");
    const resetBtn = document.getElementById("reset-btn");
    const tooltipEl = document.getElementById("tooltip-el");
    const data = readJson("topo-data") || {};
    const edges = Array.isArray(data.edges) ? data.edges : [];
    const powerLines = Array.isArray(data.power) ? data.power : [];
    const details = data.details && typeof data.details === "object" ? data.details : {};
    const cards = Array.from(inner.querySelectorAll(".net-card[data-node]"));
    // Node elements by id in a Map -- never a [data-node="..."] selector built from data, which
    // would need CSS escaping (the CSS escape helper is missing in some engines, jsdom among
    // them) to be safe.
    const nodes = new Map();
    inner.querySelectorAll("[data-node]").forEach((el) => {
      if (!nodes.has(el.getAttribute("data-node"))) nodes.set(el.getAttribute("data-node"), el);
    });
    let scale = 1;
    let panX = 0;
    let panY = 0;
    let panning = false;
    let startX = 0;
    let startY = 0;
    let flowsOn = false;
    let powerOn = false;
    let selected = null;

    function applyTransform() {
      inner.style.transform = "translate(" + panX + "px, " + panY + "px) scale(" + scale + ")";
    }

    // getBoundingClientRect(), not offsetLeft/offsetTop: offsetLeft is relative to the nearest
    // positioned ancestor (a lane, a stack), not to the canvas, so arrows drawn from it land off
    // by that ancestor's offset.  The client rect accounts for every ancestor; subtracting the
    // canvas's own rect and dividing by the current scale gives the canvas's local (untransformed)
    // coordinates, which is what the SVG inside it needs.
    function center(id) {
      const el = nodes.get(id);
      if (!el || el.getClientRects().length === 0) return null;
      const lane = el.closest(".vlan-content.collapsed");
      if (lane && el.classList.contains("net-card")) return null;
      const r = el.getBoundingClientRect();
      const ir = inner.getBoundingClientRect();
      const header = el.classList.contains("vlan-lane") ? el.querySelector(".vlan-header") : null;
      const box = header ? header.getBoundingClientRect() : r;
      return {
        x: (box.left - ir.left) / scale + box.width / scale / 2,
        y: (box.top - ir.top) / scale + box.height / scale / 2,
      };
    }

    function clearArrows() {
      svg.querySelectorAll(".flow-arrow, .power-line").forEach((p) => p.remove());
    }

    // UPS -> what it feeds: straight dotted lines, drawn under the flow arrows
    function drawPowerLines() {
      if (!powerOn) return;
      powerLines.forEach((line) => {
        const a = center(line.source);
        const b = center(line.dest);
        if (!a || !b) return;
        const path = document.createElementNS(SVG_NS, "path");
        path.setAttribute("d", "M" + a.x + "," + a.y + " L" + b.x + "," + b.y);
        path.setAttribute("class", "power-line");
        path.dataset.source = line.source;
        path.dataset.dest = line.dest;
        const title = document.createElementNS(SVG_NS, "title");
        title.textContent = String(line.source).replace(/^ups:/, "") + " feeds " + String(line.dest).replace(/^[a-z]+:/, "");
        path.appendChild(title);
        svg.appendChild(path);
      });
    }

    function drawFlowArrows() {
      clearArrows();
      svg.setAttribute("width", String(inner.scrollWidth));
      svg.setAttribute("height", String(inner.scrollHeight));
      drawPowerLines();
      if (!flowsOn) return;
      edges.forEach((edge) => {
        const a = center(edge.source);
        const b = center(edge.dest);
        if (!a || !b) return;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const mx = a.x + dx * 0.5;
        const my = a.y + dy * 0.5 - Math.min(60, Math.abs(dx) * 0.15);
        const path = document.createElementNS(SVG_NS, "path");
        path.setAttribute("d", "M" + a.x + "," + a.y + " Q" + mx + "," + my + " " + b.x + "," + b.y);
        const planned = edge.state === "planned";
        path.setAttribute("class", "flow-arrow" + (planned ? " planned" : ""));
        path.setAttribute("marker-end", planned ? "url(#arrowhead-planned)" : "url(#arrowhead)");
        path.dataset.source = edge.source;
        path.dataset.dest = edge.dest;
        const title = document.createElementNS(SVG_NS, "title");
        title.textContent = (edge.label || "") + (planned ? " (planned)" : "");
        path.appendChild(title);
        svg.appendChild(path);
      });
      if (selected) highlightFlowsFor(selected);
    }

    function highlightFlowsFor(id) {
      if (!flowsOn) return;
      const mine = edges.filter((e) => e.source === id || e.dest === id);
      svg.querySelectorAll(".flow-arrow").forEach((p) => {
        p.classList.toggle("highlighted", p.dataset.source === id || p.dataset.dest === id);
      });
      const related = new Set([id]);
      mine.forEach((e) => {
        related.add(e.source);
        related.add(e.dest);
      });
      cards.forEach((c) => {
        const n = c.getAttribute("data-node");
        c.classList.toggle("flow-dimmed", mine.length > 0 && !related.has(n));
      });
    }

    function clearFlowHighlight() {
      svg.querySelectorAll(".flow-arrow").forEach((p) => p.classList.remove("highlighted"));
      cards.forEach((c) => c.classList.remove("flow-dimmed"));
    }

    function resetView() {
      inner.style.transform = "translate(0px, 0px) scale(1)";
      const ww = wrap.clientWidth || 800;
      const wh = wrap.clientHeight || 600;
      const cw = inner.scrollWidth || ww;
      const ch = inner.scrollHeight || wh;
      scale = Math.min(ww / cw, wh / ch) * 0.96;
      scale = Math.max(0.2, Math.min(scale, 1));
      panX = Math.max(0, (ww - cw * scale) / 2);
      panY = 8;
      applyTransform();
      drawFlowArrows();
    }

    // ── flows toggle ──
    flowToggle.addEventListener("click", () => {
      flowsOn = !flowsOn;
      flowToggle.classList.toggle("active", flowsOn);
      flowToggle.setAttribute("aria-pressed", flowsOn ? "true" : "false");
      flowToggle.textContent = flowsOn ? "↔ Hide Data Flows" : "↔ Show Data Flows";
      drawFlowArrows();
      if (!flowsOn) clearFlowHighlight();
    });

    if (powerToggle) {
      powerToggle.addEventListener("click", () => {
        powerOn = !powerOn;
        powerToggle.classList.toggle("active", powerOn);
        powerToggle.setAttribute("aria-pressed", powerOn ? "true" : "false");
        powerToggle.textContent = powerOn ? "\u26a1 Hide Power" : "\u26a1 Show Power";
        drawFlowArrows();
      });
    }

    // ── pan and zoom ──
    wrap.addEventListener("mousedown", (e) => {
      if (e.button !== 0 || e.target.closest(".net-card, .vlan-header, input, button")) return;
      panning = true;
      startX = e.clientX - panX;
      startY = e.clientY - panY;
      wrap.classList.add("grabbing");
    });
    document.addEventListener("mousemove", (e) => {
      if (!panning) return;
      panX = e.clientX - startX;
      panY = e.clientY - startY;
      applyTransform();
    });
    document.addEventListener("mouseup", () => {
      panning = false;
      wrap.classList.remove("grabbing");
    });
    wrap.addEventListener(
      "wheel",
      (e) => {
        e.preventDefault();
        const rect = wrap.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const old = scale;
        scale = Math.max(0.15, Math.min(2.5, scale * (e.deltaY > 0 ? 0.92 : 1.08)));
        panX = mx - (mx - panX) * (scale / old);
        panY = my - (my - panY) * (scale / old);
        applyTransform();
      },
      { passive: false }
    );
    resetBtn.addEventListener("click", resetView);
    window.addEventListener("resize", resetView);

    // ── detail panel ──
    function section(label) {
      detailContent.appendChild(make("div", "section-label", label));
    }
    function showDetail(card) {
      const id = card.getAttribute("data-node");
      cards.forEach((c) => c.classList.remove("selected"));
      card.classList.add("selected");
      selected = id;
      detailContent.replaceChildren();
      const d = details[id];
      detailContent.appendChild(make("h3", "", (d && d.name) || card.getAttribute("data-hostname") || id));
      if (!d) {
        detailContent.appendChild(make("p", "muted", "No extended data for this node."));
      } else {
        if (d.subtitle) detailContent.appendChild(make("div", "muted", d.subtitle));
        section("Core");
        detailContent.appendChild(make("pre", "", d.yaml || "(no descriptor)"));
        if (d.does) {
          section("What it does");
          detailContent.appendChild(make("div", "does-text", d.does));
        }
        if (Array.isArray(d.services) && d.services.length) {
          section("Services (" + d.services.length + ")");
          d.services.forEach((s) => {
            const item = make("div", "service-item");
            item.appendChild(make("div", "service-name", s.name));
            if (s.description) item.appendChild(make("div", "service-desc", s.description));
            if (s.sub) item.appendChild(make("div", "service-desc", s.sub));
            detailContent.appendChild(item);
          });
        }
        if (Array.isArray(d.power) && d.power.length) {
          section("Power");
          d.power.forEach((line) => detailContent.appendChild(make("div", "power-item", line)));
        }
        if (Array.isArray(d.flows) && d.flows.length) {
          section("Data flow (" + d.flows.length + ")");
          d.flows.forEach((f) => {
            const cls = "flow-item " + (f.dir === "in" ? "flow-in" : "flow-out") + " state-" + f.state;
            detailContent.appendChild(make("div", cls, f.text));
          });
        }
      }
      detailPanel.classList.add("open");
      highlightFlowsFor(id);
    }
    closeHandlers.push(() => {
      cards.forEach((c) => c.classList.remove("selected"));
      selected = null;
      clearFlowHighlight();
    });

    // ── tooltip ──
    function tipRow(label, value) {
      const row = make("div", "tooltip-row");
      row.appendChild(make("span", "tooltip-label", label));
      row.appendChild(make("span", "tooltip-value", value || "—"));
      return row;
    }
    cards.forEach((card) => {
      card.addEventListener("click", () => showDetail(card));
      card.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          showDetail(card);
        }
      });
      card.addEventListener("mouseenter", () => {
        tooltipEl.replaceChildren();
        tooltipEl.appendChild(make("div", "t-name", card.getAttribute("data-hostname")));
        tooltipEl.appendChild(tipRow("IP", card.getAttribute("data-ip")));
        tooltipEl.appendChild(tipRow("VLAN", card.getAttribute("data-vlan")));
        tooltipEl.appendChild(tipRow("Type", card.getAttribute("data-type")));
        if (card.hasAttribute("data-power")) {
          tooltipEl.appendChild(tipRow("Power", card.getAttribute("data-power")));
        }
        const svc = make("div", "t-svc");
        svc.appendChild(tipRow("Services", card.getAttribute("data-services")));
        tooltipEl.appendChild(svc);
        tooltipEl.classList.add("visible");
      });
      card.addEventListener("mousemove", (e) => {
        const tw = tooltipEl.offsetWidth;
        const th = tooltipEl.offsetHeight;
        let tx = e.clientX + 16;
        let ty = e.clientY + 16;
        if (tx + tw > window.innerWidth - 10) tx = e.clientX - tw - 10;
        if (ty + th > window.innerHeight - 10) ty = e.clientY - th - 10;
        tooltipEl.style.left = tx + "px";
        tooltipEl.style.top = ty + "px";
      });
      card.addEventListener("mouseleave", () => tooltipEl.classList.remove("visible"));
    });

    // ── filter: host, IP, service, type ──
    onFilter((q) => {
      cards.forEach((card) => {
        if (!q) {
          card.classList.remove("highlight", "dimmed");
          return;
        }
        const text = ["data-hostname", "data-ip", "data-services", "data-type", "data-vlan"]
          .map((a) => card.getAttribute(a) || "")
          .join(" ")
          .toLowerCase();
        const hit = text.includes(q);
        card.classList.toggle("highlight", hit);
        card.classList.toggle("dimmed", !hit);
      });
    });

    // lanes animate their height: redraw once the transition settles
    afterToggle.push(() => window.setTimeout(drawFlowArrows, 320));

    resetView();
    window.setTimeout(drawFlowArrows, 50);
  }

  // ─────────────────────────────────────────────────────────────────── Dataflow
  function initDataflow(container) {
    const rows = Array.from(container.querySelectorAll(".flow-row"));
    const stateBtns = Array.from(document.querySelectorAll("[data-state-filter]"));
    let state = "all";
    function apply(q) {
      rows.forEach((row) => {
        const text = (row.getAttribute("data-search") || "").toLowerCase();
        const okText = !q || text.includes(q);
        const okState = state === "all" || row.getAttribute("data-state") === state;
        row.classList.toggle("dimmed", !(okText && okState));
      });
    }
    stateBtns.forEach((btn) => {
      btn.addEventListener("click", () => {
        state = btn.getAttribute("data-state-filter") || "all";
        stateBtns.forEach((b) => b.classList.toggle("active", b === btn));
        runFilter();
      });
    });
    onFilter(apply);
  }
})();
