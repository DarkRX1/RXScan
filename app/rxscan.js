/* RXScan local GUI — same-origin typed API client.
   No business logic lives here: Rust is authoritative for entities,
   relationships, confidence, and provenance. This file only renders what
   the API returns. Empty means empty: no demo or fabricated findings.
   All dynamic strings go through textContent / DOM APIs only. */

(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function el(tag, text, attrs) {
    const n = document.createElement(tag);
    if (text !== undefined && text !== null) n.textContent = String(text);
    if (attrs) for (const k of Object.keys(attrs)) n.setAttribute(k, attrs[k]);
    return n;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  async function api(path, options) {
    const res = await fetch(path, {
      headers: { Accept: "application/json" },
      ...(options || {}),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      const msg =
        data && data.error && data.error.message
          ? data.error.code + ": " + data.error.message
          : "http " + res.status;
      const err = new Error(msg);
      err.status = res.status;
      err.code = data && data.error ? data.error.code : "http";
      throw err;
    }
    return data;
  }

  function postJson(path, body) {
    return api(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    });
  }

  function fmtTime(ms) {
    if (ms === null || ms === undefined) return "—";
    try {
      return new Date(Number(ms)).toISOString().replace("T", " ").replace("Z", " UTC");
    } catch (_) {
      return "—";
    }
  }

  function fmtDuration(ms) {
    if (ms === null || ms === undefined) return "—";
    const s = Math.max(0, Number(ms) / 1000);
    if (s < 60) return s.toFixed(1) + "s";
    const m = Math.floor(s / 60);
    return m + "m " + Math.round(s % 60) + "s";
  }

  function jobDuration(job) {
    const start = job.started_ms || job.created_ms;
    const end = job.finished_ms || Date.now();
    if (!start) return "—";
    return fmtDuration(end - start);
  }

  function statusLabel(job) {
    if (!job) return "—";
    if (job.partial && (job.status === "cancelled" || job.status === "timed_out"))
      return job.status + " (partial evidence kept)";
    return job.status;
  }

  function formMsg(node, text, ok) {
    node.textContent = text;
    node.classList.toggle("ok", !!ok);
  }

  /* -- entity kind colors: RXScan logo language (cyan/blue family) ------- */
  /* Primary entity cyan, related entities electric blue, everything else a
     restrained navy-blue step. Historical/passive nodes render subdued via
     opacity in CSS (.gnode.dim); contradictory edges get a distinct dash. */
  const KIND_COLORS = {
    domain: "#00efff",
    hostname: "#19f4ff",
    url: "#19f4ff",
    web_endpoint: "#19f4ff",
    ip: "#078cff",
    ip_address: "#078cff",
    asn: "#0758ff",
    network_endpoint: "#0758ff",
    organization: "#7cc4ff",
    account: "#7cc4ff",
    repository: "#5aa9e6",
    username: "#00efff",
    email: "#5aa9e6",
    service: "#3d8bfd",
    certificate: "#8fa9c2",
    document: "#6b7d94",
    dns_record: "#4f9fd1",
    technology: "#6b7d94",
    default: "#078cff",
  };
  function kindColor(kind) {
    if (!kind) return KIND_COLORS.default;
    const k = String(kind).toLowerCase();
    return KIND_COLORS[k] || KIND_COLORS.default;
  }

  /* -- graph renderer ----------------------------------------------------- */
  function makeGraph(svg, legendNode, inspectorBox, inspectorEmpty) {
    const NS = "http://www.w3.org/2000/svg";
    const view = { x: 0, y: 0, k: 1 };
    let nodes = [];
    let edges = [];
    let selected = null;
    let kindFilter = "";
    // Run-diff overlay: entity id -> added|removed|changed|not_covered.
    // Gray (not covered) is never red (removed); every state also carries
    // a text label, never color alone.
    let statusColors = new Map();
    const STATUS_STYLE = {
      added: "#3ddc84",
      removed: "#f06666",
      changed: "#f0a04b",
      not_covered: "#6b7d94",
    };

    function applyTransform(g) {
      g.setAttribute("transform", "translate(" + view.x + "," + view.y + ") scale(" + view.k + ")");
    }

    function render() {
      while (svg.firstChild) svg.removeChild(svg.firstChild);
      const g = document.createElementNS(NS, "g");
      applyTransform(g);
      svg.appendChild(g);
      const shown = nodes.filter((n) => !kindFilter || String(n.kind).toLowerCase() === kindFilter);
      const byId = new Map(shown.map((n) => [n.id, n]));
      // edges first (under nodes)
      for (const e of edges.slice(0, 400)) {
        const a = byId.get(e.from);
        const b = byId.get(e.to);
        if (!a || !b) continue;
        const under = document.createElementNS(NS, "line");
        under.setAttribute("x1", a._x.toFixed(1));
        under.setAttribute("y1", a._y.toFixed(1));
        under.setAttribute("x2", b._x.toFixed(1));
        under.setAttribute("y2", b._y.toFixed(1));
        under.setAttribute("stroke", "transparent");
        under.setAttribute("stroke-width", "14");
        under.setAttribute("class", "gedge-hit");
        under.setAttribute("tabindex", "0");
        under.setAttribute("role", "button");
        under.setAttribute("aria-label", "Relationship " + e.relation);
        under.addEventListener("click", () => selectEdge(e));
        under.addEventListener("keydown", (ev) => {
          if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); selectEdge(e); }
        });
        g.appendChild(under);
        const line = document.createElementNS(NS, "line");
        line.setAttribute("x1", a._x.toFixed(1));
        line.setAttribute("y1", a._y.toFixed(1));
        line.setAttribute("x2", b._x.toFixed(1));
        line.setAttribute("y2", b._y.toFixed(1));
        line.setAttribute("class", "gedge" + (selected && selected.type === "edge" && selected.id === edgeId(e) ? " selected" : ""));
        line.setAttribute("tabindex", "0");
        line.setAttribute("role", "button");
        line.setAttribute("aria-label", "Relationship " + e.relation);
        line.addEventListener("click", () => selectEdge(e));
        line.addEventListener("keydown", (ev) => {
          if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); selectEdge(e); }
        });
        g.appendChild(line);
      }
      for (const n of shown) {
        const hit = document.createElementNS(NS, "circle");
        hit.setAttribute("cx", n._x.toFixed(1));
        hit.setAttribute("cy", n._y.toFixed(1));
        hit.setAttribute("r", "18");
        hit.setAttribute("fill", "transparent");
        hit.setAttribute("class", "gnode-hit");
        hit.setAttribute("tabindex", "0");
        hit.setAttribute("role", "button");
        hit.setAttribute("aria-label", "Entity " + n.kind + " " + n.label);
        hit.addEventListener("click", () => selectNode(n));
        hit.addEventListener("keydown", (ev) => {
          if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); selectNode(n); }
        });
        g.appendChild(hit);
        const c = document.createElementNS(NS, "circle");
        c.setAttribute("cx", n._x.toFixed(1));
        c.setAttribute("cy", n._y.toFixed(1));
        c.setAttribute("r", n.id === (selected && selected.id) ? "10" : "8");
        c.setAttribute("class", "gnode" + (selected && selected.type === "node" && selected.id === n.id ? " selected" : ""));
        c.setAttribute("fill", kindColor(n.kind));
        c.setAttribute("tabindex", "0");
        c.setAttribute("role", "button");
        const status = statusColors.get(n.id);
        c.setAttribute("aria-label", "Entity " + n.kind + " " + n.label + (status ? ", " + status.replace("_", " ") : ""));
        if (status && STATUS_STYLE[status]) {
          c.setAttribute("stroke", STATUS_STYLE[status]);
          c.setAttribute("stroke-width", "3");
        }
        c.addEventListener("click", () => selectNode(n));
        c.addEventListener("keydown", (ev) => {
          if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); selectNode(n); }
        });
        const t = document.createElementNS(NS, "text");
        t.setAttribute("x", (n._x + 12).toFixed(1));
        t.setAttribute("y", (n._y + 4).toFixed(1));
        t.setAttribute("class", "glabel");
        const label = String(n.label || n.id);
        t.textContent = label.length > 24 ? label.slice(0, 23) + "…" : label;
        g.append(c, t);
      }
      renderLegend();
    }

    function edgeId(e) {
      return e.from + "|" + e.to + "|" + e.relation;
    }

    function kvRow(dl, k, v) {
      const div = document.createElement("div");
      const dt = document.createElement("dt");
      dt.textContent = k;
      const dd = document.createElement("dd");
      dd.textContent = v === null || v === undefined || v === "" ? "—" : String(v);
      div.append(dt, dd);
      dl.appendChild(div);
    }

    function selectNode(n) {
      selected = { type: "node", id: n.id };
      inspectorEmpty.hidden = true;
      inspectorBox.hidden = false;
      clear(inspectorBox);
      kvRow(inspectorBox, "entity", n.id);
      kvRow(inspectorBox, "kind", n.kind);
      kvRow(inspectorBox, "label", n.label);
      if (n.first_seen_ms !== undefined) kvRow(inspectorBox, "first seen", fmtTime(n.first_seen_ms));
      if (n.last_seen_ms !== undefined) kvRow(inspectorBox, "last seen", fmtTime(n.last_seen_ms));
      if (n.observation_count !== undefined) kvRow(inspectorBox, "observations", n.observation_count);
      if (n.depth !== undefined) kvRow(inspectorBox, "depth", n.depth);
      if (n.confidence !== undefined) kvRow(inspectorBox, "confidence", n.confidence);
      render();
    }

    function selectEdge(e) {
      selected = { type: "edge", id: edgeId(e) };
      inspectorEmpty.hidden = true;
      inspectorBox.hidden = false;
      clear(inspectorBox);
      kvRow(inspectorBox, "relationship", e.relation);
      kvRow(inspectorBox, "from", e.from);
      kvRow(inspectorBox, "to", e.to);
      kvRow(inspectorBox, "confidence", e.confidence);
      kvRow(inspectorBox, "module", e.module);
      kvRow(inspectorBox, "scan run", e.scan_run);
      kvRow(inspectorBox, "evidence", e.evidence);
      render();
    }

    function renderLegend() {
      if (!legendNode) return;
      clear(legendNode);
      const kinds = Array.from(new Set(nodes.map((n) => String(n.kind || "unknown")))).sort().slice(0, 12);
      for (const k of kinds) {
        const li = document.createElement("li");
        const sw = document.createElement("span");
        sw.className = "swatch";
        sw.style.background = kindColor(k);
        li.append(sw, document.createTextNode(k));
        legendNode.appendChild(li);
      }
      if (!kinds.length) legendNode.appendChild(el("li", "No entities — empty graph."));
      if (statusColors.size) {
        for (const [state, label] of [["added", "added (new)"], ["removed", "removed (confirmed)"], ["changed", "changed"], ["not_covered", "not covered (inconclusive)"]]) {
          const li = document.createElement("li");
          const sw = document.createElement("span");
          sw.className = "swatch";
          sw.style.background = STATUS_STYLE[state];
          li.append(sw, document.createTextNode(label));
          legendNode.appendChild(li);
        }
      }
    }

    function setData(nextNodes, nextEdges) {
      nodes = (nextNodes || []).slice(0, 120);
      edges = (nextEdges || []).slice(0, 240);
      // radial layout in world coordinates (pan/zoom independent)
      const cx = 320, cy = 180, rx = 240, ry = 130;
      nodes.forEach((n, i) => {
        const a = (2 * Math.PI * i) / Math.max(1, nodes.length);
        n._x = cx + rx * Math.cos(a);
        n._y = cy + ry * Math.sin(a);
      });
      view.x = 0; view.y = 0; view.k = 1;
      selected = null;
      if (inspectorBox) { inspectorBox.hidden = true; }
      if (inspectorEmpty) { inspectorEmpty.hidden = false; }
      render();
    }

    // pan (single pointer) + pinch zoom (two pointers, touch-friendly)
    let drag = null;
    const pointers = new Map();
    let pinchStart = 0;
    let pinchK = 1;
    function pinchDistance() {
      const pts = Array.from(pointers.values());
      if (pts.length < 2) return 0;
      const dx = pts[0].x - pts[1].x;
      const dy = pts[0].y - pts[1].y;
      return Math.sqrt(dx * dx + dy * dy);
    }
    svg.addEventListener("pointerdown", (ev) => {
      pointers.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
      if (pointers.size === 2) {
        pinchStart = pinchDistance() || 1;
        pinchK = view.k;
        drag = null;
      } else {
        drag = { x: ev.clientX, y: ev.clientY, vx: view.x, vy: view.y };
      }
      svg.setPointerCapture(ev.pointerId);
    });
    svg.addEventListener("pointermove", (ev) => {
      if (!pointers.has(ev.pointerId)) return;
      pointers.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
      if (pointers.size === 2) {
        const d = pinchDistance();
        if (d > 0 && pinchStart > 0) {
          view.k = Math.min(4, Math.max(0.4, pinchK * (d / pinchStart)));
          const g = svg.querySelector("g");
          if (g) applyTransform(g);
        }
        return;
      }
      if (!drag) return;
      view.x = drag.vx + (ev.clientX - drag.x);
      view.y = drag.vy + (ev.clientY - drag.y);
      const g = svg.querySelector("g");
      if (g) applyTransform(g);
    });
    function endPointer(ev) {
      pointers.delete(ev.pointerId);
      if (pointers.size < 2) pinchStart = 0;
      if (pointers.size === 0) drag = null;
    }
    svg.addEventListener("pointerup", endPointer);
    svg.addEventListener("pointercancel", endPointer);
    svg.addEventListener("wheel", (ev) => {
      ev.preventDefault();
      const f = ev.deltaY < 0 ? 1.1 : 0.9;
      view.k = Math.min(4, Math.max(0.4, view.k * f));
      const g = svg.querySelector("g");
      if (g) applyTransform(g);
    }, { passive: false });

    return {
      setData,
      zoom(f) {
        view.k = Math.min(4, Math.max(0.4, view.k * f));
        const g = svg.querySelector("g");
        if (g) applyTransform(g);
      },
      reset() {
        view.x = 0; view.y = 0; view.k = 1;
        const g = svg.querySelector("g");
        if (g) applyTransform(g);
      },
      setKindFilter(v) { kindFilter = String(v || "").toLowerCase(); render(); },
      kinds() { return Array.from(new Set(nodes.map((n) => String(n.kind || "unknown")))).sort(); },
      setStatusColors(map) { statusColors = new Map(Object.entries(map || {})); render(); },
      clearStatusColors() { statusColors = new Map(); render(); },
    };
  }

  /* -- timeline ------------------------------------------------------------ */
  function evidenceClass(module) {
    const m = String(module || "").toLowerCase();
    if (m.includes("passive") || m.startsWith("search") || m.includes("username") || m.includes("entity"))
      return "passive";
    if (m.includes("scan") || m.includes("tcp") || m.includes("probe") || m.includes("service") || m.includes("web") || m.includes("syn") || m.includes("connect"))
      return "direct";
    return "";
  }
  function renderTimeline(listNode, events) {
    clear(listNode);
    if (!events || !events.length) {
      listNode.appendChild(el("li", "No timeline events yet."));
      return;
    }
    const capped = events.slice(0, 120);
    for (const ev of capped) {
      const li = document.createElement("li");
      const cls = evidenceClass(ev.module);
      li.className = (ev.current ? "current" : "historical") + (cls ? " " + cls : "");
      const when = document.createElement("div");
      when.className = "t-when";
      when.textContent = fmtTime(ev.timestamp_ms) + " · " + (ev.current ? "current observation" : "historical observation");
      const body = document.createElement("div");
      body.textContent = (ev.kind || "?") + " · " + (ev.label || ev.entity_id || "?") + " · " + (ev.module || "");
      const run = document.createElement("div");
      run.className = "t-when";
      run.textContent = "run " + (ev.scan_run || "—");
      li.append(when, body, run);
      listNode.appendChild(li);
    }
    if (events.length > capped.length) {
      const more = document.createElement("li");
      more.textContent = "Showing " + capped.length + " of " + events.length + " — use project pagination to narrow.";
      listNode.appendChild(more);
    }
  }

  /* -- visualizations (only real data) ------------------------------------- */
  function renderPortSummary(node, tcp) {
    clear(node);
    if (!tcp) return;
    const rows = [
      ["open", tcp.open || 0, "open"],
      ["closed", tcp.closed || 0, "closed"],
      ["filtered/timed out", tcp.filtered_or_timed_out || 0, "filtered"],
      ["unscanned", tcp.unscanned || 0, "unknown"],
    ];
    const max = Math.max(1, ...rows.map((r) => r[1]));
    for (const [label, count, cls] of rows) {
      const row = document.createElement("div");
      row.className = "bar-row";
      const name = document.createElement("span");
      name.textContent = label + ": " + count;
      const bar = document.createElement("span");
      bar.className = "bar " + cls;
      bar.style.width = Math.max(4, Math.round((count / max) * 160)) + "px";
      row.append(name, bar);
      node.appendChild(row);
    }
  }

  function renderServiceDist(node, openPorts) {
    clear(node);
    if (!openPorts || !openPorts.length) {
      node.appendChild(el("span", "No services observed.", { class: "muted" }));
      return;
    }
    const buckets = { SSH: 0, HTTP: 0, HTTPS: 0, DNS: 0, Other: 0, Unknown: 0 };
    for (const p of openPorts) {
      const s = String(p.service || "").toLowerCase();
      if (!s || s === "unknown") buckets.Unknown++;
      else if (s.includes("ssh")) buckets.SSH++;
      else if (s === "https" || s.includes("https") || s.includes("tls")) buckets.HTTPS++;
      else if (s === "http" || s.includes("http")) buckets.HTTP++;
      else if (s.includes("dns")) buckets.DNS++;
      else buckets.Other++;
    }
    const max = Math.max(1, ...Object.values(buckets));
    for (const [label, count] of Object.entries(buckets)) {
      if (!count) continue;
      const row = document.createElement("div");
      row.className = "bar-row";
      row.appendChild(el("span", label + ": " + count));
      const bar = document.createElement("span");
      bar.className = "bar";
      bar.style.width = Math.max(4, Math.round((count / max) * 140)) + "px";
      row.appendChild(bar);
      node.appendChild(row);
    }
  }

  function renderCoverage(node, coverage) {
    clear(node);
    if (!coverage) return;
    const entries = Object.entries(coverage).filter(([_, v]) => typeof v === "number" || typeof v === "boolean");
    if (!entries.length) return;
    for (const [k, v] of entries) {
      const row = document.createElement("div");
      row.className = "bar-row";
      row.appendChild(el("span", k + ": " + v));
      node.appendChild(row);
    }
  }

  /* -- job tracking: SSE primary, slow fallback only when SSE fails ----- */
  /* Desired lifecycle: initial load, SSE for active jobs, refresh on
     create/terminal event, slow fallback polling only when SSE is
     unavailable. EventSource closes on terminal state. Hidden documents
     suspend nonessential polling. */
  const trackers = new Map();
  const FALLBACK_POLL_MS = 15000;
  function isHidden() {
    return typeof document !== "undefined" && document.hidden;
  }
  function trackJob(id, callbacks) {
    stopTracking(id);
    const st = { src: null, timer: 0, startedAt: Date.now() };
    trackers.set(id, st);
    const onEvent = () => {
      if (isHidden()) return;
      if (callbacks.onEvent) callbacks.onEvent();
    };
    function ensureFallback() {
      if (st.timer) return;
      st.timer = window.setInterval(onEvent, FALLBACK_POLL_MS);
    }
    let sseOk = false;
    try {
      if (typeof EventSource === "undefined") {
        ensureFallback();
      } else {
        const src = new EventSource("/api/v1/jobs/" + encodeURIComponent(id) + "/events");
        st.src = src;
        src.onmessage = () => { sseOk = true; onEvent(); };
        src.onerror = () => {
          try { src.close(); } catch (_) {}
          st.src = null;
          // SSE unavailable: slow fallback polling only in this case.
          if (!sseOk) ensureFallback();
        };
      }
    } catch (_) {
      ensureFallback();
    }
    return st;
  }
  function stopTracking(id) {
    const st = trackers.get(id);
    if (!st) return;
    if (st.src) { try { st.src.close(); } catch (_) {} st.src = null; }
    if (st.timer) window.clearInterval(st.timer);
    trackers.delete(id);
  }
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) return;
    // On return to foreground, refresh the visible view once instead of
    // having polled in the background.
    const route = currentRoute().name;
    if (route === "dashboard") refreshDashboard().catch(() => {});
    else if (route === "jobs") refreshJobs().catch(() => {});
    else if (route === "projects") refreshProjects().catch(() => {});
  });

  async function fetchJob(id) {
    return api("/api/v1/jobs/" + encodeURIComponent(id));
  }

  /* -- routing -------------------------------------------------------------- */
  const VIEWS = ["dashboard", "scan", "search", "investigate", "projects", "jobs", "graph"];
  function currentRoute() {
    const h = window.location.hash || "#/dashboard";
    const parts = h.replace(/^#\//, "").split("/");
    return { name: VIEWS.includes(parts[0]) ? parts[0] : "dashboard", rest: parts.slice(1) };
  }
  function showRoute() {
    const { name } = currentRoute();
    for (const v of VIEWS) {
      const sec = $("view-" + v);
      if (sec) sec.hidden = v !== name;
    }
    $$(".sidebar a").forEach((a) => {
      if (a.dataset.nav === name) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    if (name === "dashboard") refreshDashboard().catch(() => {});
    if (name === "projects") refreshProjects().catch(() => {});
    if (name === "jobs") refreshJobs().catch(() => {});
  }
  window.addEventListener("hashchange", showRoute);

  /* -- topbar: health heartbeat (slow) + project names (on demand) -------- */
  /* Health: load at startup, slow heartbeat, refresh after reconnect.
     Projects: load at startup, refresh when Projects view becomes active,
     after project mutation, or after a persisted job completes. Never poll
     both every few seconds forever. */
  async function refreshHealth() {
    if (isHidden()) return;
    try {
      const h = await api("/api/v1/health");
      $("conn-dot").classList.add("on");
      $("conn-text").textContent = "connected · v" + h.api_version;
      $("status-left").textContent = "RXScan Web UI · engine ok · tool " + (h.tool_version || "");
    } catch (_) {
      $("conn-dot").classList.remove("on");
      $("conn-text").textContent = "backend unreachable";
      $("status-left").textContent = "RXScan Web UI · engine unreachable";
    }
  }
  async function refreshProjectNames() {
    if (isHidden()) return;
    try {
      const data = await api("/api/v1/projects?limit=50");
      const dl = $("project-names");
      clear(dl);
      for (const p of data.projects || []) {
        const o = document.createElement("option");
        o.value = p.name;
        dl.appendChild(o);
      }
    } catch (_) {}
  }
  async function refreshTopbar() {
    await refreshHealth();
    await refreshProjectNames();
  }

  function activeProject() {
    return $("active-project").value.trim() || "default";
  }
  $("project-pick-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = activeProject();
    for (const id of ["scan-project", "search-project", "inv-project"]) {
      const n = $(id);
      if (n) n.value = v;
    }
    refreshDashboard().catch(() => {});
  });

  /* -- dashboard -------------------------------------------------------------- */
  async function refreshDashboard() {
    if (isHidden()) return;
    const projName = $("dash-project-name");
    if (projName) projName.textContent = activeProject();
    try {
      const h = await api("/api/v1/health");
      $("dash-health").textContent = h.status;
      $("dash-api").textContent = String(h.api_version);
      $("dash-tool").textContent = h.tool_version || "—";
    } catch (_) {
      $("dash-health").textContent = "unreachable";
    }
    try {
      const caps = await api("/api/v1/capabilities");
      const list = caps.capabilities || [];
      const usable = list.filter((c) => c.state === "available" || c.state === "configured").length;
      $("dash-caps-summary").textContent = usable + " of " + list.length + " capabilities usable.";
      const ul = $("dash-caps");
      clear(ul);
      for (const c of list.slice(0, 12)) {
        const li = document.createElement("li");
        li.className = "cap state-" + c.state;
        const name = document.createElement("strong");
        name.textContent = c.name;
        li.append(name, document.createTextNode(" · " + c.state));
        li.title = c.detail || "";
        ul.appendChild(li);
      }
      const warn = $("dash-warnings");
      clear(warn);
      const unavailable = list.filter((c) => c.state === "unavailable");
      if (!unavailable.length) warn.appendChild(el("li", "No capability warnings."));
      else for (const c of unavailable.slice(0, 8)) warn.appendChild(el("li", c.name + ": " + (c.detail || "unavailable")));
    } catch (_) {
      $("dash-caps-summary").textContent = "Capabilities unavailable.";
    }
    try {
      const data = await api("/api/v1/jobs?limit=10");
      const jobs = data.jobs || [];
      const active = jobs.filter((j) => j.status === "running" || j.status === "queued");
      const au = $("dash-active");
      clear(au);
      $("dash-active-empty").hidden = active.length !== 0;
      for (const j of active.slice(0, 5)) {
        const li = document.createElement("li");
        const b = document.createElement("button");
        b.type = "button";
        b.textContent = j.kind + " " + j.id + " — " + statusLabel(j);
        b.addEventListener("click", () => { window.location.hash = "#/jobs"; selectJob(j.id).catch(() => {}); });
        li.appendChild(b);
        au.appendChild(li);
      }
      const rj = $("dash-jobs");
      clear(rj);
      $("dash-jobs-empty").hidden = jobs.length !== 0;
      for (const j of jobs.slice(0, 5)) {
        const li = document.createElement("li");
        li.textContent = j.kind + " · " + j.label + " · " + statusLabel(j);
        rj.appendChild(li);
      }
      const running = jobs.filter((j) => j.status === "running" || j.status === "queued").length;
      $("status-job").textContent = running ? running + " active job(s)" : "no active job";
    } catch (_) {}
    try {
      const data = await api("/api/v1/projects?limit=10");
      const ul = $("dash-projects");
      clear(ul);
      const projects = data.projects || [];
      $("dash-projects-empty").hidden = projects.length !== 0;
      for (const p of projects.slice(0, 8)) {
        const li = document.createElement("li");
        const b = document.createElement("button");
        b.type = "button";
        b.textContent = p.name;
        b.addEventListener("click", () => { window.location.hash = "#/projects"; selectProject(p.name).catch(() => {}); });
        li.appendChild(b);
        ul.appendChild(li);
      }
    } catch (_) {}
    try {
      const name = activeProject();
      const data = await api("/api/v1/projects/" + encodeURIComponent(name) + "/findings?limit=5");
      const ul = $("dash-findings");
      clear(ul);
      const findings = data.findings || [];
      $("dash-findings-empty").hidden = findings.length !== 0;
      if (!findings.length) ul.appendChild(el("li", "No findings in project " + name + "."));
      for (const f of findings) {
        ul.appendChild(el("li", f.kind + " · " + f.label + " · conf " + f.confidence + " · " + f.module));
      }
    } catch (_) {
      const ul = $("dash-findings");
      clear(ul);
      ul.appendChild(el("li", "Project " + activeProject() + " is empty or missing."));
    }
  }

  /* -- scan ------------------------------------------------------------------- */
  function scanBody() {
    const fd = new FormData($("scan-form"));
    const checkboxAll = $("scan-allports").checked;
    const portsRaw = String(fd.get("ports") || "").trim();
    // `all` (case-insensitive) in the ports field and the checkbox are the
    // SAME core option: never generate a 65k-element frontend array.
    const textAll = portsRaw.toLowerCase() === "all";
    const allPorts = checkboxAll || textAll;
    const scope = String(fd.get("scope") || "").split("\n").map((s) => s.trim()).filter(Boolean);
    const exclude = String(fd.get("exclude") || "").split("\n").map((s) => s.trim()).filter(Boolean);
    // Inline validation (no silent fallback to defaults): malformed port
    // expressions are rejected here with a useful message.
    if (!allPorts && portsRaw) {
      const ok = /^[\d\s,\-]+$/.test(portsRaw) && /[\d]/.test(portsRaw);
      if (!ok) {
        throw new Error("Ports must be like 22,80,443, 1-1024, or all.");
      }
    }
    return {
      target: String(fd.get("target") || "").trim(),
      ports: allPorts ? undefined : (portsRaw || undefined),
      all_ports: allPorts,
      mode: String(fd.get("mode") || "connect"),
      level: Number(fd.get("level") || 3),
      goal: String(fd.get("goal") || "recon"),
      speed: String(fd.get("speed") || "balanced"),
      udp: $("scan-udp").checked,
      os: $("scan-osfp").checked,
      deadline_seconds: Number(fd.get("deadline") || 60),
      project: String(fd.get("project") || "default").trim() || "default",
      scope,
      exclude,
    };
  }

  $("scan-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    formMsg($("scan-msg"), "Submitting scan…", false);
    let body;
    try { body = scanBody(); } catch (err) { formMsg($("scan-msg"), "Invalid form: " + err.message, false); return; }
    try {
      const job = await postJson("/api/v1/scans", body);
      formMsg($("scan-msg"), "Scan accepted as " + job.job_id + ".", true);
      startScanLive(job.job_id);
      refreshJobs().catch(() => {});
    } catch (err) {
      formMsg($("scan-msg"), "Scan rejected: " + err.message, false);
    }
  });
  $("scan-allports").addEventListener("change", () => {
    $("scan-ports").disabled = $("scan-allports").checked;
  });

  async function startScanLive(id) {
    $("scan-live-card").hidden = false;
    $("scan-results-card").hidden = true;
    const t0 = Date.now();
    const update = async () => {
      let job;
      try { job = await fetchJob(id); } catch (_) { return; }
      $("scan-live-id").textContent = job.id;
      $("scan-live-state").textContent = statusLabel(job);
      $("scan-live-stage").textContent = job.progress || "—";
      $("scan-live-elapsed").textContent = fmtDuration(Date.now() - t0);
      const bar = $("scan-live-bar");
      bar.className = "";
      if (job.status === "completed") bar.classList.add("done");
      if (job.status === "failed") bar.classList.add("failed");
      const ev = $("scan-live-events");
      clear(ev);
      for (const event of (job.events || []).slice(-12)) {
        const li = document.createElement("li");
        const t = document.createElement("strong");
        t.textContent = event.type;
        li.append(t, document.createTextNode(" — " + (event.message || "")));
        ev.appendChild(li);
      }
      if (job.status !== "running" && job.status !== "queued") {
        stopTracking(id);
        renderScanResult(job);
        refreshProjectNames().catch(() => {});
      }
    };
    trackJob(id, { onEvent: () => update().catch(() => {}) });
    await update();
  }
  $("scan-cancel").addEventListener("click", async () => {
    const id = $("scan-live-id").textContent;
    if (!id || id === "—") return;
    try {
      await postJson("/api/v1/jobs/" + encodeURIComponent(id) + "/cancel", {});
    } catch (_) {}
  });

  function renderScanResult(job) {
    const r = job.result;
    $("scan-results-card").hidden = false;
    renderPortSummary($("scan-viz-ports"), r && r.tcp);
    renderServiceDist($("scan-viz-services"), r && r.open_ports);
    const tbody = $("scan-table").querySelector("tbody");
    clear(tbody);
    const ports = (r && r.open_ports) || [];
    $("scan-empty").hidden = ports.length !== 0;
    if (!ports.length) $("scan-empty").textContent = "No open ports observed. Empty is honest — nothing fabricated.";
    for (const p of ports.slice(0, 100)) {
      const tr = document.createElement("tr");
      const parts = [];
      if (p.product) parts.push("product " + p.product);
      if (p.version) parts.push("version " + p.version);
      if (p.http_title) parts.push("title “" + p.http_title + "”");
      if (p.technologies && p.technologies.length) parts.push("tech " + p.technologies.slice(0, 3).join(", "));
      if (p.tls_name) parts.push("TLS " + p.tls_name);
      if (p.tls_issuer) parts.push("issuer " + p.tls_issuer);
      if (p.ssh_key) parts.push("ssh key " + String(p.ssh_key).slice(0, 24) + "…");
      if (p.endpoint) parts.push(p.endpoint);
      if (p.banner) parts.push("banner: " + String(p.banner).slice(0, 80));
      const details = parts.length ? parts.join(" · ") : "—";
      // OPEN PORT -> SERVICE -> EVIDENCE hierarchy. Unknown stays unknown.
      const portCell = el("td", String(p.port) + "/tcp");
      portCell.className = "port-open";
      const stateCell = el("td", "open");
      stateCell.className = "port-open";
      const svc = p.service || "unknown";
      const svcCell = el("td", svc);
      if (!p.service || svc === "unknown") svcCell.className = "svc-unknown";
      tr.append(portCell, stateCell, svcCell, el("td", details), el("td", "observed"));
      tbody.appendChild(tr);
    }
    // OS inference from the core (no JS scoring): best candidate or
    // explicit Unknown per host, with confidence and limitations.
    const osList = $("scan-os");
    clear(osList);
    const systems = (r && r.operating_systems) || [];
    $("scan-os-empty").hidden = systems.length !== 0;
    if (!systems.length) $("scan-os-empty").textContent = "No OS evidence observed. Empty is honest — nothing inferred.";
    for (const s of systems.slice(0, 100)) {
      const name = s.family === "Unknown" ? "Unknown" : (s.family + (s.generation ? " " + s.generation : ""));
      const bits = [name, (s.band || "unknown") + " " + (s.confidence || 0)];
      if (typeof s.coverage === "number") bits.push("coverage " + Math.round(s.coverage * 100) + "%");
      if (s.limitation) bits.push("limits: " + String(s.limitation).slice(0, 120));
      const li = document.createElement("li");
      const t = document.createElement("strong");
      t.textContent = String(s.host || "—");
      li.append(t, document.createTextNode(" — " + bits.join(" · ")));
      osList.appendChild(li);
    }
    $("scan-raw").textContent = r ? JSON.stringify({ job: job.id, status: job.status, result: r }, null, 2) : "No result yet.";
  }
  $("scan-download").addEventListener("click", () => {
    const blob = new Blob([$("scan-raw").textContent], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "rxscan-scan.json";
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  });

  /* -- search ------------------------------------------------------------------ */
  const PASSIVE_KINDS = ["email", "domain", "hostname", "ip", "asn", "url", "repository", "organization"];
  // SOURCES: category registry from the API (same as CLI `search categories`).
  // No hardcoded category list here: the core owns categories, the GUI renders them.
  let searchCategoryCache = [];
  async function loadSearchCategories() {
    const wrap = $("search-sources");
    const empty = $("search-sources-empty");
    if (!wrap) return;
    try {
      const data = await api("/api/v1/username-searches/categories");
      clear(wrap);
      const cats = data.categories || [];
      searchCategoryCache = cats;
      if (!cats.length) {
        if (empty) empty.textContent = "No categories in registry.";
        return;
      }
      if (empty) empty.hidden = true;
      for (const c of cats) {
        const label = document.createElement("label");
        label.className = "source-check";
        const box = document.createElement("input");
        box.type = "checkbox";
        box.value = c.category;
        box.checked = true;
        box.dataset.usable = String(c.usable ?? 0);
        box.dataset.vectors = String(c.vectors ?? c.configured ?? 0);
        box.addEventListener("change", updateSelectedVectorsLine);
        box.setAttribute("aria-label", (c.label || c.category) + " (" + (c.vectors ?? c.configured ?? 0) + " vectors)");
        const text = document.createElement("span");
        // e.g. "Social — 612 vectors" — values from the core, never hardcoded.
        text.textContent = (c.label || c.category) + "  " + (c.vectors ?? c.configured ?? 0) + " vectors";
        label.append(box, text);
        wrap.appendChild(label);
      }
      updateSelectedVectorsLine();
      fillProviderCategorySelect(cats);
    } catch (_) {
      if (empty) empty.textContent = "Categories unavailable (API unreachable).";
    }
  }
  function updateSelectedVectorsLine() {
    const node = $("search-sources-selected");
    if (!node) return;
    const wrap = $("search-sources");
    if (!wrap) return;
    const boxes = Array.from(wrap.querySelectorAll("input[type=checkbox]"));
    if (!boxes.length) { node.textContent = "— usable vectors selected"; return; }
    let usable = 0;
    let vectors = 0;
    for (const b of boxes) {
      if (!b.checked) continue;
      usable += Number(b.dataset.usable || 0);
      vectors += Number(b.dataset.vectors || 0);
    }
    node.textContent = usable.toLocaleString("en-US") + " usable vectors selected (" + vectors.toLocaleString("en-US") + " registered in scope)";
  }
  function fillProviderCategorySelect(cats) {
    const sel = $("search-prov-cat");
    if (!sel) return;
    const current = sel.value;
    clear(sel);
    const all = document.createElement("option");
    all.value = "";
    all.textContent = "All";
    sel.appendChild(all);
    for (const c of cats) {
      const o = document.createElement("option");
      o.value = c.category;
      o.textContent = (c.label || c.category) + " (" + (c.vectors ?? c.configured ?? 0) + ")";
      sel.appendChild(o);
    }
    sel.value = current;
  }
  // Bounded provider browser: one 50-row page at a time, selection kept in
  // a Set across pages. Never renders thousands of nodes on load.
  const provBrowser = { page: 0, limit: 50, total: 0, selected: new Set() };
  async function loadProviderPage() {
    const list = $("search-prov-list");
    const pageNote = $("search-prov-page");
    if (!list) return;
    const q = ($("search-prov-q") || {}).value || "";
    const cat = ($("search-prov-cat") || {}).value || "";
    const state = ($("search-prov-state") || {}).value || "";
    const params = new URLSearchParams({
      limit: String(provBrowser.limit),
      offset: String(provBrowser.page * provBrowser.limit),
    });
    if (q.trim()) params.set("q", q.trim());
    if (cat) params.set("category", cat);
    if (state) params.set("state", state);
    try {
      const data = await api("/api/v1/username-searches/providers?" + params.toString());
      clear(list);
      provBrowser.total = data.total ?? (data.providers || []).length;
      for (const p of data.providers || []) {
        const li = document.createElement("li");
        li.className = "prov-row";
        const box = document.createElement("input");
        box.type = "checkbox";
        box.checked = provBrowser.selected.has(p.id);
        box.setAttribute("aria-label", "Select provider " + p.id);
        box.addEventListener("change", () => {
          if (box.checked) provBrowser.selected.add(p.id);
          else provBrowser.selected.delete(p.id);
        });
        const name = document.createElement("strong");
        name.textContent = p.name || p.id;
        const meta = document.createElement("span");
        meta.className = "muted";
        meta.textContent = " " + (p.id || "") + " · " + (p.category_label || p.category || "") + " · " + (p.vectors ?? 1) + " vector" + ((p.vectors ?? 1) === 1 ? "" : "s") + " · " + (p.state || "");
        li.append(box, name, meta);
        list.appendChild(li);
      }
      if (!(data.providers || []).length) list.appendChild(el("li", "No providers match this filter."));
      if (pageNote) {
        const from = provBrowser.total ? provBrowser.page * provBrowser.limit + 1 : 0;
        const to = Math.min(provBrowser.total, (provBrowser.page + 1) * provBrowser.limit);
        pageNote.textContent = "Showing " + from + "–" + to + " of " + provBrowser.total + " · " + provBrowser.selected.size + " selected";
      }
    } catch (_) {
      clear(list);
      list.appendChild(el("li", "Provider list unavailable (API unreachable)."));
    }
  }
  function resetProviderPage() { provBrowser.page = 0; loadProviderPage().catch(() => {}); }
  function selectedSearchCategories() {
    const wrap = $("search-sources");
    if (!wrap) return [];
    const boxes = Array.from(wrap.querySelectorAll("input[type=checkbox]"));
    if (!boxes.length) return [];
    // Unchecked categories are excluded from the plan (same as CLI --category).
    // When all are checked, send no filter (same plan as CLI with no --category).
    const checked = boxes.filter((b) => b.checked).map((b) => b.value);
    if (checked.length === boxes.length) return [];
    return checked;
  }
  // Load categories when the Search view becomes visible + at startup.
  loadSearchCategories().catch(() => {});
  loadProviderPage().catch(() => {});
  let provDebounce = 0;
  const provFilterChanged = () => {
    window.clearTimeout(provDebounce);
    provDebounce = window.setTimeout(resetProviderPage, 250);
  };
  if ($("search-prov-q")) $("search-prov-q").addEventListener("input", provFilterChanged);
  if ($("search-prov-cat")) $("search-prov-cat").addEventListener("change", resetProviderPage);
  if ($("search-prov-state")) $("search-prov-state").addEventListener("change", resetProviderPage);
  if ($("search-prov-prev")) $("search-prov-prev").addEventListener("click", () => {
    if (provBrowser.page > 0) { provBrowser.page--; loadProviderPage().catch(() => {}); }
  });
  if ($("search-prov-next")) $("search-prov-next").addEventListener("click", () => {
    if ((provBrowser.page + 1) * provBrowser.limit < provBrowser.total) { provBrowser.page++; loadProviderPage().catch(() => {}); }
  });
  if ($("search-prov-clear")) $("search-prov-clear").addEventListener("click", () => {
    provBrowser.selected.clear();
    loadProviderPage().catch(() => {});
  });
  $("search-type").addEventListener("change", () => {
    const isUser = $("search-type").value === "username";
    const wrap = $("search-sources-wrap");
    if (wrap) wrap.hidden = !isUser;
    const prov = $("search-providers-wrap");
    if (prov) prov.hidden = !isUser;
  });
  if ($("search-sources-wrap")) $("search-sources-wrap").hidden = $("search-type").value !== "username";
  if ($("search-providers-wrap")) $("search-providers-wrap").hidden = $("search-type").value !== "username";

  $("search-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const kind = $("search-type").value;
    const value = $("search-value").value.trim();
    const project = $("search-project").value.trim() || "default";
    if (PASSIVE_KINDS.includes(kind)) {
      formMsg($("search-msg"), "Searching locally…", false);
      $("search-live-card").hidden = true;
      try {
        const data = await postJson("/api/v1/search", { entity_type: kind, value, project });
        formMsg($("search-msg"), "Local search complete: " + data.seed_canonical, true);
        renderPassiveSearch(data);
      } catch (err) {
        formMsg($("search-msg"), "Search rejected: " + err.message, false);
      }
    } else {
      formMsg($("search-msg"), "Submitting username search…", false);
      try {
        const deadline = Number($("search-deadline").value || 25);
        const categories = selectedSearchCategories();
        const body = { value, deadline_seconds: deadline, project };
        if (categories.length) body.categories = categories;
        // Explicit provider ticks narrow the plan like CLI --provider.
        if (provBrowser.selected.size) body.providers = Array.from(provBrowser.selected).sort();
        const job = await postJson("/api/v1/username-searches", body);
        formMsg($("search-msg"), "Username search accepted as " + job.job_id + ".", true);
        startUsernameLive(job.job_id);
      } catch (err) {
        formMsg($("search-msg"), "Search rejected: " + err.message, false);
      }
    }
  });

  function honestUrlLabel(item) {
    // Backend honesty: url_kind comes from the core (same as CLI).
    // Profile = observed identity-specific, Resource = API/resource,
    // Candidate = unconfirmed, Provider Endpoint = generic.
    const kind = String(item.url_kind || "");
    const url = item.url || item.final_url || item.profile_url || "";
    if (kind === "observed_profile") return "Profile: " + (url || "—");
    if (kind === "observed_resource") return "Resource: " + (url || "—");
    if (kind === "candidate") return "Candidate: " + (url || "—");
    if (!url) return "Provider Endpoint";
    if (item.url_observed) return "Profile: " + url;
    return "Candidate: " + url;
  }
  function searchStatusClass(status) {
    // Same semantics as the terminal: green=confirmed, amber=possible/
    // blocked/rate-limited, red=error, gray=negative/unavailable/unscanned,
    // cyan=urls/metadata.
    const s = String(status || "").toLowerCase();
    if (s === "confirmed") return "s-confirmed";
    if (s === "possible" || s === "probable" || s === "blocked" || s === "rate_limited") return "s-possible";
    if (s === "error") return "s-error";
    return "s-muted";
  }
  function renderPassiveSearch(data) {
    $("search-results-card").hidden = false;
    const tbody = $("search-table").querySelector("tbody");
    clear(tbody);
    const obs = data.observations || [];
    $("search-empty").hidden = obs.length !== 0;
    const otherBox = $("search-other-details");
    if (otherBox) otherBox.hidden = true;
    for (const o of obs.slice(0, 60)) {
      const tr = document.createElement("tr");
      tr.append(el("td", o.provider || "local"), el("td", o.status || "?"), el("td", String(o.confidence ?? "—")));
      const url = (o.attributes && (o.attributes.final_url || o.attributes.profile_url)) || "";
      // Passive canonicalization never verifies a remote profile.
      const label = url ? "Resource: " + url : "—";
      tr.append(el("td", label), el("td", (o.evidence || []).slice(0, 2).join(" · ") || "—"));
      tbody.appendChild(tr);
    }
    renderCoverage($("search-viz-coverage"), { entities: (data.entities || []).length, observations: obs.length, relationships: (data.relationships || []).length, network_scans: 0 });
    $("search-raw").textContent = JSON.stringify(data, null, 2);
  }

  async function startUsernameLive(id) {
    $("search-live-card").hidden = false;
    $("search-results-card").hidden = true;
    const update = async () => {
      let job;
      try { job = await fetchJob(id); } catch (_) { return; }
      $("search-live-id").textContent = job.id;
      $("search-live-state").textContent = statusLabel(job);
      $("search-live-stage").textContent = job.progress || "—";
      const ev = $("search-live-events");
      clear(ev);
      for (const event of (job.events || []).slice(-12)) {
        const li = document.createElement("li");
        const t = document.createElement("strong");
        t.textContent = event.type;
        li.append(t, document.createTextNode(" — " + (event.message || "")));
        ev.appendChild(li);
      }
      if (job.status !== "running" && job.status !== "queued") {
        stopTracking(id);
        renderUsernameResult(job);
        refreshProjectNames().catch(() => {});
      }
    };
    trackJob(id, { onEvent: () => update().catch(() => {}) });
    await update();
  }
  $("search-cancel").addEventListener("click", async () => {
    const id = $("search-live-id").textContent;
    if (!id || id === "—") return;
    try { await postJson("/api/v1/jobs/" + encodeURIComponent(id) + "/cancel", {}); } catch (_) {}
  });

  function renderUsernameResult(job) {
    const r = job.result;
    $("search-results-card").hidden = false;
    const tbody = $("search-table").querySelector("tbody");
    clear(tbody);
    const otherTbody = $("search-table-other") ? $("search-table-other").querySelector("tbody") : null;
    if (otherTbody) clear(otherTbody);
    const rows = (r && r.results_sample) || [];
    const rank = (s) => {
      const v = String(s || "").toLowerCase();
      if (v === "confirmed") return 0;
      if (v === "probable") return 1;
      if (v === "possible") return 2;
      return 3;
    };
    const sorted = rows.slice().sort((a, b) => rank(a.status) - rank(b.status));
    const top = sorted.filter((it) => rank(it.status) <= 2);
    const rest = sorted.filter((it) => rank(it.status) > 2);
    const shown = top.length ? top : [];
    $("search-empty").hidden = sorted.length !== 0;
    if (!sorted.length) $("search-empty").textContent = "No provider results. Unqueried stays unqueried.";
    // Bounded rendering note: at thousands of vectors only the first page of
    // findings renders; totals come from coverage denominators.
    const sampleNote = $("search-sample-note");
    if (sampleNote) {
      if (r && r.results_total != null && sorted.length) {
        sampleNote.textContent = "Showing " + shown.slice(0, 60).length + " of " + r.results_total + " results (" + (r.results_truncated ? "truncated sample — refine filters" : "complete sample") + ").";
        sampleNote.hidden = false;
      } else {
        sampleNote.hidden = true;
      }
    }
    for (const item of shown.slice(0, 60)) {
      const tr = document.createElement("tr");
      tr.className = searchStatusClass(item.status);
      const cat = item.category_label || item.category || "—";
      const meta = item.metadata ? Object.entries(item.metadata).slice(0, 3).map(([k, v]) => k + ": " + String(v).slice(0, 40)).join(" · ") : "";
      const prov = item.provenance ? (item.provenance.provider_id || "") + "@" + (item.provenance.provider_version || "") : "";
      const evidence = ((item.evidence || []).slice(0, 2).join(" · ") || "—") + (meta ? " · " + meta : "") + (prov ? " · " + prov : "");
      tr.append(
        el("td", item.provider || "?"),
        el("td", (item.category_label || item.category || "—")),
        el("td", item.status || "?"),
        el("td", String(item.confidence ?? "—")),
        el("td", honestUrlLabel(item)),
        el("td", evidence)
      );
      tbody.appendChild(tr);
    }
    const otherBox = $("search-other-details");
    if (otherBox && otherTbody) {
      if (!rest.length) {
        otherBox.hidden = true;
      } else {
        otherBox.hidden = false;
        otherBox.open = false;
        const summary = $("search-other-summary");
        if (summary) summary.textContent = "Other provider outcomes (" + rest.length + ": negative / blocked / unknown)";
        for (const item of rest.slice(0, 60)) {
          const tr = document.createElement("tr");
          tr.className = searchStatusClass(item.status);
          tr.append(
            el("td", item.provider || "?"),
            el("td", (item.category_label || item.category || "—")),
            el("td", item.status || "?"),
            el("td", String(item.confidence ?? "—")),
            el("td", honestUrlLabel(item)),
            el("td", (item.evidence || []).slice(0, 2).join(" · ") || "—")
          );
          otherTbody.appendChild(tr);
        }
      }
    }
    // Coverage with the same denominators as Core/CLI/JSONL: scheduled is
    // the effective plan for this run; configured/enabled/usable describe
    // the registry. Per-category rows stay bounded (20 max).
    const cov = r && r.coverage;
    if (cov && cov.by_category) {
      const box = $("search-viz-coverage");
      clear(box);
      const head = document.createElement("div");
      head.className = "bar-row";
      const parts = [];
      if (cov.scheduled != null) parts.push("scheduled " + cov.scheduled);
      if (cov.completed != null) parts.push("completed " + cov.completed);
      if (cov.remaining != null) parts.push("remaining " + cov.remaining);
      if (cov.configured != null) parts.push("registry " + cov.configured);
      head.appendChild(el("span", parts.join(" · ") || "coverage"));
      box.appendChild(head);
      for (const entry of cov.by_category.slice(0, 20)) {
        const row = document.createElement("div");
        row.className = "bar-row";
        row.appendChild(el("span", (entry.label || entry.category) + ": " + entry.complete + " complete"));
        box.appendChild(row);
      }
      if (cov.by_category.length > 20) {
        box.appendChild(el("span", "…and " + (cov.by_category.length - 20) + " more categories (see Raw / JSON)."));
      }
    } else {
      renderCoverage($("search-viz-coverage"), cov);
    }
    $("search-raw").textContent = r ? JSON.stringify({ job: job.id, status: job.status, result: r }, null, 2) : "No result yet.";
  }

  /* -- investigate --------------------------------------------------------------- */
  $("inv-network").addEventListener("change", () => {
    $("inv-scope-wrap").hidden = !$("inv-network").checked;
  });
  $$("[data-inv-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$("[data-inv-tab]").forEach((b) => b.setAttribute("aria-selected", b === btn ? "true" : "false"));
      $$("[data-inv-panel]").forEach((p) => { p.hidden = p.dataset.invPanel !== btn.dataset.invTab; });
    });
  });

  const invGraph = makeGraph($("inv-graph"), $("inv-legend"), $("inv-inspect"), $("inv-inspect-empty"));
  $("inv-graph-in").addEventListener("click", () => invGraph.zoom(1.25));
  $("inv-graph-out").addEventListener("click", () => invGraph.zoom(0.8));
  $("inv-graph-reset").addEventListener("click", () => invGraph.reset());
  $("inv-graph-kind").addEventListener("change", () => invGraph.setKindFilter($("inv-graph-kind").value));

  $("inv-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData($("inv-form"));
    const network = $("inv-network").checked;
    const scope = String(fd.get("scope") || "").split("\n").map((s) => s.trim()).filter(Boolean);
    const exclude = String(fd.get("exclude") || "").split("\n").map((s) => s.trim()).filter(Boolean);
    if (network && !scope.length) {
      formMsg($("inv-msg"), "Network bridge requires explicit scope.", false);
      return;
    }
    const body = {
      entity_type: String(fd.get("entity_type") || "domain"),
      value: String(fd.get("value") || "").trim(),
      depth: Number(fd.get("depth") ?? 2),
      deadline_seconds: Number(fd.get("deadline") || 60),
      project: String(fd.get("project") || "default").trim() || "default",
      network,
      scope,
      exclude,
    };
    formMsg($("inv-msg"), "Submitting investigation…", false);
    try {
      const job = await postJson("/api/v1/investigations", body);
      formMsg($("inv-msg"), "Investigation accepted as " + job.job_id + ".", true);
      startInvLive(job.job_id, body.project);
    } catch (err) {
      formMsg($("inv-msg"), "Investigation rejected: " + err.message, false);
    }
  });

  async function startInvLive(id, project) {
    $("inv-live-card").hidden = false;
    $("inv-results-card").hidden = true;
    const t0 = Date.now();
    const update = async () => {
      let job;
      try { job = await fetchJob(id); } catch (_) { return; }
      $("inv-live-id").textContent = job.id;
      $("inv-live-state").textContent = statusLabel(job);
      $("inv-live-stage").textContent = job.progress || "—";
      $("inv-live-elapsed").textContent = fmtDuration(Date.now() - t0);
      const bar = $("inv-live-bar");
      bar.className = "";
      if (job.status === "completed") bar.classList.add("done");
      if (job.status === "failed") bar.classList.add("failed");
      const ev = $("inv-live-events");
      clear(ev);
      for (const event of (job.events || []).slice(-12)) {
        const li = document.createElement("li");
        const t = document.createElement("strong");
        t.textContent = event.type;
        li.append(t, document.createTextNode(" — " + (event.message || "")));
        ev.appendChild(li);
      }
      if (job.status !== "running" && job.status !== "queued") {
        stopTracking(id);
        await renderInvResult(job, project).catch(() => {
          $("inv-raw").textContent = JSON.stringify(job, null, 2);
          $("inv-results-card").hidden = false;
        });
        refreshProjectNames().catch(() => {});
      }
    };
    trackJob(id, { onEvent: () => update().catch(() => {}) });
    await update();
  }
  $("inv-cancel").addEventListener("click", async () => {
    const id = $("inv-live-id").textContent;
    if (!id || id === "—") return;
    try { await postJson("/api/v1/jobs/" + encodeURIComponent(id) + "/cancel", {}); } catch (_) {}
  });

  async function renderInvResult(job, project) {
    const r = job.result || {};
    $("inv-results-card").hidden = false;
    const chip = $("inv-seed-chip");
    const chipVal = $("inv-seed-value");
    if (chip && chipVal && (r.seed_kind || r.seed_value)) {
      chip.hidden = false;
      chipVal.textContent = String(r.seed_kind || "") + " " + String(r.seed_value || "");
    } else if (chip) {
      chip.hidden = true;
    }
    const ov = $("inv-overview");
    clear(ov);
    const rows = [
      ["seed", (r.seed_kind || "") + " " + (r.seed_value || "")],
      ["entities", r.entities ?? "—"],
      ["relationships", r.relationships ?? "—"],
      ["observations", r.observations ?? "—"],
      ["depth", (r.depth ?? "—") + " / " + (r.max_depth ?? "—")],
      ["network scans", (r.network_scans || []).length ? JSON.stringify(r.network_scans) : "0 (passive)"],
    ];
    for (const [k, v] of rows) {
      const div = document.createElement("div");
      const dt = document.createElement("dt"); dt.textContent = k;
      const dd = document.createElement("dd"); dd.textContent = String(v);
      div.append(dt, dd);
      ov.appendChild(div);
    }
    renderCoverage($("inv-viz-coverage"), { entities: r.entities || 0, relationships: r.relationships || 0, observations: r.observations || 0 });
    const etbody = $("inv-entities-table").querySelector("tbody");
    clear(etbody);
    for (const ent of (r.entities_sample || []).slice(0, 60)) {
      const tr = document.createElement("tr");
      tr.append(el("td", ent.kind || "?"), el("td", ent.label || ent.id || "?"), el("td", String(ent.depth ?? "—")), el("td", String(ent.observations ?? "—")));
      etbody.appendChild(tr);
    }
    const evList = $("inv-evidence");
    clear(evList);
    const sample = r.entities_sample || [];
    if (!sample.length) evList.appendChild(el("li", "No evidence yet."));
    for (const ent of sample.slice(0, 30)) {
      evList.appendChild(el("li", (ent.kind || "?") + " · " + (ent.label || ent.id) + " · " + (ent.observations || 0) + " observation(s)"));
    }
    const src = $("inv-sources");
    clear(src);
    const corrs = r.correlations || [];
    if (!corrs.length) src.appendChild(el("li", "No correlated sources."));
    for (const c of corrs.slice(0, 20)) {
      src.appendChild(el("li", (c.entity || "?") + " ← " + (c.sources || []).slice(0, 5).join(", ")));
    }
    // Pivots are Rust-computed evidence leads; JavaScript only renders them.
    const pivBox = $("inv-pivots");
    if (pivBox) {
      clear(pivBox);
      const pivots = r.pivots || [];
      if (!pivots.length) pivBox.appendChild(el("li", "No suggested pivots."));
      for (const p of pivots.slice(0, 32)) {
        pivBox.appendChild(el("li",
          (p.target_kind || "?") + " " + (p.target_value || "?") +
          " — " + (p.reason || "?") +
          " [" + (p.source || "?") + "; " + (p.state || "?") + "]" +
          " {" + (p.action || "investigate") + "}"));
      }
    }
    $("inv-raw").textContent = JSON.stringify({ job: job.id, status: job.status, result: r }, null, 2);
    // Graph + timeline come from the persisted project (same store as CLI).
    try {
      const name = project || job.project || activeProject();
      const entities = await api("/api/v1/projects/" + encodeURIComponent(name) + "/entities?limit=100");
      const list = entities.entities || [];
      const seed = list.length ? list[0].entity_id : "";
      if (seed) {
        const graph = await api("/api/v1/projects/" + encodeURIComponent(name) + "/graph?seed=" + encodeURIComponent(seed) + "&depth=2&limit=100");
        invGraph.setData(graph.nodes || [], graph.edges || []);
        const sel = $("inv-graph-kind");
        clear(sel);
        sel.appendChild(el("option", "all kinds"));
        sel.lastChild.value = "";
        for (const k of invGraph.kinds()) {
          const o = document.createElement("option");
          o.value = k; o.textContent = k;
          sel.appendChild(o);
        }
      } else {
        invGraph.setData([], []);
      }
      const tl = await api("/api/v1/projects/" + encodeURIComponent(name) + "/timeline?limit=60");
      renderTimeline($("inv-timeline"), tl.events || []);
    } catch (_) {
      invGraph.setData([], []);
      renderTimeline($("inv-timeline"), []);
    }
  }

  /* -- projects ------------------------------------------------------------------- */
  $$("[data-proj-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$("[data-proj-tab]").forEach((b) => b.setAttribute("aria-selected", b === btn ? "true" : "false"));
      $$("[data-proj-panel]").forEach((p) => { p.hidden = p.dataset.projPanel !== btn.dataset.projTab; });
    });
  });
  const projGraph = makeGraph($("p-graph"), $("p-legend"), $("p-inspect"), $("p-inspect-empty"));
  let selectedProject = "";
  let timelineOffset = 0;

  async function refreshProjects() {
    if (isHidden() && currentRoute().name !== "projects") return;
    try {
      const data = await api("/api/v1/projects?limit=50");
      const ul = $("projects-list");
      clear(ul);
      const projects = data.projects || [];
      $("projects-empty").hidden = projects.length !== 0;
      if (!projects.length) ul.appendChild(el("li", "No projects yet. Create one above."));
      for (const p of projects) {
        const li = document.createElement("li");
        const b = document.createElement("button");
        b.type = "button";
        b.textContent = p.name;
        b.addEventListener("click", () => selectProject(p.name).catch(() => {}));
        li.appendChild(b);
        ul.appendChild(li);
      }
    } catch (_) {}
  }
  $("projects-refresh").addEventListener("click", () => refreshProjects().catch(() => {}));
  $("project-create-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = $("project-create-name").value.trim();
    if (!name) { formMsg($("project-create-msg"), "Name is required.", false); return; }
    try {
      await postJson("/api/v1/projects", { name });
      formMsg($("project-create-msg"), "Project " + name + " created.", true);
      $("project-create-name").value = "";
      await refreshProjects();
      await refreshProjectNames();
    } catch (err) {
      formMsg($("project-create-msg"), "Create failed: " + err.message, false);
    }
  });

  async function selectProject(name) {
    selectedProject = name;
    timelineOffset = 0;
    $("pdetail-empty").hidden = true;
    $("pdetail-body").hidden = false;
    const summary = await api("/api/v1/projects/" + encodeURIComponent(name));
    const dl = $("pdetail-summary");
    clear(dl);
    const rows = [
      ["name", summary.name], ["runs", summary.runs], ["entities", summary.entities],
      ["observations", summary.observations], ["relationships", summary.relationships],
      ["latest run", summary.latest_run || "—"],
    ];
    for (const [k, v] of rows) {
      const div = document.createElement("div");
      const dt = document.createElement("dt"); dt.textContent = k;
      const dd = document.createElement("dd"); dd.textContent = String(v);
      div.append(dt, dd);
      dl.appendChild(div);
    }
    projRuns = summary.run_ids || [];
    refreshDiffRuns();
    const entities = await api("/api/v1/projects/" + encodeURIComponent(name) + "/entities?limit=30");
    const eu = $("p-entities");
    clear(eu);
    for (const ent of entities.entities || []) {
      const li = document.createElement("li");
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = ent.kind + " · " + ent.label + " (seen " + ent.observation_count + "×)";
      b.addEventListener("click", () => {
        $("project-seed").value = ent.entity_id;
        loadProjectGraph().catch(() => {});
      });
      li.appendChild(b);
      eu.appendChild(li);
    }
    if (!(entities.entities || []).length) eu.appendChild(el("li", "No entities yet."));
    const findings = await api("/api/v1/projects/" + encodeURIComponent(name) + "/findings?limit=20");
    const fu = $("p-findings");
    clear(fu);
    for (const f of findings.findings || []) {
      fu.appendChild(el("li", f.kind + " · " + f.label + " · conf " + f.confidence + " · " + f.module + " · " + (f.evidence_excerpt || "no excerpt")));
    }
    if (!(findings.findings || []).length) fu.appendChild(el("li", "No findings yet."));
    clear($("p-timeline"));
    timelineOffset = 0;
    await loadProjectTimeline();
    const jobs = await api("/api/v1/jobs?limit=50");
    const ju = $("p-jobs");
    clear(ju);
    const mine = (jobs.jobs || []).filter((j) => j.project === name);
    if (!mine.length) ju.appendChild(el("li", "No jobs for this project yet."));
    for (const j of mine.slice(0, 10)) {
      const li = document.createElement("li");
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = j.kind + " " + j.id + " — " + statusLabel(j);
      b.addEventListener("click", () => { window.location.hash = "#/jobs"; selectJob(j.id).catch(() => {}); });
      li.appendChild(b);
      ju.appendChild(li);
    }
    projGraph.setData([], []);
    clear($("p-edges"));
  }

  async function loadProjectGraph() {
    const seed = $("project-seed").value.trim();
    if (!seed || !selectedProject) return;
    const graph = await api("/api/v1/projects/" + encodeURIComponent(selectedProject) + "/graph?seed=" + encodeURIComponent(seed) + "&depth=2&limit=100");
    projGraph.setData(graph.nodes || [], graph.edges || []);
    const eu = $("p-edges");
    clear(eu);
    for (const edge of (graph.edges || []).slice(0, 40)) {
      eu.appendChild(el("li", edge.relation + " (conf " + edge.confidence + ") · " + edge.module));
    }
    if (!(graph.edges || []).length) eu.appendChild(el("li", "Graph is empty for this seed."));
  }
  $("project-graph-load").addEventListener("click", () => loadProjectGraph().catch(() => {}));

  async function loadProjectTimeline() {
    if (!selectedProject) return;
    const data = await api("/api/v1/projects/" + encodeURIComponent(selectedProject) + "/timeline?limit=30&offset=" + timelineOffset);
    const events = data.events || [];
    const list = $("p-timeline");
    if (timelineOffset === 0) clear(list);
    const tmp = document.createElement("ol");
    renderTimeline(tmp, events);
    while (tmp.firstChild) list.appendChild(tmp.firstChild);
    timelineOffset += events.length;
  }
  $("project-timeline-more").addEventListener("click", () => loadProjectTimeline().catch(() => {}));

  /* -- run-to-run diff timeline: slider moves between runs ----------------- */
  /* Statuses come from the server (coverage-gated): added = green,
     removed = red (confirmed only), changed = amber, not covered = gray.
     Gray is never red; every state also shows a text label. */
  let projRuns = [];
  function refreshDiffRuns() {
    for (const id of ["p-diff-old", "p-diff-new"]) {
      const sel = $(id);
      clear(sel);
      for (const run of projRuns) {
        const o = document.createElement("option");
        o.value = run;
        o.textContent = run;
        sel.appendChild(o);
      }
    }
    const slider = $("p-diff-slider");
    slider.max = Math.max(0, projRuns.length - 1);
    slider.value = Math.max(0, projRuns.length - 1);
    if (projRuns.length >= 2) {
      $("p-diff-old").value = projRuns[projRuns.length - 2];
      $("p-diff-new").value = projRuns[projRuns.length - 1];
      $("p-diff-summary").textContent = projRuns.length + " runs. Move the slider, then Compare runs.";
    } else {
      $("p-diff-summary").textContent = projRuns.length < 1 ? "No runs yet." : "One run: import another scan to compare.";
    }
    clear($("p-diff-list"));
    projGraph.clearStatusColors();
  }
  $("p-diff-slider").addEventListener("input", () => {
    const idx = Number($("p-diff-slider").value || 0);
    if (projRuns[idx] !== undefined) $("p-diff-new").value = projRuns[idx];
    if ($("p-diff-new").value === $("p-diff-old").value && idx > 0) {
      $("p-diff-old").value = projRuns[idx - 1];
    }
  });
  $("p-diff-apply").addEventListener("click", async () => {
    const old = $("p-diff-old").value, cur = $("p-diff-new").value;
    if (!selectedProject || !old || !cur) { $("p-diff-summary").textContent = "Pick two runs to compare."; return; }
    if (old === cur) { $("p-diff-summary").textContent = "Baseline and current must differ."; return; }
    $("p-diff-summary").textContent = "Comparing " + old + " → " + cur + "…";
    try {
      const diff = await api("/api/v1/projects/" + encodeURIComponent(selectedProject) + "/diff?old=" + encodeURIComponent(old) + "&new=" + encodeURIComponent(cur) + "&limit=500");
      const s = diff.summary || {};
      $("p-diff-summary").textContent =
        "added " + (s.added || 0) + " · removed " + (s.removed || 0) + " (confirmed only)" +
        " · changed " + (s.changed || 0) + " · not covered " + (s.not_covered || 0) +
        " · unchanged " + (s.unchanged || 0) + (diff.truncated ? " · truncated" : "") +
        ". Highlight applied to the Graph tab.";
      const list = $("p-diff-list");
      clear(list);
      const overlay = {};
      for (const row of (diff.rows || []).slice(0, 200)) {
        overlay[row.entity_id] = row.status;
        const li = document.createElement("li");
        li.textContent = row.status.replace("_", " ") + " · " + row.kind + " · " + row.label + " — " + row.detail;
        list.appendChild(li);
      }
      if (!(diff.rows || []).length) list.appendChild(el("li", "No differences between these runs."));
      projGraph.setStatusColors(overlay);
    } catch (err) {
      $("p-diff-summary").textContent = "Compare failed: " + err.message;
    }
  });
  $("p-diff-clear").addEventListener("click", () => {
    clear($("p-diff-list"));
    projGraph.clearStatusColors();
    $("p-diff-summary").textContent = "Highlight cleared.";
  });

  /* -- jobs: SSE primary, slow fallback list refresh -------------------------- */
  let jobsAuto = null;
  const JOBS_FALLBACK_MS = 15000;
  async function refreshJobs() {
    if (isHidden()) return;
    try {
      const data = await api("/api/v1/jobs?limit=50");
      const jobs = data.jobs || [];
      const tbody = $("jobs-table").querySelector("tbody");
      clear(tbody);
      $("jobs-empty").hidden = jobs.length !== 0;
      for (const j of jobs) {
        const tr = document.createElement("tr");
        tr.className = "status-" + String(j.status || "unknown").replace(/[^a-z_]/g, "");
        tr.append(el("td", j.kind || "?"), el("td", j.label || "?"), el("td", statusLabel(j)), el("td", fmtTime(j.started_ms || j.created_ms)), el("td", jobDuration(j)), el("td", j.project || "—"));
        const act = document.createElement("td");
        const view = document.createElement("button");
        view.type = "button";
        view.textContent = "Inspect";
        view.setAttribute("aria-label", "Inspect job " + j.id);
        view.addEventListener("click", () => selectJob(j.id).catch(() => {}));
        act.appendChild(view);
        if (j.status === "running" || j.status === "queued") {
          const cancel = document.createElement("button");
          cancel.type = "button";
          cancel.textContent = "Cancel";
          cancel.setAttribute("aria-label", "Cancel job " + j.id);
          cancel.addEventListener("click", async () => {
            try { await postJson("/api/v1/jobs/" + encodeURIComponent(j.id) + "/cancel", {}); await refreshJobs(); } catch (_) {}
          });
          act.appendChild(cancel);
        }
        tr.appendChild(act);
        tbody.appendChild(tr);
      }
    } catch (_) {}
  }
  $("jobs-refresh").addEventListener("click", () => refreshJobs().catch(() => {}));
  $("jobs-auto").addEventListener("change", () => {
    if ($("jobs-auto").checked && !jobsAuto) jobsAuto = window.setInterval(() => { if (!isHidden()) refreshJobs().catch(() => {}); }, JOBS_FALLBACK_MS);
    else if (!$("jobs-auto").checked && jobsAuto) { window.clearInterval(jobsAuto); jobsAuto = null; }
  });

  async function selectJob(id) {
    $("job-detail-card").hidden = false;
    trackJob(id, { onEvent: () => loadJobDetail(id).catch(() => {}) });
    await loadJobDetail(id);
  }
  async function loadJobDetail(id) {
    let job;
    try { job = await fetchJob(id); } catch (_) { return; }
    $("d-id").textContent = job.id;
    $("d-kind").textContent = job.kind;
    $("d-status").textContent = statusLabel(job);
    $("d-progress").textContent = job.progress || "—";
    $("d-project").textContent = job.project || "—";
    const ev = $("d-events");
    clear(ev);
    for (const event of job.events || []) {
      const li = document.createElement("li");
      const t = document.createElement("strong");
      t.textContent = event.type;
      li.append(t, document.createTextNode(" — " + (event.message || "")));
      ev.appendChild(li);
    }
    $("d-result").textContent = job.result ? JSON.stringify(job.result, null, 2) : (job.error ? JSON.stringify(job.error, null, 2) : "No result yet.");
    if (job.status !== "running" && job.status !== "queued") stopTracking(id);
  }
  $("detail-cancel").addEventListener("click", async () => {
    const id = $("d-id").textContent;
    if (!id || id === "—") return;
    try { await postJson("/api/v1/jobs/" + encodeURIComponent(id) + "/cancel", {}); await loadJobDetail(id); await refreshJobs(); } catch (_) {}
  });
  $("detail-refresh").addEventListener("click", async () => {
    const id = $("d-id").textContent;
    if (id && id !== "—") await loadJobDetail(id);
  });
  $("detail-open").addEventListener("click", async () => {
    const kind = $("d-kind").textContent;
    if (kind === "scan") window.location.hash = "#/scan";
    else if (kind === "investigation") window.location.hash = "#/investigate";
    else if (kind === "username_search") window.location.hash = "#/search";
    else window.location.hash = "#/jobs";
  });

  /* -- Graph view: Maltego-style link analysis over stored evidence --- */
  /* Reads only the project graph endpoints (stored data, never network
     expansion). Rust decides entities, links, confidence, and masking;
     this file lays out and renders. Solid = observed, dashed = inferred,
     width = confidence; shape + label always repeat what color shows. */
  const GV_COLORS = {
    network: "#078cff", ip: "#00efff", host: "#3ddc84", port_service: "#f0a04b",
    software: "#b07cc4", certificate: "#e5488f", domain: "#19f4ff", url: "#8fa9c2",
    username: "#e2e8f0", account: "#f4f8ff", exposure: "#f06666", evidence: "#6b7d94",
    scope: "#4a9eff", cluster: "#2a4a6b",
  };
  const GV_SHAPES = {
    network: "hexagon", ip: "circle", host: "square", port_service: "diamond",
    software: "triangle", certificate: "pentagon", domain: "ellipse", url: "rounded_rect",
    username: "ring", account: "double_square", exposure: "triangle_down", evidence: "parallelogram",
    scope: "dashed_circle", cluster: "octagon",
  };
  const GV_KINDS = Object.keys(GV_COLORS).filter((k) => k !== "cluster");
  const GV_RENDER_NODES = 1500;
  const GV_RENDER_EDGES = 3000;

  /* Icon ramp colors (manifest ramps). Used to tint icon glyphs by category;
     light/dark tile variants fall back to these ramp colors. */
  const RAMP_COLOR = {
    amber: "#f59e0b", blue: "#078cff", coral: "#f97316", gray: "#6b7d94",
    green: "#3ddc84", pink: "#e879f9", purple: "#8b5cf6", red: "#f06666",
    teal: "#14b8a6",
  };
  /* Sprite `<use>` targets: inlined once from /app/assets/icons/glyphs/
     rxscan-sprite.svg, cached in the graph <defs>. */
  let spriteReady = false;

  const gv = {
    nodes: [], edges: [], byId: new Map(),
    positions: new Map(), hidden: new Set(), pinned: new Set(),
    collapsed: new Map(), selection: new Set(), layout: "organic",
    undo: [], redo: [], collections: new Map(), groupSeq: 0,
    clusterMembers: new Map(), loaded: false,
  };
  const GVNS = "http://www.w3.org/2000/svg";
  const gvReducedMotion = () =>
    window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function gvStatus(text) {
    $("graph-status").textContent = text;
  }
  function gvKindOf(n) {
    return n.display_kind || n.kind || "unknown";
  }
  function gvColor(kind) {
    return GV_COLORS[kind] || GV_COLORS.network;
  }
  function gvShape(kind) {
    return GV_SHAPES[kind] || "hexagon";
  }

  function gvSnapshot() {
    gv.undo.push(JSON.stringify({
      hidden: Array.from(gv.hidden), pinned: Array.from(gv.pinned),
      collapsed: Array.from(gv.collapsed.entries()), positions: Array.from(gv.positions.entries()),
      selection: Array.from(gv.selection), layout: gv.layout,
    }));
    if (gv.undo.length > 50) gv.undo.shift();
    gv.redo.length = 0;
  }
  function gvRestore(json) {
    const s = JSON.parse(json);
    gv.hidden = new Set(s.hidden); gv.pinned = new Set(s.pinned);
    gv.collapsed = new Map(s.collapsed); gv.positions = new Map(s.positions);
    gv.selection = new Set(s.selection); gv.layout = s.layout;
    $("graph-layout").value = s.layout;
    gvRender();
  }
  $("graph-undo").addEventListener("click", () => {
    const cur = gv.undo.pop();
    if (cur === undefined) { gvStatus("Nothing to undo."); return; }
    gv.redo.push(JSON.stringify({
      hidden: Array.from(gv.hidden), pinned: Array.from(gv.pinned),
      collapsed: Array.from(gv.collapsed.entries()), positions: Array.from(gv.positions.entries()),
      selection: Array.from(gv.selection), layout: gv.layout,
    }));
    gvRestore(cur);
    gvStatus("Undone.");
  });
  $("graph-redo").addEventListener("click", () => {
    const cur = gv.redo.pop();
    if (cur === undefined) { gvStatus("Nothing to redo."); return; }
    gv.undo.push(JSON.stringify({
      hidden: Array.from(gv.hidden), pinned: Array.from(gv.pinned),
      collapsed: Array.from(gv.collapsed.entries()), positions: Array.from(gv.positions.entries()),
      selection: Array.from(gv.selection), layout: gv.layout,
    }));
    gvRestore(cur);
    gvStatus("Redone.");
  });

  /* -- deterministic layouts (same math as the Rust exporters) ----------- */
  function gvHash(text) {
    let h = 0xcbf29ce484222325;
    const s = String(text);
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 0x100000001b3) >>> 0 || (h * 0x100000001b3) % 4294967296;
    }
    return h >>> 0;
  }
  function gvAdjacency(ids, edges) {
    const adj = new Map(ids.map((id) => [id, []]));
    for (const e of edges) {
      if (adj.has(e.from)) adj.get(e.from).push(e.to);
      if (adj.has(e.to)) adj.get(e.to).push(e.from);
    }
    for (const list of adj.values()) list.sort();
    return adj;
  }
  function gvBfsLayers(ids, edges, root) {
    const adj = gvAdjacency(ids, edges);
    const seen = new Set([root]);
    const layers = [];
    let frontier = [root];
    while (frontier.length) {
      frontier.sort();
      layers.push(frontier.slice());
      const next = [];
      for (const cur of frontier) {
        for (const nb of adj.get(cur) || []) {
          if (!seen.has(nb)) { seen.add(nb); next.push(nb); }
        }
      }
      frontier = next;
      if (layers.length > ids.length + 1) break;
    }
    const rest = ids.filter((id) => !seen.has(id)).sort();
    if (rest.length) {
      if (layers.length) layers[layers.length - 1] = layers[layers.length - 1].concat(rest).sort();
      else layers.push(rest);
    }
    return layers;
  }
  function gvRoot(ids, edges, seed) {
    if (seed && ids.includes(seed)) return seed;
    const adj = gvAdjacency(ids, edges);
    let best = ids[0];
    let bestDeg = -1;
    for (const id of ids) {
      const deg = (adj.get(id) || []).length;
      if (deg > bestDeg || (deg === bestDeg && id < best)) { best = id; bestDeg = deg; }
    }
    return best;
  }
  function gvComputeLayout(ids, edges, kind, seed) {
    const pos = new Map();
    const W = 1000, H = 700;
    if (!ids.length) return pos;
    const sorted = ids.slice().sort();
    if (kind === "circular") {
      sorted.forEach((id, i) => {
        const a = (2 * Math.PI * i) / sorted.length;
        pos.set(id, [500 + 420 * Math.cos(a), 350 + 280 * Math.sin(a)]);
      });
      return pos;
    }
    if (kind === "block") {
      const byKind = new Map();
      for (const id of sorted) {
        const n = gv.byId.get(id);
        const k = n ? gvKindOf(n) : "unknown";
        if (!byKind.has(k)) byKind.set(k, []);
        byKind.get(k).push(id);
      }
      const blocks = Math.max(1, byKind.size);
      const cols = Math.ceil(Math.sqrt(blocks));
      const bw = W / cols, bh = H / Math.max(1, cols);
      let bi = 0;
      for (const list of byKind.values()) {
        const inner = Math.max(1, Math.ceil(Math.sqrt(list.length)));
        list.forEach((id, i) => {
          pos.set(id, [
            (bi % cols) * bw + ((i % inner) + 1) * bw / (inner + 1),
            Math.floor(bi / cols) * bh + (Math.floor(i / inner) + 1) * bh / (inner + 1),
          ]);
        });
        bi++;
      }
      return pos;
    }
    if (kind === "hierarchical" || kind === "radial") {
      const root = gvRoot(sorted, edges, kind === "radial" ? seed : null);
      const layers = gvBfsLayers(sorted, edges, root);
      if (kind === "hierarchical") {
        layers.forEach((layer, li) => {
          layer.forEach((id, i) => {
            pos.set(id, [(li + 1) * W / (layers.length + 1), (i + 1) * H / (layer.length + 1)]);
          });
        });
      } else {
        pos.set(root, [500, 350]);
        const rings = Math.max(1, layers.length - 1);
        layers.slice(1).forEach((layer, li) => {
          const r = 460 * (0.46 * W / 1000 + 0.54) * (li + 1) / rings;
          layer.forEach((id, i) => {
            const a = (2 * Math.PI * i) / Math.max(1, layer.length);
            pos.set(id, [500 + r * Math.cos(a), 350 + r * 0.7 * Math.sin(a)]);
          });
        });
      }
      return pos;
    }
    // Organic: deterministic start + bounded sampled-repulsion passes.
    const cx = 500, cy = 350, radius = 266;
    sorted.forEach((id, i) => {
      const a = (2 * Math.PI * i) / sorted.length;
      const j = (gvHash(id) % 1000) / 1000 - 0.5;
      pos.set(id, [cx + radius * Math.cos(a + j * 0.2), cy + radius * Math.sin(a + j * 0.2)]);
    });
    if (sorted.length < 2) return pos;
    if (gvReducedMotion()) return pos;
    const index = new Map(sorted.map((id, i) => [id, i]));
    const P = sorted.map((id) => pos.get(id).slice());
    const iters = Math.min(100, Math.max(6, Math.floor(600000 / sorted.length)));
    const SAMPLE = 48;
    const stride = Math.max(1, Math.floor(sorted.length / SAMPLE));
    const ideal = Math.sqrt((W * H) / sorted.length);
    let temp = W / 10;
    const cool = temp / iters;
    const el = [];
    for (const e of edges) {
      const a = index.get(e.from), b = index.get(e.to);
      if (a !== undefined && b !== undefined && a !== b) el.push([a, b]);
    }
    for (let it = 0; it < iters; it++) {
      const D = P.map(() => [0, 0]);
      for (let i = 0; i < P.length; i++) {
        let j = (i * 2654435761) % P.length;
        for (let s = 0; s < Math.min(SAMPLE, P.length - 1); s++) {
          j = (j + stride) % P.length;
          if (j === i) continue;
          const dx = P[i][0] - P[j][0], dy = P[i][1] - P[j][1];
          const d = Math.max(0.01, Math.hypot(dx, dy));
          const f = (ideal * ideal) / d / d;
          D[i][0] += dx * f; D[i][1] += dy * f;
        }
      }
      for (const [a, b] of el) {
        const dx = P[a][0] - P[b][0], dy = P[a][1] - P[b][1];
        const d = Math.max(0.01, Math.hypot(dx, dy));
        const f = (d * d) / ideal / d;
        D[a][0] -= dx * f; D[a][1] -= dy * f;
        D[b][0] += dx * f; D[b][1] += dy * f;
      }
      for (let i = 0; i < P.length; i++) {
        const id = sorted[i];
        if (gv.pinned.has(id)) continue;
        const len = Math.max(0.01, Math.hypot(D[i][0], D[i][1]));
        const c = Math.min(temp, len) / len;
        P[i][0] = Math.min(980, Math.max(20, P[i][0] + D[i][0] * c));
        P[i][1] = Math.min(680, Math.max(20, P[i][1] + D[i][1] * c));
      }
      temp = Math.max(0.5, temp - cool);
    }
    sorted.forEach((id, i) => {
      if (!gv.pinned.has(id) || !pos.has(id)) pos.set(id, P[i]);
    });
    return pos;
  }

  /* -- visible graph: filters, search, hide, collapse -------------------- */
  function gvRep(id) {
    for (const [superId, entry] of gv.collapsed) {
      if (entry.members.includes(id)) return superId;
    }
    return id;
  }
  function gvVisible() {
    const kindFilter = $("graph-kind").value;
    const minConf = Number($("graph-minconf").value || 0);
    const nodes = [];
    const seen = new Set();
    for (const n of gv.nodes) {
      const id = n.id;
      if (gv.hidden.has(id)) continue;
      if (kindFilter && gvKindOf(n) !== kindFilter) continue;
      const rep = gvRep(id);
      if (rep !== id) {
        if (!seen.has(rep)) {
          seen.add(rep);
          const entry = gv.collapsed.get(rep);
          nodes.push({
            id: rep, display_kind: "cluster", kind: "cluster",
            label: entry.label, link_confidence: entry.confidence,
            member_count: entry.members.length,
          });
        }
        continue;
      }
      nodes.push(n);
    }
    const ids = new Set(nodes.map((n) => n.id));
    const edges = [];
    const edgeSeen = new Set();
    for (const e of gv.edges) {
      if (e.confidence < minConf) continue;
      const from = gvRep(e.from), to = gvRep(e.to);
      if (from === to || !ids.has(from) || !ids.has(to)) continue;
      const key = from + "|" + to + "|" + e.relation;
      if (edgeSeen.has(key)) continue;
      edgeSeen.add(key);
      edges.push({ ...e, from, to });
    }
    return { nodes, edges };
  }

  function gvAutoCluster(visible) {
    // Collapse dense components past the render budget (deterministic).
    gv.clusterMembers = new Map();
    for (const [superId, entry] of gv.collapsed) {
      if (entry.auto) gv.collapsed.delete(superId);
    }
    if (visible.nodes.length <= GV_RENDER_NODES) return visible;
    const parent = new Map(visible.nodes.map((n) => [n.id, n.id]));
    const find = (x) => {
      let r = x;
      while (parent.get(r) !== r) r = parent.get(r);
      return r;
    };
    const sorted = visible.edges.slice().sort((a, b) =>
      (a.from < b.from ? -1 : a.from > b.from ? 1 : a.to < b.to ? -1 : a.to > b.to ? 1 : 0));
    for (const e of sorted) {
      const a = find(e.from), b = find(e.to);
      if (a !== b) parent.set(a < b ? b : a, a < b ? a : b);
    }
    const members = new Map();
    for (const n of visible.nodes) {
      const r = find(n.id);
      if (!members.has(r)) members.set(r, []);
      members.get(r).push(n.id);
    }
    const minCluster = Math.max(4, Math.floor(visible.nodes.length / GV_RENDER_NODES));
    const comps = Array.from(members.entries()).sort((a, b) => b[1].length - a[1].length || (a[0] < b[0] ? -1 : 1));
    let shown = visible.nodes.length;
    let seq = 0;
    for (const [, ids] of comps) {
      if (shown <= GV_RENDER_NODES) break;
      if (ids.length < minCluster) continue;
      seq++;
      const superId = "cluster:" + seq;
      const byKind = {};
      let conf = null;
      ids.forEach((id) => {
        const n = gv.byId.get(id);
        const k = n ? gvKindOf(n) : "unknown";
        byKind[k] = (byKind[k] || 0) + 1;
        const c = n && n.link_confidence !== undefined && n.link_confidence !== null ? n.link_confidence : null;
        if (c !== null && (conf === null || c > conf)) conf = c;
      });
      const summary = Object.keys(byKind).sort().map((k) => k + "×" + byKind[k]).join(", ");
      gv.collapsed.set(superId, {
        auto: true, label: ids.length + " nodes (" + summary + ")",
        members: ids.slice().sort(), confidence: conf,
      });
      shown = shown - ids.length + 1;
    }
    return gvVisible();
  }

  /* -- rendering ----------------------------------------------------------- */
  const gvView = { x: 0, y: 0, k: 1 };
  function gvApplyTransform() {
    const g = $("graph-canvas").querySelector("g[data-root]");
    if (g) g.setAttribute("transform", "translate(" + gvView.x + "," + gvView.y + ") scale(" + gvView.k + ")");
    $("graph-canvas").classList.toggle("labels-off", gvView.k < 0.7);
  }
  function gvSvgEl(tag, attrs, parent) {
    const e = document.createElementNS(GVNS, tag);
    for (const k of Object.keys(attrs)) e.setAttribute(k, attrs[k]);
    parent.appendChild(e);
    return e;
  }
  function gvDrawShape(parent, shape, x, y, r, fill) {
    const stroke = "#010813";
    const pts = (n, rot) => {
      const s = [];
      for (let i = 0; i < n; i++) {
        const a = rot + (2 * Math.PI * i) / n;
        s.push((x + r * Math.cos(a)).toFixed(1) + "," + (y + r * Math.sin(a)).toFixed(1));
      }
      return s.join(" ");
    };
    const R = (v) => Math.round(v * 10) / 10;
    if (shape === "circle") return gvSvgEl("circle", { cx: R(x), cy: R(y), r: R(r), fill, stroke, "stroke-width": 1.5, class: "gnode-shape" }, parent);
    if (shape === "ring" || shape === "dashed_circle") {
      const c = gvSvgEl("circle", { cx: R(x), cy: R(y), r: R(r), fill: "none", stroke: fill, "stroke-width": 2.5, class: "gnode-shape" }, parent);
      if (shape === "dashed_circle") c.setAttribute("stroke-dasharray", "4 3");
      return c;
    }
    if (shape === "square") return gvSvgEl("rect", { x: R(x - r * 0.85), y: R(y - r * 0.85), width: R(r * 1.7), height: R(r * 1.7), fill, stroke, "stroke-width": 1.5, class: "gnode-shape" }, parent);
    if (shape === "double_square") {
      gvSvgEl("rect", { x: R(x - r * 0.85), y: R(y - r * 0.85), width: R(r * 1.7), height: R(r * 1.7), fill, stroke, "stroke-width": 1.5, class: "gnode-shape" }, parent);
      return gvSvgEl("rect", { x: R(x - r * 0.55), y: R(y - r * 0.55), width: R(r * 1.1), height: R(r * 1.1), fill: "none", stroke, "stroke-width": 1, class: "gnode-shape" }, parent);
    }
    if (shape === "rounded_rect") return gvSvgEl("rect", { x: R(x - r), y: R(y - r * 0.7), width: R(r * 2), height: R(r * 1.4), rx: 3, fill, stroke, "stroke-width": 1.5, class: "gnode-shape" }, parent);
    if (shape === "diamond") return gvSvgEl("polygon", { points: R(x) + "," + R(y - r) + " " + R(x + r) + "," + R(y) + " " + R(x) + "," + R(y + r) + " " + R(x - r) + "," + R(y), fill, stroke, "stroke-width": 1.5, class: "gnode-shape" }, parent);
    if (shape === "triangle") return gvSvgEl("polygon", { points: R(x) + "," + R(y - r) + " " + R(x - r) + "," + R(y + r * 0.8) + " " + R(x + r) + "," + R(y + r * 0.8), fill, stroke, "stroke-width": 1.5, class: "gnode-shape" }, parent);
    if (shape === "triangle_down") return gvSvgEl("polygon", { points: R(x) + "," + R(y + r) + " " + R(x - r) + "," + R(y - r * 0.8) + " " + R(x + r) + "," + R(y - r * 0.8), fill, stroke, "stroke-width": 1.5, class: "gnode-shape" }, parent);
    if (shape === "ellipse") return gvSvgEl("ellipse", { cx: R(x), cy: R(y), rx: R(r * 1.25), ry: R(r * 0.8), fill, stroke, "stroke-width": 1.5, class: "gnode-shape" }, parent);
    if (shape === "parallelogram") return gvSvgEl("polygon", { points: R(x - r * 0.6) + "," + R(y - r * 0.8) + " " + R(x + r) + "," + R(y - r * 0.8) + " " + R(x + r * 0.6) + "," + R(y + r * 0.8) + " " + R(x - r) + "," + R(y + r * 0.8), fill, stroke, "stroke-width": 1.5, class: "gnode-shape" }, parent);
    const sides = shape === "pentagon" ? 5 : shape === "octagon" ? 8 : 6;
    return gvSvgEl("polygon", { points: pts(sides, -Math.PI / 2), fill, stroke, "stroke-width": 1.5, class: "gnode-shape" }, parent);
  }

  /* Draw an icon glyph from the embedded sprite via `<use>`, never inline
     SVG per node. Falls back to the caller when the sprite is unavailable. */
  function gvDrawIcon(parent, icon, ramp, x, y, r, selected) {
    const color = RAMP_COLOR[ramp] || GV_COLORS.network;
    const use = gvSvgEl("use", {
      href: `#rx-${icon}`,
      x: (x - r).toFixed(1),
      y: (y - r).toFixed(1),
      width: (2 * r).toFixed(1),
      height: (2 * r).toFixed(1),
      fill: "none",
      stroke: selected ? "#fff" : color,
      "stroke-width": selected ? 2.5 : (r < 6 ? 1.2 : 2),
      class: "gnode-shape gicon",
    }, parent);
    return use;
  }

  /* Inline the icon sprite symbols into the graph <defs> once, so every node
     references them with `<use>` instead of duplicating SVG. Fail closed: the
     shape renderer stays available if the sprite cannot be loaded. */
  async function ensureSprite() {
    if (spriteReady) return;
    try {
      const res = await fetch("/app/assets/icons/glyphs/rxscan-sprite.svg");
      if (!res.ok) return;
      const text = await res.text();
      const doc = new DOMParser().parseFromString(text, "image/svg+xml");
      const symbols = doc.querySelectorAll("symbol");
      if (!symbols.length) return;
      const svg = $("graph-canvas");
      let defs = svg.querySelector("defs");
      if (!defs) {
        defs = document.createElementNS(GVNS, "defs");
        svg.insertBefore(defs, svg.firstChild);
      }
      for (const sym of symbols) {
        defs.appendChild(document.importNode(sym, true));
      }
      spriteReady = true;
    } catch (_) {
      spriteReady = false;
    }
  }

  function gvRender() {
    const svg = $("graph-canvas");
    const defs = svg.querySelector("defs");
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const g = gvSvgEl("g", { "data-root": "1" }, svg);
    if (defs) svg.insertBefore(defs, g);
    if (!gv.loaded) { gvStatus("No graph loaded."); return; }
    let visible = gvVisible();
    visible = gvAutoCluster(visible);
    const nodes = visible.nodes.slice(0, GV_RENDER_NODES);
    const edges = visible.edges.slice(0, GV_RENDER_EDGES);
    const shownIds = new Set(nodes.map((n) => n.id));
    const posOf = (id) => gv.positions.get(id) || [500, 350];
    const query = $("graph-q").value.trim().toLowerCase();
    const lightweight = gvView.k < 0.6 || window.innerWidth <= 760;
    for (const e of edges) {
      if (!shownIds.has(e.from) || !shownIds.has(e.to)) continue;
      const [x1, y1] = posOf(e.from), [x2, y2] = posOf(e.to);
      const line = gvSvgEl("line", {
        x1: x1.toFixed(1), y1: y1.toFixed(1), x2: x2.toFixed(1), y2: y2.toFixed(1),
        class: "glink" + (e.observed === false ? " inferred" : "") + (gv.selection.has("e:" + e.from + "|" + e.to + "|" + e.relation) ? " selected" : ""),
        "stroke-width": e.thickness || 1.5, tabindex: "0", role: "button",
        "aria-label": "Relationship " + (e.display_relation || e.relation) + ", confidence " + e.confidence,
      }, g);
      line.addEventListener("click", (ev) => { ev.stopPropagation(); gvSelectEdge(e, ev.ctrlKey || ev.metaKey); });
      line.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); gvSelectEdge(e, false); }
      });
    }
    for (const n of nodes) {
      const [x, y] = posOf(n.id);
      const kind = gvKindOf(n);
      const wrap = gvSvgEl("g", {
        class: "gnode-wrap" + (gv.selection.has(n.id) ? " selected" : "") + (query && (n.label + " " + n.id).toLowerCase().includes(query) ? " highlighted" : ""),
        tabindex: "0", role: "button",
        "aria-label": "Entity " + kind + " " + n.label + ", confidence " + (n.link_confidence === null || n.link_confidence === undefined ? "unrated" : n.link_confidence),
      }, g);
      wrap.setAttribute("data-node", n.id);
      const r = kind === "cluster" ? Math.min(20, 6 + Math.sqrt(n.member_count || 1) * 2) : 8;
      const icon = n.icon || null;
      const ramp = n.ramp || null;
      const useIcon = spriteReady && icon && !lightweight && kind !== "cluster";
      const shape = useIcon
        ? gvDrawIcon(wrap, icon, ramp, x, y, r, gv.selection.has(n.id))
        : gvDrawShape(wrap, gvShape(kind), x, y, r, gvColor(kind));
      shape.addEventListener("click", (ev) => { ev.stopPropagation(); gvSelectNode(n.id, ev.ctrlKey || ev.metaKey); });
      shape.addEventListener("dblclick", (ev) => { ev.stopPropagation(); gvExpandCluster(n.id); });
      wrap.addEventListener("click", (ev) => { ev.stopPropagation(); gvSelectNode(n.id, ev.ctrlKey || ev.metaKey); });
      wrap.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); gvSelectNode(n.id, false); }
      });
      wrap.addEventListener("pointerdown", (ev) => {
        if (ev.button !== 0 || ev.shiftKey) return;
        ev.stopPropagation();
        gvDragNode(n.id, ev);
      });
      const label = String(n.label || n.id);
      const t = gvSvgEl("text", { x: (x + r + 3).toFixed(1), y: (y + 4).toFixed(1), class: "glabel" }, wrap);
      t.textContent = label.length > 24 ? label.slice(0, 23) + "…" : label;
    }
    gvRenderLegend(visible.nodes);
    gvApplyTransform();
    const total = gv.nodes.length;
    gvStatus(
      "Showing " + nodes.length + " of " + total + " nodes, " + edges.length + " relationships" +
      (visible.nodes.length > nodes.length || visible.edges.length > edges.length ? " (render caps; filter or zoom to narrow)" : "") +
      (gv.truncated ? " (server truncated; narrow filters or export via CLI)" : "") +
      ". Shift-drag selects an area; right-click a node for actions."
    );
  }

  function gvRenderLegend(nodes) {
    const ul = $("graph-legend");
    clear(ul);
    // Group visible nodes by manifest category, show one icon per category.
    const byCat = new Map();
    for (const n of nodes) {
      const cat = n.category || "other";
      if (!byCat.has(cat)) byCat.set(cat, []);
      byCat.get(cat).push(n);
    }
    const cats = Array.from(byCat.keys()).sort();
    for (const cat of cats) {
      const members = byCat.get(cat);
      const sample = members[0];
      const li = document.createElement("li");
      li.className = "legend-item";
      const icon = sample.icon || null;
      const ramp = sample.ramp || null;
      if (icon && spriteReady) {
        const sw = document.createElementNS(GVNS, "use");
        sw.setAttribute("href", `#rx-${icon}`);
        sw.setAttribute("width", "16");
        sw.setAttribute("height", "16");
        sw.setAttribute("fill", "none");
        sw.setAttribute("stroke", RAMP_COLOR[ramp] || GV_COLORS.network);
        sw.setAttribute("stroke-width", "2");
        sw.setAttribute("class", "swatch");
        li.appendChild(sw);
      } else {
        const sw = document.createElement("span");
        sw.className = "swatch";
        sw.style.background = sample ? gvColor(gvKindOf(sample)) : "#6b7d94";
        li.appendChild(sw);
      }
      const label = document.createElement("span");
      label.textContent = cat + " (" + members.length + ")";
      li.appendChild(label);
      ul.appendChild(li);
    }
    if (!cats.length) ul.appendChild(el("li", "No entities — empty graph."));
    const solid = document.createElement("li");
    solid.textContent = "solid = observed · dashed = inferred · width = confidence";
    ul.appendChild(solid);
  }

  /* -- selection + detail -------------------------------------------------- */
  function gvKv(dl, k, v) {
    const div = document.createElement("div");
    const dt = document.createElement("dt");
    dt.textContent = k;
    const dd = document.createElement("dd");
    dd.textContent = v === null || v === undefined || v === "" ? "—" : String(v);
    div.append(dt, dd);
    dl.appendChild(div);
  }
  function gvSelectNode(id, additive) {
    if (!additive) gv.selection.clear();
    if (gv.selection.has(id)) gv.selection.delete(id);
    else gv.selection.add(id);
    gvRender();
    const single = gv.selection.size === 1 ? Array.from(gv.selection)[0] : null;
    if (single && !single.startsWith("e:")) gvShowNode(single).catch(() => {});
    else if (single) gvShowEdgeById(single);
  }
  function gvSelectEdge(e, additive) {
    const id = "e:" + e.from + "|" + e.to + "|" + e.relation;
    if (!additive) gv.selection.clear();
    gv.selection.add(id);
    gvRender();
    gvShowEdge(e);
  }
  function gvShowEdgeById(id) {
    const parts = id.slice(2).split("|");
    const e = gv.edges.find((x) => x.from === parts[0] && x.to === parts[1] && String(x.relation) === parts[2]);
    if (e) gvShowEdge(e);
  }
  async function gvShowNode(id) {
    const box = $("graph-inspect"), empty = $("graph-inspect-empty");
    const rep = gvRep(id);
    if (rep !== id) {
      empty.hidden = true; box.hidden = false; clear(box);
      const entry = gv.collapsed.get(rep);
      gvKv(box, "collection", entry.label);
      gvKv(box, "members", entry.members.length);
      gvKv(box, "hint", "Double-click or right-click to expand.");
      return;
    }
    try {
      const detail = await api("/api/v1/projects/" + encodeURIComponent(activeProject()) + "/graph/node?node=" + encodeURIComponent(id));
      empty.hidden = true; box.hidden = false; clear(box);
      const n = detail.node || {};
      gvKv(box, "label", n.label);
      gvKv(box, "kind", gvKindOf(n) + " (" + (n.stored_kind || "?") + ")");
      gvKv(box, "confidence", n.link_confidence === null || n.link_confidence === undefined ? "unrated (no incident relationships)" : n.link_confidence + " (strongest linked relationship)");
      gvKv(box, "scope", n.scope);
      gvKv(box, "observations", n.observations);
      Object.keys(n.attributes || {}).sort().forEach((k) => gvKv(box, "attr " + k, n.attributes[k]));
      (detail.evidence_chain || []).slice(0, 16).forEach((link, i) => {
        gvKv(box, "evidence " + (i + 1), link.summary + " — " + link.module);
      });
      gvKv(box, "explanation", detail.explanation);
    } catch (err) {
      gvStatus("Detail unavailable: " + err.message);
    }
  }
  function gvShowEdge(e) {
    const box = $("graph-inspect"), empty = $("graph-inspect-empty");
    empty.hidden = true; box.hidden = false; clear(box);
    gvKv(box, "relationship", (e.display_relation || e.relation) + " (" + (e.stored_relation || e.relation) + ")");
    gvKv(box, "style", e.observed === false ? "dashed (inferred)" : "solid (directly observed)");
    gvKv(box, "confidence", e.confidence);
    gvKv(box, "from", e.from);
    gvKv(box, "to", e.to);
    gvKv(box, "module", e.module);
    gvKv(box, "scan run", e.scan_run);
    (e.evidence || []).forEach((x, i) => gvKv(box, "evidence " + (i + 1), x));
  }

  /* -- data ---------------------------------------------------------------- */
  async function gvLoad() {
    const project = activeProject();
    const minConf = Number($("graph-minconf").value || 0);
    gvStatus("Loading graph for project " + project + "…");
    try {
      const data = await api("/api/v1/projects/" + encodeURIComponent(project) + "/graph?limit=5000&min_confidence=" + minConf);
      gv.nodes = data.nodes || [];
      gv.edges = data.edges || [];
      gv.byId = new Map(gv.nodes.map((n) => [n.id, n]));
      gv.truncated = !!data.truncated;
      await ensureSprite();
      gv.hidden.clear(); gv.pinned.clear(); gv.selection.clear();
      for (const [superId, entry] of gv.collapsed) {
        if (entry.auto) gv.collapsed.delete(superId);
      }
      gv.undo.length = 0; gv.redo.length = 0;
      gv.layout = $("graph-layout").value;
      gvRelayout();
      gv.loaded = true;
      gvRender();
    } catch (err) {
      gv.loaded = false;
      gvRender();
      gvStatus("Graph unavailable: " + err.message);
    }
  }
  function gvRelayout() {
    const visible = gvVisible();
    const ids = visible.nodes.map((n) => n.id);
    const seed = gv.selection.size === 1 ? Array.from(gv.selection)[0] : null;
    const computed = gvComputeLayout(ids, visible.edges, gv.layout, seed);
    for (const [id, p] of computed) {
      if (!gv.pinned.has(id) || !gv.positions.has(id)) gv.positions.set(id, p);
    }
  }
  $("graph-load").addEventListener("click", gvLoad);
  $("graph-layout").addEventListener("change", () => {
    gvSnapshot();
    gv.layout = $("graph-layout").value;
    gvRelayout();
    gvRender();
  });
  $("graph-kind").addEventListener("change", gvRender);
  $("graph-minconf").addEventListener("input", () => {
    $("graph-minconf-val").textContent = $("graph-minconf").value;
  });
  $("graph-minconf").addEventListener("change", gvLoad);
  $("graph-q").addEventListener("input", gvRender);
  // Kind options mirror the Rust DisplayKind vocabulary.
  for (const k of GV_KINDS) {
    const o = document.createElement("option");
    o.value = k;
    o.textContent = k;
    $("graph-kind").appendChild(o);
  }

  /* -- pan / zoom / box select / drag -------------------------------------- */
  const gvSvg = () => $("graph-canvas");
  function gvScreenToWorld(clientX, clientY) {
    const r = gvSvg().getBoundingClientRect();
    const vb = gvSvg().viewBox.baseVal;
    const sx = (clientX - r.left) * (vb.width / r.width);
    const sy = (clientY - r.top) * (vb.height / r.height);
    return [(sx - gvView.x) / gvView.k, (sy - gvView.y) / gvView.k];
  }
  function gvZoom(f) {
    gvView.k = Math.min(4, Math.max(0.4, gvView.k * f));
    gvApplyTransform();
  }
  $("graph-zin").addEventListener("click", () => gvZoom(1.25));
  $("graph-zout").addEventListener("click", () => gvZoom(0.8));
  $("graph-zreset").addEventListener("click", () => { gvView.x = 0; gvView.y = 0; gvView.k = 1; gvApplyTransform(); });
  gvSvg().addEventListener("wheel", (ev) => {
    ev.preventDefault();
    gvZoom(ev.deltaY < 0 ? 1.1 : 0.9);
  }, { passive: false });

  let gvPan = null, gvBox = null;
  gvSvg().addEventListener("pointerdown", (ev) => {
    hideCtxMenu();
    if (ev.button !== 0) return;
    gvSvg().setPointerCapture(ev.pointerId);
    if (ev.shiftKey) {
      const [wx, wy] = gvScreenToWorld(ev.clientX, ev.clientY);
      gvBox = { x0: wx, y0: wy, x1: wx, y1: wy, el: null };
    } else {
      gvPan = { x: ev.clientX, y: ev.clientY, vx: gvView.x, vy: gvView.y, moved: false };
    }
  });
  gvSvg().addEventListener("pointermove", (ev) => {
    if (gvBox) {
      const [wx, wy] = gvScreenToWorld(ev.clientX, ev.clientY);
      gvBox.x1 = wx; gvBox.y1 = wy;
      drawBox();
    } else if (gvPan) {
      const dx = ev.clientX - gvPan.x, dy = ev.clientY - gvPan.y;
      if (Math.abs(dx) + Math.abs(dy) > 3) gvPan.moved = true;
      gvView.x = gvPan.vx + dx; gvView.y = gvPan.vy + dy;
      gvApplyTransform();
    }
  });
  gvSvg().addEventListener("pointerup", (ev) => {
    if (gvBox) {
      boxSelect();
      gvBox = null;
    } else if (gvPan && !gvPan.moved) {
      gv.selection.clear();
      gvRender();
    }
    gvPan = null;
  });
  function drawBox() {
    const svg = gvSvg();
    let rect = svg.querySelector("rect.graph-box");
    if (!rect) {
      const g = svg.querySelector("g[data-root]");
      rect = gvSvgEl("rect", { class: "graph-box" }, g);
      gvBox.el = rect;
    }
    const x = Math.min(gvBox.x0, gvBox.x1), y = Math.min(gvBox.y0, gvBox.y1);
    rect.setAttribute("x", x); rect.setAttribute("y", y);
    rect.setAttribute("width", Math.abs(gvBox.x1 - gvBox.x0));
    rect.setAttribute("height", Math.abs(gvBox.y1 - gvBox.y0));
  }
  function boxSelect() {
    const x = Math.min(gvBox.x0, gvBox.x1), y = Math.min(gvBox.y0, gvBox.y1);
    const w = Math.abs(gvBox.x1 - gvBox.x0), h = Math.abs(gvBox.y1 - gvBox.y0);
    gv.selection.clear();
    for (const [id, p] of gv.positions) {
      if (p[0] >= x && p[0] <= x + w && p[1] >= y && p[1] <= y + h) gv.selection.add(id);
    }
    gvRender();
    gvStatus(gv.selection.size + " selected.");
  }
  let gvDrag = null;
  function gvDragNode(id, ev) {
    gvSnapshot();
    const start = gvScreenToWorld(ev.clientX, ev.clientY);
    const orig = gv.positions.get(id) || [500, 350];
    const dx = orig[0] - start[0], dy = orig[1] - start[1];
    const move = (me) => {
      const [wx, wy] = gvScreenToWorld(me.clientX, me.clientY);
      gv.positions.set(id, [wx + dx, wy + dy]);
      gvApplyPositions();
    };
    const up = () => {
      gvSvg().removeEventListener("pointermove", move);
      gvSvg().removeEventListener("pointerup", up);
      if (gvDrag && gvDrag.moved) { gv.pinned.add(id); }
      gvDrag = null;
    };
    gvDrag = { moved: true };
    gvSvg().addEventListener("pointermove", move);
    gvSvg().addEventListener("pointerup", up);
  }
  function gvApplyPositions() {
    // Move rendered nodes without a full re-render (drag stays smooth).
    const svg = gvSvg();
    const g = svg.querySelector("g[data-root]");
    if (!g) return;
    gvRender();
  }

  /* -- context menu: stored-data actions only ------------------------------ */
  function hideCtxMenu() {
    const m = $("graph-menu");
    m.hidden = true;
    clear(m);
  }
  function gvCopy(text) {
    const done = () => gvStatus("Copied (masked where required).");
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, () => gvStatus("Copy failed."));
    } else {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); done(); } catch (_) { gvStatus("Copy failed."); }
      document.body.removeChild(ta);
    }
  }
  gvSvg().addEventListener("contextmenu", (ev) => {
    ev.preventDefault();
    const target = ev.target.closest ? ev.target.closest(".gnode-wrap") : null;
    const m = $("graph-menu");
    clear(m);
    m.hidden = false;
    const wrap = gvSvg().parentElement;
    m.style.left = Math.min(ev.clientX - wrap.getBoundingClientRect().left, wrap.clientWidth - 200) + "px";
    m.style.top = (ev.clientY - wrap.getBoundingClientRect().top) + "px";
    const add = (label, fn) => {
      const b = document.createElement("button");
      b.type = "button";
      b.setAttribute("role", "menuitem");
      b.textContent = label;
      b.addEventListener("click", () => { hideCtxMenu(); fn(); });
      m.appendChild(b);
    };
    const note = document.createElement("p");
    note.className = "ctx-note";
    note.textContent = "Stored evidence only — no network activity.";
    m.appendChild(note);
    // Resolve the node under the pointer via its data attribute.
    let id = null;
    if (target && target.getAttribute("data-node")) {
      id = target.getAttribute("data-node");
      if (!gv.selection.has(id)) {
        gv.selection.clear();
        gv.selection.add(id);
        gvRender();
      }
    }
    if (!id || id.startsWith("e:")) {
      add("Clear selection", () => { gv.selection.clear(); gvRender(); });
      m.querySelector("button").focus();
      return;
    }
    const nodeId = id;
    add("Show detail", () => gvShowNode(nodeId).catch(() => {}));
    add("Expand neighbors (stored)", () => gvExpand(nodeId).catch(() => {}));
    add(gv.pinned.has(nodeId) ? "Unpin" : "Pin position", () => {
      gvSnapshot();
      if (gv.pinned.has(nodeId)) gv.pinned.delete(nodeId);
      else gv.pinned.add(nodeId);
      gvRender();
    });
    add("Hide node", () => {
      gvSnapshot();
      gv.hidden.add(nodeId);
      gv.selection.delete(nodeId);
      gvRender();
    });
    if (gv.collapsed.has(nodeId)) {
      add("Expand collection", () => {
        gvSnapshot();
        gv.collapsed.delete(nodeId);
        gvRelayout();
        gvRender();
      });
    }
    add("Copy value (masked)", () => {
      const n = gv.byId.get(nodeId);
      gvCopy(n ? n.label + " [" + gvKindOf(n) + "]" : nodeId);
    });
    m.querySelector("button").focus();
  });
  document.addEventListener("click", (ev) => {
    const m = $("graph-menu");
    if (!m.hidden && !m.contains(ev.target)) hideCtxMenu();
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") hideCtxMenu();
  });

  async function gvExpand(nodeId) {
    gvStatus("Expanding stored neighbors of " + nodeId + "…");
    try {
      const data = await api("/api/v1/projects/" + encodeURIComponent(activeProject()) + "/graph/neighbors?node=" + encodeURIComponent(nodeId) + "&limit=100");
      gvSnapshot();
      let added = 0;
      for (const nb of data.neighbors || []) {
        if (!gv.byId.has(nb.id)) {
          gv.nodes.push({
            id: nb.id, kind: nb.kind, display_kind: nb.display_kind || nb.kind,
            label: nb.label, link_confidence: nb.confidence,
          });
          gv.byId.set(nb.id, gv.nodes[gv.nodes.length - 1]);
          added++;
        }
        if (!gv.edges.some((e) => e.from === nodeId && e.to === nb.id && String(e.relation) === nb.stored_relation)) {
          gv.edges.push({
            from: nodeId, to: nb.id, relation: nb.stored_relation,
            display_relation: nb.relation, observed: nb.observed,
            confidence: nb.confidence, thickness: 1 + 3 * nb.confidence / 100,
            module: nb.module, scan_run: nb.scan_run,             evidence: nb.evidence ? [nb.evidence] : [],
          });
        }
      }
      gvRelayout();
      gvRender();
      gvStatus("Added " + added + " stored neighbors (no network).");
    } catch (err) {
      gvStatus("Expand failed: " + err.message);
    }
  }

  /* -- manual groups -------------------------------------------------------- */
  $("graph-group").addEventListener("click", () => {
    const members = Array.from(gv.selection).filter((id) => !id.startsWith("e:") && gvRep(id) === id);
    if (members.length < 2) { gvStatus("Select two or more nodes to group."); return; }
    gvSnapshot();
    gv.groupSeq++;
    const gid = "group:" + gv.groupSeq;
    let conf = null;
    members.forEach((id) => {
      const n = gv.byId.get(id);
      const c = n && n.link_confidence !== undefined && n.link_confidence !== null ? n.link_confidence : null;
      if (c !== null && (conf === null || c > conf)) conf = c;
    });
    gv.collapsed.set(gid, { auto: false, label: "Group of " + members.length, members: members.slice().sort(), confidence: conf });
    gv.selection.clear();
    gv.selection.add(gid);
    gvRelayout();
    gvRender();
    gvStatus("Grouped " + members.length + " nodes.");
  });
  $("graph-ungroup").addEventListener("click", () => {
    const groups = Array.from(gv.selection).filter((id) => gv.collapsed.has(id));
    if (!groups.length) { gvStatus("Select a group or collection to expand."); return; }
    gvSnapshot();
    groups.forEach((g) => gv.collapsed.delete(g));
    gvRelayout();
    gvRender();
    gvStatus("Expanded.");
  });
  function gvExpandCluster(id) {
    if (!gv.collapsed.has(id)) return;
    gvSnapshot();
    gv.collapsed.delete(id);
    gvRelayout();
    gvRender();
    gvStatus("Expanded collection.");
  }

  /* -- collections ----------------------------------------------------------- */
  function gvRefreshCollections() {
    const sel = $("graph-collection");
    clear(sel);
    const none = document.createElement("option");
    none.value = "";
    none.textContent = "none";
    sel.appendChild(none);
    for (const name of Array.from(gv.collections.keys()).sort()) {
      const o = document.createElement("option");
      o.value = name;
      o.textContent = name + " (" + gv.collections.get(name).length + ")";
      sel.appendChild(o);
    }
  }
  $("graph-col-save").addEventListener("click", () => {
    const name = $("graph-col-name").value.trim();
    const members = Array.from(gv.selection).filter((id) => !id.startsWith("e:"));
    if (!name) { gvStatus("Type a collection name first."); return; }
    if (!members.length) { gvStatus("Select nodes to save into the collection."); return; }
    gv.collections.set(name, members.slice().sort());
    gvRefreshCollections();
    $("graph-collection").value = name;
    gvStatus("Saved collection " + name + " (" + members.length + " nodes).");
  });
  $("graph-col-apply").addEventListener("click", () => {
    const name = $("graph-collection").value;
    const members = gv.collections.get(name);
    if (!members) { gvStatus("No such collection."); return; }
    gv.selection.clear();
    members.forEach((id) => gv.selection.add(id));
    gvRender();
    gvStatus("Applied collection " + name + ".");
  });
  $("graph-col-delete").addEventListener("click", () => {
    const name = $("graph-collection").value;
    if (gv.collections.delete(name)) {
      gvRefreshCollections();
      gvStatus("Deleted collection " + name + ".");
    } else {
      gvStatus("No such collection.");
    }
  });

  /* -- keyboard -------------------------------------------------------------- */
  gvSvg().addEventListener("keydown", (ev) => {
    const visible = gvVisible().nodes.map((n) => n.id).sort();
    if (!visible.length) return;
    const current = Array.from(gv.selection).filter((id) => !id.startsWith("e:"))[0] || null;
    const idx = current ? visible.indexOf(current) : -1;
    if (ev.key === "ArrowRight" || ev.key === "ArrowDown") {
      ev.preventDefault();
      gvSelectNode(visible[(idx + 1 + visible.length) % visible.length], false);
    } else if (ev.key === "ArrowLeft" || ev.key === "ArrowUp") {
      ev.preventDefault();
      gvSelectNode(visible[(idx - 1 + visible.length) % visible.length], false);
    } else if (ev.key === "+" || ev.key === "=") {
      ev.preventDefault();
      gvZoom(1.25);
    } else if (ev.key === "-") {
      ev.preventDefault();
      gvZoom(0.8);
    } else if (ev.key === "Delete" || ev.key === "Backspace") {
      ev.preventDefault();
      if (current) {
        gvSnapshot();
        gv.hidden.add(current);
        gv.selection.delete(current);
        gvRender();
        gvStatus("Hidden. Undo restores it.");
      }
    }
  });

  /* -- init ------------------------------------------------------------------ */
  gvRefreshCollections();

  /* -- init: slow heartbeat only, never aggressive health/project polling --- */
  /* Health heartbeat is slow (60s) and skips when hidden. Projects refresh
     on view activation, after mutation, or after a persisted job completes.
     Jobs list uses a slow 15s fallback only when auto-refresh is on and the
     Jobs view is visible. Live job detail is SSE-primary. */
  const HEALTH_HEARTBEAT_MS = 60000;
  jobsAuto = window.setInterval(() => {
    if (isHidden()) return;
    if (currentRoute().name === "jobs" && $("jobs-auto").checked) refreshJobs().catch(() => {});
  }, JOBS_FALLBACK_MS);
  window.setInterval(() => { refreshHealth().catch(() => {}); }, HEALTH_HEARTBEAT_MS);
  window.addEventListener("online", () => { refreshHealth().catch(() => {}); });
  showRoute();
  refreshTopbar().catch(() => {});
  refreshDashboard().catch(() => {});
})();
