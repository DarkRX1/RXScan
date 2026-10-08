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
        const c = document.createElementNS(NS, "circle");
        c.setAttribute("cx", n._x.toFixed(1));
        c.setAttribute("cy", n._y.toFixed(1));
        c.setAttribute("r", n.id === (selected && selected.id) ? "10" : "8");
        c.setAttribute("class", "gnode" + (selected && selected.type === "node" && selected.id === n.id ? " selected" : ""));
        c.setAttribute("fill", kindColor(n.kind));
        c.setAttribute("tabindex", "0");
        c.setAttribute("role", "button");
        c.setAttribute("aria-label", "Entity " + n.kind + " " + n.label);
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

    // pan
    let drag = null;
    svg.addEventListener("pointerdown", (ev) => {
      drag = { x: ev.clientX, y: ev.clientY, vx: view.x, vy: view.y };
      svg.setPointerCapture(ev.pointerId);
    });
    svg.addEventListener("pointermove", (ev) => {
      if (!drag) return;
      view.x = drag.vx + (ev.clientX - drag.x);
      view.y = drag.vy + (ev.clientY - drag.y);
      const g = svg.querySelector("g");
      if (g) applyTransform(g);
    });
    svg.addEventListener("pointerup", () => { drag = null; });
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
  const VIEWS = ["dashboard", "scan", "search", "investigate", "projects", "jobs"];
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
