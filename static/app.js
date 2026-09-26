(function () {
"use strict";

/* ---------- nav ---------- */
const views = ["home", "db", "sentinel", "threat"];
const labels = { home: "Home", db: "Research Database", sentinel: "Encrypted Sentinel", threat: "Threat Intelligence" };
const nav = document.getElementById("nav");
views.forEach((v) => {
  const b = document.createElement("button");
  b.textContent = labels[v];
  b.dataset.v = v;
  if (v === "home") b.className = "active";
  b.onclick = () => showView(v);
  nav.appendChild(b);
});
function showView(v) {
  views.forEach((x) => document.getElementById("view-" + x).classList.toggle("active", x === v));
  [...nav.children].forEach((b) => b.classList.toggle("active", b.dataset.v === v));
  if (v === "threat") loadThreatDb();
}

/* ---------- Research Database + API explorer ---------- */
fetch("/api/samples").then((r) => r.json()).then((d) => {
  const tbody = document.querySelector("#sampleTable tbody");
  d.samples.forEach((s) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${s.id}</td><td>${s.species}</td><td>${s.depth_m}</td><td>${s.site}</td><td>${s.status}</td>`;
    tbody.appendChild(tr);
  });
});

const endpoints = [
  { path: "/api/species", desc: "Published species list" },
  { path: "/api/expeditions", desc: "Expedition logs" },
  { path: "/api/samples", desc: "Full specimen registry" },
  { path: "/api/samples/search?q=riftia", desc: "Search the registry" },
  { path: "/api/users", desc: "Internal researcher accounts" },
  { path: "/api/admin/config", desc: "Infrastructure configuration" },
  { path: "/api/internal/export", desc: "Full database export" },
];
const epList = document.getElementById("endpointList");
endpoints.forEach((ep) => {
  const row = document.createElement("div");
  row.className = "endpoint-row";
  row.innerHTML = `<div><div class="epath">GET ${ep.path}</div><div class="esub">${ep.desc}</div></div>
    <button class="btn ghost">Try it</button>`;
  epList.appendChild(row);
  const pre = document.createElement("pre");
  pre.className = "resp";
  pre.style.display = "none";
  epList.appendChild(pre);
  row.querySelector("button").onclick = async () => {
    const res = await fetch(ep.path);
    const json = await res.json();
    pre.style.display = "block";
    pre.textContent = `GET ${ep.path} → ${res.status}\n\n` + JSON.stringify(json, null, 2);
  };
});

/* ---------- Encrypted Sentinel ---------- */
document.getElementById("runSentinel").onclick = async function () {
  const btn = this, stat = document.getElementById("sentinelStatus");
  const wrap = document.getElementById("sentinelTableWrap");
  const tbody = document.querySelector("#sentinelTable tbody");
  btn.disabled = true;
  stat.textContent = "Scanning live endpoints…";
  tbody.innerHTML = "";
  try {
    const res = await fetch("/api/sentinel/scan", { method: "POST" });
    const data = await res.json();
    wrap.style.display = "block";
    data.findings.forEach((f) => {
      const tr = document.createElement("tr");
      const cls = f.result === "PASS" ? "pass" : f.result === "WARN" ? "warn" : "fail";
      tr.innerHTML = `<td>${f.endpoint}</td><td>${f.check_type}</td>
        <td><span class="pill ${cls}">${f.result}</span></td>
        <td class="small">${f.evidence}</td>
        <td class="small">${f.ai_suggestion || ""}</td>`;
      tbody.appendChild(tr);
    });
    stat.textContent = `Scan complete · ${data.findings.length} checks run`;
  } catch (e) {
    stat.textContent = "Scan failed: " + e;
  }
  btn.disabled = false;
};

/* ---------- Malicious-AI attack launcher ---------- */
document.getElementById("targetUrl").value = window.location.origin;

document.getElementById("launchAttack").onclick = async function () {
  const btn = this;
  const targetUrl = document.getElementById("targetUrl").value.trim();
  const consoleEl = document.getElementById("attackConsole");
  const resultWrap = document.getElementById("attackResultWrap");
  if (!targetUrl) return;
  btn.disabled = true;
  consoleEl.style.display = "block";
  consoleEl.innerHTML = "";
  resultWrap.style.display = "none";

  const startRes = await fetch("/api/attack/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target_url: targetUrl }),
  });
  const { run_id, error } = await startRes.json();
  if (error) {
    addLine(consoleEl, "error", error);
    btn.disabled = false;
    return;
  }

  const es = new EventSource("/api/attack/stream/" + run_id);
  es.onmessage = (ev) => {
    const e = JSON.parse(ev.data);
    if (e.kind === "run_status") {
      es.close();
      btn.disabled = false;
      loadThreatDb();
      showAttackResult(run_id);
      return;
    }
    addLine(consoleEl, e.kind, e.text);
    consoleEl.scrollTop = consoleEl.scrollHeight;
  };
  es.onerror = () => { es.close(); btn.disabled = false; };
};

function addLine(el, kind, text) {
  const div = document.createElement("div");
  div.className = "line " + kind;
  const prefix = { tool_call: "→", reasoning: "·", thought: "·", status: "◆", error: "✕", final: "✓" }[kind] || "·";
  div.textContent = `${prefix} ${text}`;
  el.appendChild(div);
}

async function showAttackResult(runId) {
  const res = await fetch("/api/attack/result/" + runId);
  const { extracted } = await res.json();
  const wrap = document.getElementById("attackResultWrap");
  const tbody = document.querySelector("#attackResultTable tbody");
  tbody.innerHTML = "";
  let rows = [];
  let body = extracted && (extracted.last_body || extracted.raw);
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch (e) { body = null; }
  }
  if (body) {
    rows = body.samples || body.data || (Array.isArray(body) ? body : []);
  }
  if (!rows.length) {
    wrap.style.display = "none";
    return;
  }
  wrap.style.display = "block";
  rows.forEach((s) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${s.id || ""}</td><td>${s.species || ""}</td><td>${s.depth_m || ""}</td><td>${s.site || ""}</td><td>${s.status || ""}</td>`;
    tbody.appendChild(tr);
  });
}

/* ---------- Threat DB ---------- */
document.getElementById("refreshThreatDb").onclick = loadThreatDb;

async function loadThreatDb() {
  const res = await fetch("/api/threatdb");
  const { runs } = await res.json();
  document.getElementById("statSessions").textContent = runs.length;
  document.getElementById("statDiverted").textContent = runs.filter((r) => r.diverted).length;
  document.getElementById("statCanary").textContent = runs.filter((r) => r.canary_triggered).length;

  const box = document.getElementById("threatList");
  box.innerHTML = "";
  if (!runs.length) {
    box.innerHTML = '<p class="small">No attack runs recorded yet. Launch one above.</p>';
    return;
  }
  runs.forEach((r) => {
    const risk = r.score >= 70 ? "high" : r.score >= 40 ? "med" : "";
    const div = document.createElement("div");
    div.className = "threat-item " + risk;
    const seq = r.action_sequence.join("  →  ");
    div.innerHTML = `<div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px;">
        <b>${r.target_url}</b>
        <span class="pill ${risk === "high" ? "fail" : risk === "med" ? "warn" : "pass"}">score ${r.score}</span>
      </div>
      <div class="small">${new Date(r.started_at * 1000).toLocaleString()} · ${r.action_count} requests · status: ${r.status}
        ${r.diverted ? ' · <span style="color:var(--amber)">diverted to decoy registry</span>' : ""}
        ${r.canary_triggered ? ' · <span style="color:var(--red)">canary triggered</span>' : ""}</div>
      <div class="threat-seq">${seq || "—"}</div>
      <button class="btn ghost" style="margin-top:10px;" data-run="${r.run_id}">View attack method</button>
      <div class="console method-log" style="display:none;margin-top:10px;"></div>`;
    box.appendChild(div);
    const toggleBtn = div.querySelector("button[data-run]");
    const logEl = div.querySelector(".method-log");
    toggleBtn.onclick = async () => {
      if (logEl.style.display === "block") { logEl.style.display = "none"; return; }
      if (!logEl.dataset.loaded) {
        const res = await fetch("/api/attack/events/" + r.run_id);
        const { events } = await res.json();
        logEl.innerHTML = "";
        events.forEach((e) => addLine(logEl, e.kind, e.text));
        logEl.dataset.loaded = "1";
      }
      logEl.style.display = "block";
    };
  });
}
})();
