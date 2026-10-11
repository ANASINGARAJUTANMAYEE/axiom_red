/* ─── AXIOM RED Dashboard — app.js ──────────────────────────────────
   Handles: scan start, WebSocket live updates, panel rendering,
   🔊 Voice Narration, 📊 Radar Chart, 🕸️ Attack Graph,
   📋 OWASP Scorecard, 🧠 Executive Summary
────────────────────────────────────────────────────────────────── */

const API_BASE = "http://localhost:8000";
let currentSession  = null;
let ws              = null;
let feedCount       = 0;
let state           = null;

// ── 🔊 Voice Narration ──────────────────────────────────────────────
let voiceEnabled = false;
let speechQueue = [];

function toggleVoice() {
  voiceEnabled = !voiceEnabled;
  const btn = document.getElementById("btn-voice");
  btn.textContent = voiceEnabled ? "🔊 Voice" : "🔇 Voice";
  btn.classList.toggle("voice-active", voiceEnabled);
  if (!voiceEnabled && window.speechSynthesis) {
    speechSynthesis.cancel();
  }
}

function speakEvent(log) {
  if (!voiceEnabled || !window.speechSynthesis) return;
  const text = log.thought || log.action || "";
  if (!text || text.length < 5) return;
  // Cancel previous to avoid queue buildup
  speechSynthesis.cancel();
  const utterance = new SpeechSynthesisUtterance(text);
  utterance.rate = 1.05;
  utterance.pitch = 0.75; // deep robotic voice
  utterance.volume = 0.9;
  // Try to use a deep voice
  const voices = speechSynthesis.getVoices();
  const preferred = voices.find(v => v.name.includes("Google") && v.lang.startsWith("en")) || voices.find(v => v.lang.startsWith("en"));
  if (preferred) utterance.voice = preferred;
  speechSynthesis.speak(utterance);
}

// Preload voices
if (window.speechSynthesis) {
  speechSynthesis.getVoices();
  speechSynthesis.onvoiceschanged = () => speechSynthesis.getVoices();
}

// ── Panel navigation ─────────────────────────────────────────────────
function showPanel(name, el) {
  document.querySelectorAll(".panel").forEach(p => {
    p.classList.remove("active");
    p.style.display = "none";
  });
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  const panel = document.getElementById(`panel-${name}`);
  if (panel) { panel.classList.add("active"); panel.style.display = ""; }
  if (el) el.classList.add("active");
}

// ── Start scan ───────────────────────────────────────────────────────
async function startScan() {
  const target = document.getElementById("target-input").value.trim();
  const llm    = document.getElementById("llm-select").value;
  if (!target) return alert("Please enter a target URL.");

  document.getElementById("btn-start").disabled = true;
  document.getElementById("btn-start").textContent = "Launching…";
  document.getElementById("btn-stop").style.display = "inline-flex";
  document.getElementById("live-feed").innerHTML = "";
  feedCount = 0;
  updateFeedBadge();

  try {
    const res = await fetch(`${API_BASE}/api/scan/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, llm_provider: llm })
    });
    const data = await res.json();
    currentSession = data.session_id;

    document.getElementById("topbar-title").textContent = target;
    setStatus("running", "Running");
    connectWS(currentSession);
  } catch (e) {
    document.getElementById("btn-start").disabled = false;
    document.getElementById("btn-start").textContent = "▶ Launch AXIOM RED";
    document.getElementById("btn-stop").style.display = "none";
    setStatus("idle", "Ready");

    let banner = document.getElementById("backend-error-banner");
    if (!banner) {
      banner = document.createElement("div");
      banner.id = "backend-error-banner";
      banner.style.cssText = `
        background: rgba(255,58,58,0.1);
        border: 1px solid rgba(255,58,58,0.4);
        border-radius: 10px;
        padding: 14px 18px;
        margin-top: 12px;
        font-size: 13px;
        line-height: 1.6;
        color: #ff8080;
      `;
      document.querySelector(".scan-form").appendChild(banner);
    }
    banner.innerHTML = `
      ⚠️ <strong>Backend not running</strong> — No server found on port 8000.<br>
      👉 Click <strong style="color:#fff">"▷ Run Demo"</strong> below to see the full demo without any setup.
    `;
  }
}

function stopScan() {
  if (ws) ws.close();
  setStatus("idle", "Stopped");
  document.getElementById("btn-stop").style.display = "none";
  document.getElementById("btn-start").disabled = false;
  document.getElementById("btn-start").textContent = "▶ Launch AXIOM RED";
}

// ── WebSocket ─────────────────────────────────────────────────────────
function connectWS(sessionId) {
  const wsUrl = `ws://localhost:8000/ws/${sessionId}`;
  ws = new WebSocket(wsUrl);

  ws.onmessage = (evt) => {
    const msg = JSON.parse(evt.data);
    if (msg.type === "state_update" || msg.type === "done") {
      state = msg.data;
      renderState(state);
      if (msg.type === "done") onDone(state);
    } else if (msg.type === "error") {
      appendFeedEvent({ phase: "ERROR", action: msg.message, status: "error" });
      setStatus("error", "Error");
    }
  };

  ws.onerror = () => {
    appendFeedEvent({ phase: "WS", action: "WebSocket error — check backend", status: "error" });
  };
}

// ── Render entire state ───────────────────────────────────────────────
function renderState(s) {
  updatePhases(s.phase_complete, s.current_phase);
  updateTopbarPhase(s.current_phase);

  const findings = s.findings || [];
  document.getElementById("stat-critical").textContent = findings.filter(f => f.severity === "Critical").length;
  document.getElementById("stat-high").textContent     = findings.filter(f => f.severity === "High").length;
  document.getElementById("stat-medium").textContent   = findings.filter(f => f.severity === "Medium").length;
  document.getElementById("stat-low").textContent      = findings.filter(f => f.severity === "Low").length;
  document.getElementById("stat-ports").textContent    = (s.open_ports || []).length;
  document.getElementById("stat-endpoints").textContent = (s.web_endpoints || []).length;

  const logs = s.activity_log || [];
  const feedEl = document.getElementById("live-feed");
  if (feedEl.querySelector(".feed-empty")) feedEl.innerHTML = "";

  if (logs.length > feedCount) {
    logs.slice(feedCount).forEach(log => {
      appendFeedEvent(log);
      speakEvent(log);  // 🔊 Voice narration
    });
    feedCount = logs.length;
    updateFeedBadge();
  }

  renderRecon(s);
  renderFindings(findings);
  renderLogs(logs);
  renderRadarChart(s.risk_scores || {});
  renderAttackGraph(s.attack_chains || [], findings);
  renderOWASPScorecard(findings);
  renderXSSPanel(findings);
  terminalAppendNew(logs);

  // Executive summary
  if (s.executive_summary) {
    const card = document.getElementById("exec-summary-card");
    card.style.display = "block";
    document.getElementById("exec-summary-text").textContent = s.executive_summary;
  }
}

// ── Phase steps ───────────────────────────────────────────────────────
function updatePhases(phaseComplete, currentPhase) {
  const phases = ["RECON","ANALYSE","PLAN","TEST","VALIDATE","REPORT"];
  phases.forEach(p => {
    const el = document.getElementById(`phase-${p}`);
    if (!el) return;
    el.classList.remove("active","done");
    const statusEl = el.querySelector(".phase-status");
    if (phaseComplete && phaseComplete[p]) {
      el.classList.add("done");
      statusEl.textContent = "done";
    } else if (currentPhase === p) {
      el.classList.add("active");
      statusEl.textContent = "running…";
    } else {
      statusEl.textContent = "pending";
    }
  });
}

function updateTopbarPhase(phase) {
  const badge = document.getElementById("topbar-phase");
  badge.textContent = phase || "IDLE";
  badge.className = `topbar-badge phase-${(phase||"").toLowerCase()}`;
}

// ── Live feed event ───────────────────────────────────────────────────
function appendFeedEvent(log) {
  const feed = document.getElementById("live-feed");
  const div  = document.createElement("div");
  div.className = `feed-event status-${log.status || "ok"}`;

  const ts = log.timestamp ? log.timestamp.substring(11,19) : now();
  div.innerHTML = `
    <div class="event-phase phase-col-${log.phase}">${log.phase || ""}</div>
    <div class="event-content">
      ${log.thought ? `<div class="event-thought">💭 ${escHtml(log.thought)}</div>` : ""}
      <div class="event-action">⚡ ${escHtml(log.action || "")}</div>
      ${log.result ? `<div class="event-result">${escHtml(log.result)}</div>` : ""}
    </div>
    <div class="event-time">${ts}</div>
  `;
  feed.appendChild(div);
  feed.scrollTop = feed.scrollHeight;
}

function updateFeedBadge() {
  document.getElementById("feed-badge").textContent = `${feedCount} events`;
}

// ── Recon panel ───────────────────────────────────────────────────────
function renderRecon(s) {
  const ports = s.open_ports || [];
  const techs = s.technologies || [];
  const eps   = s.web_endpoints || [];

  const portsList = document.getElementById("ports-list");
  portsList.innerHTML = ports.length
    ? ports.map(p => `
        <div class="mono-item port-item">
          <span style="color:var(--low);font-weight:700">${p.port}</span>
          <span style="color:var(--muted)">/tcp</span>
          <span>${p.service || "unknown"}</span>
          ${p.state === "open" ? '<span style="color:var(--success);margin-left:auto;font-size:10px">OPEN</span>' : ""}
        </div>
      `).join("")
    : '<div style="color:var(--muted);font-size:13px">Waiting for recon…</div>';

  const techList = document.getElementById("tech-list");
  techList.innerHTML = techs.length
    ? techs.map(t => `<div class="mono-item tech-item">${escHtml(t)}</div>`).join("")
    : '<div style="color:var(--muted);font-size:13px">No data yet</div>';

  const epList = document.getElementById("endpoints-list");
  epList.innerHTML = eps.length
    ? eps.map(e => `<div class="mono-item endpoint-item">${escHtml(e)}</div>`).join("")
    : '<div style="color:var(--muted);font-size:13px">No data yet</div>';
}

// ── Findings panel ────────────────────────────────────────────────────
const CVSS_COLORS = { Critical:"#ff3a3a", High:"#ff8c00", Medium:"#ffd600", Low:"#4da6ff", Info:"#a0aacc" };

function renderFindings(findings) {
  const container = document.getElementById("findings-list");
  if (!findings.length) {
    container.innerHTML = '<div class="empty-state">No findings confirmed yet.</div>';
    return;
  }
  container.innerHTML = findings.map((f, i) => `
    <div class="finding-card" id="finding-${i}">
      <div class="finding-head" onclick="toggleFinding(${i})">
        <span class="finding-num">F-${String(i+1).padStart(3,"0")}</span>
        <span class="sev-pill sev-${f.severity}">${f.severity}</span>
        ${f.owasp_category ? `<span class="owasp-pill">${escHtml(f.owasp_category)}</span>` : ""}
        <span class="finding-title-text">${escHtml(f.title)}</span>
        <span class="cvss-num" style="color:${CVSS_COLORS[f.severity]||"#aaa"}">${f.cvss_score}</span>
      </div>
      <div class="finding-body">
        <div class="finding-section">
          <h5>Description</h5>
          <p>${escHtml(f.description)}</p>
        </div>
        <div class="finding-section">
          <h5>Endpoint</h5>
          <pre class="code-block">${escHtml(f.method)} ${escHtml(f.endpoint)}</pre>
        </div>
        ${f.payload ? `
        <div class="finding-section">
          <h5>Payload</h5>
          <pre class="code-block">${escHtml(f.payload)}</pre>
        </div>` : ""}
        ${f.evidence ? `
        <div class="finding-section">
          <h5>Evidence</h5>
          <pre class="code-block">${escHtml(f.evidence)}</pre>
        </div>` : ""}
        ${f.poc_curl ? `
        <div class="finding-section">
          <h5>🧪 Proof of Concept</h5>
          <pre class="code-block poc-block" onclick="navigator.clipboard.writeText(this.textContent).then(()=>this.classList.add('copied'))" title="Click to copy">${escHtml(f.poc_curl)}</pre>
        </div>` : ""}
        <div class="finding-section">
          <h5>Remediation</h5>
          <ul class="remediation-steps">
            ${f.remediation.split("\n").filter(l=>l.trim()).map(l =>
              `<li>${escHtml(l.replace(/^\d+\.\s*/,"").replace(/^→\s*/,""))}</li>`
            ).join("")}
          </ul>
        </div>
      </div>
    </div>
  `).join("");
}

function toggleFinding(i) {
  document.getElementById(`finding-${i}`).classList.toggle("expanded");
}

// ── 📊 Risk Radar Chart ──────────────────────────────────────────────
function renderRadarChart(scores) {
  const canvas = document.getElementById("radar-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  const cx = W / 2, cy = H / 2;
  const R = Math.min(cx, cy) - 40;

  ctx.clearRect(0, 0, W, H);

  const labels = Object.keys(scores);
  const values = Object.values(scores);
  const n = labels.length || 6;
  const angleStep = (2 * Math.PI) / n;

  // Draw grid rings
  for (let ring = 1; ring <= 5; ring++) {
    const r = (ring / 5) * R;
    ctx.beginPath();
    for (let i = 0; i <= n; i++) {
      const angle = i * angleStep - Math.PI / 2;
      const x = cx + r * Math.cos(angle);
      const y = cy + r * Math.sin(angle);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    }
    ctx.closePath();
    ctx.strokeStyle = "rgba(255,255,255,0.08)";
    ctx.lineWidth = 1;
    ctx.stroke();
  }

  // Draw axis lines and labels
  labels.forEach((label, i) => {
    const angle = i * angleStep - Math.PI / 2;
    const lx = cx + (R + 20) * Math.cos(angle);
    const ly = cy + (R + 20) * Math.sin(angle);

    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + R * Math.cos(angle), cy + R * Math.sin(angle));
    ctx.strokeStyle = "rgba(255,255,255,0.1)";
    ctx.stroke();

    ctx.fillStyle = "#8892a4";
    ctx.font = "10px Inter, sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(label, lx, ly);
  });

  // Draw data polygon
  if (values.some(v => v > 0)) {
    ctx.beginPath();
    values.forEach((val, i) => {
      const r = (Math.min(val, 10) / 10) * R;
      const angle = i * angleStep - Math.PI / 2;
      const x = cx + r * Math.cos(angle);
      const y = cy + r * Math.sin(angle);
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.closePath();

    const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, R);
    grad.addColorStop(0, "rgba(224, 16, 48, 0.4)");
    grad.addColorStop(1, "rgba(255, 45, 85, 0.15)");
    ctx.fillStyle = grad;
    ctx.fill();
    ctx.strokeStyle = "#e01030";
    ctx.lineWidth = 2;
    ctx.stroke();

    // Draw data points
    values.forEach((val, i) => {
      const r = (Math.min(val, 10) / 10) * R;
      const angle = i * angleStep - Math.PI / 2;
      const x = cx + r * Math.cos(angle);
      const y = cy + r * Math.sin(angle);
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fillStyle = "#ff2d55";
      ctx.fill();
      ctx.strokeStyle = "#fff";
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });
  }
}

// ── 🕸️ Attack Chain Graph ────────────────────────────────────────────
function renderAttackGraph(chains, findings) {
  const canvas = document.getElementById("attack-graph-canvas");
  const emptyEl = document.getElementById("graph-empty");
  if (!canvas) return;

  if (!chains || chains.length === 0) {
    if (emptyEl) emptyEl.style.display = "block";
    return;
  }
  if (emptyEl) emptyEl.style.display = "none";

  canvas.width = canvas.parentElement.clientWidth || 900;
  canvas.height = 480;
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  // Collect unique nodes
  const nodeSet = new Set();
  chains.forEach(c => {
    nodeSet.add(c.from_node);
    nodeSet.add(c.to_node);
  });
  const nodes = [...nodeSet];

  // Position nodes in a circle
  const cx = W / 2, cy = H / 2;
  const R = Math.min(W, H) / 2 - 80;
  const nodePositions = {};
  nodes.forEach((name, i) => {
    const angle = (i / nodes.length) * 2 * Math.PI - Math.PI / 2;
    nodePositions[name] = {
      x: cx + R * Math.cos(angle),
      y: cy + R * Math.sin(angle),
      name: name
    };
  });

  // Draw edges with arrows
  chains.forEach(chain => {
    const from = nodePositions[chain.from_node];
    const to = nodePositions[chain.to_node];
    if (!from || !to) return;

    const dx = to.x - from.x, dy = to.y - from.y;
    const dist = Math.sqrt(dx*dx + dy*dy);
    const nx = dx / dist, ny = dy / dist;
    const sx = from.x + nx * 30, sy = from.y + ny * 30;
    const ex = to.x - nx * 30, ey = to.y - ny * 30;

    // Line
    ctx.beginPath();
    ctx.moveTo(sx, sy);
    ctx.lineTo(ex, ey);
    ctx.strokeStyle = "rgba(224, 16, 48, 0.6)";
    ctx.lineWidth = 2;
    ctx.stroke();

    // Arrow head
    const arrowSize = 10;
    const angle = Math.atan2(ey - sy, ex - sx);
    ctx.beginPath();
    ctx.moveTo(ex, ey);
    ctx.lineTo(ex - arrowSize * Math.cos(angle - 0.4), ey - arrowSize * Math.sin(angle - 0.4));
    ctx.lineTo(ex - arrowSize * Math.cos(angle + 0.4), ey - arrowSize * Math.sin(angle + 0.4));
    ctx.closePath();
    ctx.fillStyle = "#e01030";
    ctx.fill();

    // Edge label
    const midX = (sx + ex) / 2, midY = (sy + ey) / 2;
    ctx.fillStyle = "#7c839e";
    ctx.font = "9px Inter, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText(chain.label || "", midX, midY - 8);
  });

  // Draw nodes
  nodes.forEach(name => {
    const pos = nodePositions[name];
    const finding = findings.find(f => f.title === name);
    const color = finding ? (CVSS_COLORS[finding.severity] || "#aaa") : "#555";

    // Glow
    ctx.beginPath();
    ctx.arc(pos.x, pos.y, 28, 0, Math.PI * 2);
    ctx.fillStyle = color + "22";
    ctx.fill();

    // Circle
    ctx.beginPath();
    ctx.arc(pos.x, pos.y, 22, 0, Math.PI * 2);
    ctx.fillStyle = "#12151f";
    ctx.fill();
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // Severity icon
    const sev = finding ? finding.severity[0] : "?";
    ctx.fillStyle = color;
    ctx.font = "bold 14px JetBrains Mono, monospace";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(sev, pos.x, pos.y);

    // Label
    const shortName = name.length > 20 ? name.substring(0, 18) + "…" : name;
    ctx.fillStyle = "#e8eaf2";
    ctx.font = "11px Inter, sans-serif";
    ctx.fillText(shortName, pos.x, pos.y + 38);
  });
}

// ── 📋 OWASP Top 10 Scorecard ────────────────────────────────────────
const OWASP_TOP_10 = [
  { id: "A01", name: "A01:2021 Broken Access Control" },
  { id: "A02", name: "A02:2021 Cryptographic Failures" },
  { id: "A03", name: "A03:2021 Injection" },
  { id: "A04", name: "A04:2021 Insecure Design" },
  { id: "A05", name: "A05:2021 Security Misconfiguration" },
  { id: "A06", name: "A06:2021 Vulnerable Components" },
  { id: "A07", name: "A07:2021 Auth Failures" },
  { id: "A08", name: "A08:2021 Data Integrity Failures" },
  { id: "A09", name: "A09:2021 Logging Failures" },
  { id: "A10", name: "A10:2021 SSRF" },
];

function renderOWASPScorecard(findings) {
  const tbody = document.getElementById("owasp-tbody");
  if (!tbody) return;

  let passCount = 0;
  let failCount = 0;
  let naCount = 0;

  tbody.innerHTML = OWASP_TOP_10.map(cat => {
    const matched = findings.filter(f => f.owasp_id === cat.id);
    let status, statusClass, statusIcon;
    if (matched.length > 0) {
      status = "FAIL";
      statusClass = "owasp-fail";
      statusIcon = "🔴";
      failCount++;
    } else if (findings.length > 0) {
      status = "PASS";
      statusClass = "owasp-pass";
      statusIcon = "🟢";
      passCount++;
    } else {
      status = "N/A";
      statusClass = "owasp-na";
      statusIcon = "⚪";
      naCount++;
    }

    const maxCvss = matched.length ? Math.max(...matched.map(f => f.cvss_score)) : "—";
    const findingNames = matched.map(f => f.title).join(", ") || "—";

    return `<tr class="${statusClass}">
      <td class="owasp-cat-name">${cat.name}</td>
      <td class="owasp-status">${statusIcon} ${status}</td>
      <td class="owasp-findings">${escHtml(findingNames)}</td>
      <td class="owasp-cvss">${maxCvss}</td>
    </tr>`;
  }).join("");

  // Score bar
  const total = OWASP_TOP_10.length;
  const scoreBar = document.getElementById("owasp-score-bar");
  if (scoreBar && findings.length > 0) {
    const pct = Math.round((passCount / total) * 100);
    scoreBar.innerHTML = `
      <div class="score-label">${pct}% Compliant (${passCount}/${total} categories passed)</div>
      <div class="score-track">
        <div class="score-fill" style="width:${pct}%;background:${pct > 70 ? '#00e676' : pct > 40 ? '#ffd600' : '#ff3a3a'}"></div>
      </div>
      <div class="score-details">
        <span style="color:#ff3a3a">🔴 ${failCount} Failed</span>
        <span style="color:#00e676">🟢 ${passCount} Passed</span>
      </div>
    `;
  }
}

// ── Log panel ─────────────────────────────────────────────────────────
function renderLogs(logs) {
  const container = document.getElementById("log-list");
  if (!logs.length) {
    container.innerHTML = '<div class="empty-state">Activity log will appear during engagement.</div>';
    return;
  }
  container.innerHTML = logs.map(log => `
    <div class="log-row">
      <div class="log-phase-tag phase-col-${log.phase}">${log.phase}</div>
      <div class="log-body">
        ${log.thought ? `<div class="log-thought">💭 ${escHtml(log.thought)}</div>` : ""}
        <div class="log-action-text">⚡ ${escHtml(log.action||"")}</div>
        ${log.result ? `<div class="log-result-text">${escHtml(log.result)}</div>` : ""}
      </div>
      <div class="log-ts">${(log.timestamp||"").substring(11,19)}</div>
    </div>
  `).join("");
  container.scrollTop = container.scrollHeight;
}

// ── Done ──────────────────────────────────────────────────────────────
function onDone(s) {
  setStatus("done", "Complete");
  document.getElementById("btn-stop").style.display = "none";
  document.getElementById("btn-start").disabled = false;
  document.getElementById("btn-start").textContent = "▶ Launch AXIOM RED";

  if (s.report_path) {
    const reportUrl = `${API_BASE}/api/report/${s.session_id}`;
    const btnReport = document.getElementById("btn-report");
    btnReport.href = reportUrl;
    btnReport.style.display = "inline-flex";

    const frameContainer = document.getElementById("report-frame-container");
    frameContainer.innerHTML = `<iframe src="${reportUrl}" title="AXIOM RED Report"></iframe>`;
  }

  appendFeedEvent({
    phase: "REPORT",
    action: "🎯 Engagement complete! " + (s.findings||[]).length + " finding(s) identified.",
    result: s.report_path ? "Report generated — click 'View Report' in the top bar" : "",
    status: "finding"
  });

  // Announce completion via voice
  if (voiceEnabled) {
    speakEvent({ thought: `Engagement complete. ${(s.findings||[]).length} vulnerabilities identified.` });
  }
}

// ── Status ────────────────────────────────────────────────────────────
function setStatus(type, text) {
  const dot  = document.getElementById("status-dot");
  const span = document.getElementById("status-text");
  dot.className = `status-dot ${type}`;
  span.textContent = text;
}

// ── Helpers ───────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
function now() {
  return new Date().toTimeString().slice(0,8);
}

// ── Demo / Offline mode ──────────────────────────────────────────────
function runDemoMode() {
  const demoState = {
    session_id: "demo-abc123",
    target: "http://localhost:5000",
    current_phase: "VALIDATE",
    phase_complete: { RECON:true, ANALYSE:true, PLAN:true, TEST:true, VALIDATE:false, REPORT:false },
    open_ports: [
      { port:5000, service:"HTTP-Flask", state:"open" },
      { port:6379, service:"Redis", state:"open" },
      { port:3306, service:"MySQL", state:"open" },
      { port:8080, service:"HTTP-Alt", state:"open" },
    ],
    web_endpoints: [
      "http://localhost:5000/ [200]",
      "http://localhost:5000/api/v1/users/1 [200]",
      "http://localhost:5000/api/v1/search [200]",
      "http://localhost:5000/api/v1/admin [401]",
      "http://localhost:5000/api/v1/config [200]",
      "http://localhost:5000/api/v1/ping [200]",
      "http://localhost:5000/api/v1/upload [200]",
    ],
    technologies: [
      "Server: Werkzeug/3.0 Python/3.11",
      "Framework: Flask",
      "Auth: JWT detected in response",
      "API Docs: Swagger/OpenAPI"
    ],
    services: [{ service:"Redis", detail:{ status:"OPEN — NO AUTH", rce_vector:true } }],
    risk_scores: {
      "Authentication": 7.4, "Injection": 10.0, "Configuration": 10.0,
      "Encryption": 7.4, "Access Control": 6.0, "Data Exposure": 9.2
    },
    attack_chains: [
      { from_node: "Sensitive Configuration Exposure", to_node: "JWT Algorithm Confusion", label: "leaks JWT secret" },
      { from_node: "JWT Algorithm Confusion", to_node: "IDOR", label: "forges admin token" },
      { from_node: "OS Command Injection", to_node: "Unauthenticated Redis", label: "lateral movement" },
      { from_node: "SQL Injection", to_node: "IDOR", label: "extracts user IDs" },
      { from_node: "Unauthenticated Redis", to_node: "OS Command Injection", label: "RCE via cron" },
    ],
    executive_summary: "A comprehensive penetration test was conducted against the target application at http://localhost:5000. The assessment revealed critical security deficiencies across multiple domains, resulting in an overall Critical risk rating. Six vulnerabilities were identified, including four Critical and two High severity findings.\n\nThe discovered vulnerabilities present severe business risks. An attacker could achieve full remote code execution through unauthenticated Redis access, extract all customer personally identifiable information (including SSNs and credit card numbers) via IDOR and SQL injection attacks, and gain unrestricted administrative access through JWT authentication bypass. These findings could result in significant financial penalties under GDPR (up to 4% of annual revenue) and PCI-DSS non-compliance.\n\nImmediate actions required: (1) Disable external Redis access and enforce authentication, (2) Implement parameterized database queries across all endpoints, (3) Enforce JWT signature verification with explicit algorithm whitelisting, (4) Deploy object-level authorization on all user data endpoints. A follow-up assessment is recommended within 30 days of remediation.",
    findings: [
      {
        title:"Unauthenticated Redis — Remote Code Execution Vector",
        severity:"Critical", cvss_score:9.8,
        description:"Redis is accessible without authentication. Attacker can dump all keys, achieve RCE via CONFIG SET, or write SSH authorized_keys for persistent backdoor.",
        endpoint:"redis://localhost:6379", method:"TCP",
        payload:"redis-cli SET AXIOM_RED_RCE_PROOF 'rce_confirmed'",
        evidence:"Key written and read back: rce_confirmed",
        remediation:"1. Set requirepass in redis.conf.\n2. Bind to 127.0.0.1 only.\n3. Rename CONFIG command.\n4. Run as low-privilege user.\n5. Apply firewall rules.",
        owasp_id:"A05", owasp_category:"A05:2021 Security Misconfiguration",
        poc_curl:"redis-cli -h localhost -p 6379 SET test_key pwned"
      },
      {
        title:"OS Command Injection",
        severity:"Critical", cvss_score:9.8,
        description:"Unsanitised 'host' parameter passed to shell in /api/v1/ping. OS command output visible in response.",
        endpoint:"http://localhost:5000/api/v1/ping", method:"GET",
        payload:"127.0.0.1; id",
        evidence:"uid=1000(www-data) gid=1000(www-data) groups=1000(www-data)",
        remediation:"1. Never pass user input to shell.\n2. Use subprocess with shell=False.\n3. Apply strict allow-list input validation.\n4. Run as non-root user.",
        owasp_id:"A03", owasp_category:"A03:2021 Injection",
        poc_curl:'curl -s "http://localhost:5000/api/v1/ping?host=127.0.0.1;id"'
      },
      {
        title:"JWT Algorithm Confusion",
        severity:"Critical", cvss_score:9.3,
        description:"API accepts JWTs with 'alg:none', bypassing signature verification. Attacker can forge any identity including admin role.",
        endpoint:"http://localhost:5000/api/v1/admin", method:"GET",
        payload:"eyJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4ifQ.",
        evidence:'{"message":"Welcome to the admin panel","all_users":[...full PII dumped...]}',
        remediation:"1. Reject 'none' algorithm.\n2. Use jwt.decode() with algorithms=['HS256'] only.\n3. Rotate JWT secret.\n4. Consider RS256 asymmetric signing.",
        owasp_id:"A02", owasp_category:"A02:2021 Cryptographic Failures",
        poc_curl:'curl -s -H "Authorization: Bearer eyJhbGciOiJub25lIn0..." "http://localhost:5000/api/v1/admin"'
      },
      {
        title:"SQL Injection",
        severity:"Critical", cvss_score:9.1,
        description:"SQL Injection via error-based technique in parameter 'q' at /api/v1/search.",
        endpoint:"http://localhost:5000/api/v1/search", method:"GET",
        payload:"' OR '1'='1",
        evidence:"OperationalError: unrecognized token",
        remediation:"1. Use parameterised queries exclusively.\n2. Never concatenate user input into SQL.\n3. Apply input validation.\n4. Enable WAF with SQL rules.",
        owasp_id:"A03", owasp_category:"A03:2021 Injection",
        poc_curl:`curl -s "http://localhost:5000/api/v1/search?q=' OR '1'='1"`
      },
      {
        title:"IDOR",
        severity:"High", cvss_score:7.5,
        description:"Sequential user IDs expose SSN and credit card data without authentication.",
        endpoint:"http://localhost:5000/api/v1/users/<id>", method:"GET",
        payload:"IDs: 1,2,3,4,5",
        evidence:'{"id":2,"name":"alice","ssn":"123-45-6789","credit_card":"4222222222222222"}',
        remediation:"1. Enforce object-level authorisation.\n2. Replace integer IDs with UUIDs.\n3. Validate user owns the resource.\n4. Apply RBAC middleware.",
        owasp_id:"A01", owasp_category:"A01:2021 Broken Access Control",
        poc_curl:'curl -s "http://localhost:5000/api/v1/users/1"'
      },
      {
        title:"Sensitive Configuration Exposure",
        severity:"High", cvss_score:7.7,
        description:"Unauthenticated /api/v1/config endpoint exposes database credentials, JWT secret, and internal API keys.",
        endpoint:"http://localhost:5000/api/v1/config", method:"GET",
        payload:"None (unauthenticated GET)",
        evidence:'{"db_pass":"p@ssw0rd","jwt_secret":"supersecret123"}',
        remediation:"1. Remove /config from production.\n2. Require auth for diagnostic endpoints.\n3. Use a secrets manager.\n4. Store secrets in environment variables.",
        owasp_id:"A05", owasp_category:"A05:2021 Security Misconfiguration",
        poc_curl:'curl -s "http://localhost:5000/api/v1/config"'
      },
    ],
    activity_log: [
      { phase:"RECON",    timestamp:"2026-01-01T10:00:01", thought:"Starting recon on http://localhost:5000. I'll scan ports first.", action:"Port scan + endpoint discovery", result:"Found 4 open ports: [5000, 6379, 3306, 8080]", status:"finding" },
      { phase:"RECON",    timestamp:"2026-01-01T10:00:05", thought:null, action:"Redis unauthenticated probe", result:"CRITICAL: Redis open with NO AUTH — RCE vector confirmed", status:"finding" },
      { phase:"RECON",    timestamp:"2026-01-01T10:00:09", thought:null, action:"Endpoint discovery complete", result:"Found 7 live endpoints", status:"ok" },
      { phase:"ANALYSE",  timestamp:"2026-01-01T10:00:15", thought:"I see unauthenticated Redis, an exposed /config endpoint, and a JWT-protected admin panel. Redis is the highest priority — RCE is possible.", action:"LLM attack surface analysis", result:"Risk level: Critical. High-value: Redis, /api/v1/ping, /api/v1/admin", status:"finding" },
      { phase:"PLAN",     timestamp:"2026-01-01T10:00:20", thought:"I'll test Redis first for maximum impact, then cmd injection, config exposure, JWT bypass, SQLi, and IDOR.", action:"Attack plan generated", result:"Plan: [redis_rce, cmd_injection, config_exposure, jwt_none, sqli, idor]", status:"ok" },
      { phase:"TEST",     timestamp:"2026-01-01T10:00:25", thought:"Unauthenticated Redis is a critical misconfiguration — testing RCE via config rewrite.", action:"Testing: redis_rce", result:"[Critical] Unauthenticated Redis — Remote Code Execution Vector", status:"finding" },
      { phase:"TEST",     timestamp:"2026-01-01T10:00:30", thought:"Ping endpoint likely uses shell — testing command injection.", action:"Testing: cmd_injection on /api/v1/ping", result:"[Critical] OS Command Injection confirmed — uid=1000(www-data)", status:"finding" },
      { phase:"TEST",     timestamp:"2026-01-01T10:00:35", thought:null, action:"Testing: config_exposure on /api/v1/config", result:"[High] Sensitive config exposed — JWT secret, DB password, API keys", status:"finding" },
      { phase:"TEST",     timestamp:"2026-01-01T10:00:40", thought:"Admin panel visible — forging JWT with alg:none.", action:"Testing: jwt_none on /api/v1/admin", result:"[Critical] JWT alg:none bypass — full admin access gained", status:"finding" },
      { phase:"TEST",     timestamp:"2026-01-01T10:00:45", thought:null, action:"Testing: sqli on /api/v1/search param q", result:"[Critical] SQL Injection confirmed — DB error returned", status:"finding" },
      { phase:"TEST",     timestamp:"2026-01-01T10:00:50", thought:null, action:"Testing: idor on /api/v1/users/<id>", result:"[High] IDOR confirmed — SSN + credit card exposed for IDs 1-5", status:"finding" },
      { phase:"VALIDATE", timestamp:"2026-01-01T10:01:00", thought:"Chain: Redis RCE → full OS access. IDOR + SQLi → all PII. JWT bypass → admin panel. This is a catastrophic attack surface.", action:"Finding validation and chain analysis complete", result:"Overall risk: Critical. Chain: Redis→OS→lateral movement; IDOR+SQLi→data breach; JWT→admin", status:"finding" },
    ],
    done: false,
    report_path: null
  };

  document.getElementById("target-input").value = demoState.target;
  document.getElementById("topbar-title").textContent = demoState.target;
  setStatus("running", "Demo Mode");

  let i = 0;
  function stepDemo() {
    if (i >= demoState.activity_log.length) {
      demoState.done = true;
      demoState.phase_complete.VALIDATE = true;
      demoState.phase_complete.REPORT = true;
      demoState.current_phase = "DONE";
      renderState(demoState);
      setStatus("done", "Demo Complete");
      document.getElementById("btn-start").disabled = false;
      document.getElementById("btn-start").textContent = "▶ Launch AXIOM RED";
      document.getElementById("btn-stop").style.display = "none";
      return;
    }
    demoState.current_phase = demoState.activity_log[i].phase;
    const phases = ["RECON","ANALYSE","PLAN","TEST","VALIDATE","REPORT"];
    const idx = phases.indexOf(demoState.current_phase);
    phases.slice(0, idx).forEach(p => { demoState.phase_complete[p] = true; });

    renderState(demoState);
    i++;
    setTimeout(stepDemo, 800);
  }

  document.getElementById("btn-start").disabled = true;
  document.getElementById("btn-start").textContent = "Running Demo…";
  document.getElementById("btn-stop").style.display = "inline-flex";
  document.getElementById("live-feed").innerHTML = "";
  feedCount = 0;

  stepDemo();
}

// Expose demo mode button
window.addEventListener("DOMContentLoaded", () => {
  const scanCard = document.querySelector(".scan-form");
  if (scanCard) {
    const demoBtn = document.createElement("button");
    demoBtn.className = "btn btn-ghost";
    demoBtn.style.cssText = "text-align:center;justify-content:center;width:100%;margin-top:-8px;";
    demoBtn.textContent = "\u25b7 Run Demo (no backend required)";
    demoBtn.onclick = runDemoMode;
    scanCard.appendChild(demoBtn);
  }

  // Initialize panels (hide XSS initially)
  document.querySelectorAll(".panel").forEach(p => {
    if (!p.classList.contains("active")) p.style.display = "none";
  });

  // Initialize OWASP scorecard
  renderOWASPScorecard([]);
  // Initialize radar with zeros
  renderRadarChart({ "Authentication":0, "Injection":0, "Configuration":0, "Encryption":0, "Access Control":0, "Data Exposure":0 });
});

// ── 🌙 TERMINAL HACKER VIEW ──────────────────────────────────────────
let terminalOpen   = false;
let matrixAnimId   = null;
let terminalLineCount = 0;

function toggleTerminalView() {
  const overlay = document.getElementById("terminal-overlay");
  terminalOpen = !terminalOpen;
  overlay.style.display = terminalOpen ? "flex" : "none";
  const btn = document.getElementById("btn-terminal");
  btn.textContent = terminalOpen ? "\u274c Close Terminal" : "\ud83c\udf19 Terminal";
  btn.classList.toggle("terminal-active", terminalOpen);

  if (terminalOpen) {
    startMatrixRain();
    syncTerminalFromState();
  } else {
    if (matrixAnimId) { cancelAnimationFrame(matrixAnimId); matrixAnimId = null; }
  }
}

// Matrix rain animation
function startMatrixRain() {
  const canvas = document.getElementById("matrix-canvas");
  const ctx    = canvas.getContext("2d");
  canvas.width  = window.innerWidth;
  canvas.height = window.innerHeight;

  const CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*(){}[]<>?/\\|+=-_`~;:!.,'\"";
  const FONT_SIZE = 14;
  const cols = Math.floor(canvas.width / FONT_SIZE);
  const drops = Array(cols).fill(1);

  function frame() {
    ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    drops.forEach((y, i) => {
      const char = CHARS[Math.floor(Math.random() * CHARS.length)];
      // Leading char bright green, trail darker
      const isHead = Math.random() > 0.95;
      ctx.fillStyle = isHead ? "#ffffff" : (Math.random() > 0.5 ? "#00ff41" : "#00cc33");
      ctx.font = `${FONT_SIZE}px 'JetBrains Mono', monospace`;
      ctx.fillText(char, i * FONT_SIZE, y * FONT_SIZE);
      if (y * FONT_SIZE > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    });
    matrixAnimId = requestAnimationFrame(frame);
  }
  if (matrixAnimId) cancelAnimationFrame(matrixAnimId);
  frame();

  // Resize handler
  window._matrixResize = () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  };
  window.addEventListener("resize", window._matrixResize);
}

// Typewriter line printer for terminal
function terminalPrint(text, cls = "", delay = 0) {
  const container = document.getElementById("terminal-lines");
  if (!container) return;

  setTimeout(() => {
    const line = document.createElement("div");
    line.className = `tline ${cls}`;

    // Typewrite the text
    let i = 0;
    line.textContent = "";
    container.appendChild(line);
    const body = document.getElementById("terminal-body");
    body.scrollTop = body.scrollHeight;

    const type = () => {
      if (i < text.length) {
        line.textContent += text[i++];
        body.scrollTop = body.scrollHeight;
        setTimeout(type, Math.random() * 12 + 4);
      }
    };
    type();
  }, delay);
}

// Sync all existing log events to terminal on open
function syncTerminalFromState() {
  const container = document.getElementById("terminal-lines");
  if (!container) return;
  container.innerHTML = "";
  terminalLineCount = 0;

  if (!state || !state.activity_log || !state.activity_log.length) {
    terminalPrint("[AXIOM RED] No active engagement. Run a scan to begin.", "tline-muted");
    return;
  }

  terminalPrint(`[AXIOM RED] Loaded session: ${state.session_id || "demo"}`, "tline-ok", 0);
  terminalPrint(`[AXIOM RED] Target: ${state.target}`, "tline-ok", 100);
  terminalPrint(`[AXIOM RED] Findings confirmed: ${(state.findings||[]).length}`, "tline-ok", 200);
  terminalPrint("─".repeat(80), "tline-dim", 300);

  (state.activity_log || []).forEach((log, idx) => {
    const prefix = `[${log.phase}]`;
    const ts     = (log.timestamp || "").substring(11, 19);
    const cls    = log.status === "finding" ? "tline-finding" :
                   log.status === "error"   ? "tline-error"   : "tline-ok";
    const baseDelay = 350 + idx * 120;

    if (log.thought) {
      terminalPrint(`${prefix} >> ${log.thought}`, "tline-thought", baseDelay);
    }
    terminalPrint(
      `${prefix} ACTION: ${log.action}${log.result ? "  |  " + log.result : ""}`,
      cls, baseDelay + 60
    );
  });

  terminalLineCount = (state.activity_log || []).length;
}

// Called on each new state update to add new lines only
function terminalAppendNew(logs) {
  if (!terminalOpen) return;
  const newLogs = logs.slice(terminalLineCount);
  newLogs.forEach((log, idx) => {
    const prefix   = `[${log.phase}]`;
    const cls      = log.status === "finding" ? "tline-finding" :
                     log.status === "error"   ? "tline-error"   : "tline-ok";
    const baseDelay = idx * 150;
    if (log.thought) terminalPrint(`${prefix} >> ${log.thought}`, "tline-thought", baseDelay);
    terminalPrint(
      `${prefix} ACTION: ${log.action}${log.result ? "  |  " + log.result : ""}`,
      cls, baseDelay + 60
    );
  });
  terminalLineCount = logs.length;
}

// Keyboard shortcut: F2 = toggle terminal
document.addEventListener("keydown", (e) => {
  if (e.key === "F2") { e.preventDefault(); toggleTerminalView(); }
  if (e.key === "Escape" && terminalOpen) toggleTerminalView();
});

// ── 🔐 XSS PANEL RENDERING ───────────────────────────────────────────
function renderXSSPanel(findings) {
  const reflected = findings.find(f => f.title && f.title.includes("Reflected"));
  const stored    = findings.find(f => f.title && f.title.includes("Stored"));

  const refEl = document.getElementById("xss-reflected-status");
  if (refEl) {
    refEl.innerHTML = reflected
      ? `<span class="xss-vuln">🔴 VULNERABLE</span> ${escHtml(reflected.title)} — CVSS ${reflected.cvss_score}<br>
         <pre class="code-block poc-block" onclick="navigator.clipboard.writeText(this.textContent)">${escHtml(reflected.poc_curl||'')}</pre>`
      : findings.length > 0
        ? `<span class="xss-safe">🟢 Not vulnerable</span> — No reflected XSS payload executed.`
        : `<span style="color:var(--muted)">Run a scan to test.</span>`;
  }

  const storedEl = document.getElementById("xss-stored-status");
  if (storedEl) {
    storedEl.innerHTML = stored
      ? `<span class="xss-vuln">🔴 VULNERABLE</span> ${escHtml(stored.title)} — CVSS ${stored.cvss_score}<br>
         <pre class="code-block poc-block" onclick="navigator.clipboard.writeText(this.textContent)">${escHtml(stored.poc_curl||'')}</pre>`
      : findings.length > 0
        ? `<span class="xss-safe">🟢 Not vulnerable</span> — No stored XSS payload persisted.`
        : `<span style="color:var(--muted)">Run a scan to test.</span>`;
  }

  // Show any XSS findings as full finding cards
  const xssFindings = findings.filter(f => f.title && f.title.toLowerCase().includes("xss"));
  const listEl = document.getElementById("xss-findings-list");
  if (listEl && xssFindings.length) {
    listEl.innerHTML = xssFindings.map((f, i) => `
      <div class="finding-card expanded" id="xss-finding-${i}">
        <div class="finding-head">
          <span class="sev-pill sev-${f.severity}">${f.severity}</span>
          <span class="owasp-pill">${escHtml(f.owasp_category||'')}</span>
          <span class="finding-title-text">${escHtml(f.title)}</span>
          <span class="cvss-num" style="color:${CVSS_COLORS[f.severity]||'#aaa'}">${f.cvss_score}</span>
        </div>
        <div class="finding-body">
          <div class="finding-section"><h5>Description</h5><p>${escHtml(f.description)}</p></div>
          <div class="finding-section"><h5>Payload</h5><pre class="code-block">${escHtml(f.payload||'')}</pre></div>
          ${f.poc_curl ? `<div class="finding-section"><h5>🧪 PoC curl</h5><pre class="code-block poc-block" onclick="navigator.clipboard.writeText(this.textContent)">${escHtml(f.poc_curl)}</pre></div>` : ''}
          <div class="finding-section"><h5>Remediation</h5>
            <ul class="remediation-steps">${f.remediation.split("\n").filter(l=>l.trim()).map(l=>`<li>${escHtml(l.replace(/^\d+\.\s*/,""))}</li>`).join("")}</ul>
          </div>
        </div>
      </div>
    `).join("");
  }
}
