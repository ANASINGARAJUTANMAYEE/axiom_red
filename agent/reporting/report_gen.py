"""
AXIOM RED — Report Generator
Generates HTML (and optionally PDF) pentest reports from AgentState.
"""

import os
from datetime import datetime
from jinja2 import Environment, BaseLoader
from agent.core.state import AgentState

REPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "reports")
os.makedirs(REPORT_DIR, exist_ok=True)

SEVERITY_COLOR = {
    "Critical": "#ff4444",
    "High":     "#ff8800",
    "Medium":   "#ffcc00",
    "Low":      "#44aaff",
    "Info":     "#aaaaaa",
}

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AXIOM RED — Pentest Report | {{ session_id }}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;900&family=JetBrains+Mono:wght@400;700&display=swap');
  :root {
    --bg: #0a0c12;
    --surface: #12151f;
    --surface2: #1a1e2e;
    --border: #2a2d3e;
    --accent: #e0102f;
    --accent2: #ff4560;
    --text: #e8eaf0;
    --muted: #8892a4;
    --critical: #ff4444;
    --high: #ff8800;
    --medium: #ffcc00;
    --low: #44aaff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
  
  /* HEADER */
  .header {
    background: linear-gradient(135deg, #0a0c12 0%, #1a0510 50%, #0a0c12 100%);
    border-bottom: 2px solid var(--accent);
    padding: 48px 60px;
    position: relative;
    overflow: hidden;
  }
  .header::before {
    content: '';
    position: absolute; inset: 0;
    background: radial-gradient(ellipse at 20% 50%, rgba(224,16,47,0.15) 0%, transparent 60%);
  }
  .header-logo { font-size: 11px; letter-spacing: 4px; color: var(--accent); text-transform: uppercase; margin-bottom: 12px; }
  .header-title { font-size: 42px; font-weight: 900; letter-spacing: -1px; margin-bottom: 6px; }
  .header-title span { color: var(--accent); }
  .header-sub { font-size: 15px; color: var(--muted); }
  .header-meta { margin-top: 32px; display: flex; gap: 40px; }
  .meta-item label { display: block; font-size: 10px; letter-spacing: 2px; color: var(--muted); text-transform: uppercase; margin-bottom: 4px; }
  .meta-item span { font-size: 14px; font-weight: 600; font-family: 'JetBrains Mono', monospace; }

  /* LAYOUT */
  .container { max-width: 1100px; margin: 0 auto; padding: 48px 60px; }
  
  /* EXECUTIVE SUMMARY */
  .exec-summary {
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 4px solid var(--accent);
    border-radius: 12px;
    padding: 32px;
    margin-bottom: 40px;
  }
  .section-label { font-size: 10px; letter-spacing: 3px; color: var(--accent); text-transform: uppercase; margin-bottom: 8px; }
  .section-title { font-size: 22px; font-weight: 700; margin-bottom: 16px; }
  
  /* SEVERITY BADGES */
  .severity-grid { display: flex; gap: 16px; margin: 24px 0; flex-wrap: wrap; }
  .sev-card {
    flex: 1; min-width: 120px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    text-align: center;
  }
  .sev-card .count { font-size: 36px; font-weight: 900; font-family: 'JetBrains Mono', monospace; }
  .sev-card .label { font-size: 11px; letter-spacing: 2px; text-transform: uppercase; margin-top: 4px; }
  .sev-critical .count { color: var(--critical); }
  .sev-high .count { color: var(--high); }
  .sev-medium .count { color: var(--medium); }
  .sev-low .count { color: var(--low); }

  /* FINDINGS */
  .findings-section { margin: 40px 0; }
  .finding-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    margin-bottom: 24px;
    overflow: hidden;
  }
  .finding-header {
    padding: 20px 24px;
    display: flex;
    align-items: center;
    gap: 16px;
    border-bottom: 1px solid var(--border);
  }
  .finding-id { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--muted); min-width: 50px; }
  .severity-badge {
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
  }
  .finding-title { font-size: 16px; font-weight: 600; flex: 1; }
  .cvss-score { font-family: 'JetBrains Mono', monospace; font-size: 20px; font-weight: 700; min-width: 60px; text-align: right; }
  
  .finding-body { padding: 24px; }
  .finding-section { margin-bottom: 20px; }
  .finding-section h4 { font-size: 11px; letter-spacing: 2px; color: var(--muted); text-transform: uppercase; margin-bottom: 8px; }
  .finding-section p { font-size: 14px; line-height: 1.7; }
  pre {
    background: #0d0f1a;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #a8ff78;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }
  .remediation-list { list-style: none; }
  .remediation-list li { padding: 6px 0; padding-left: 20px; position: relative; font-size: 14px; }
  .remediation-list li::before { content: '→'; position: absolute; left: 0; color: var(--accent); }

  /* ACTIVITY LOG */
  .log-section { margin: 40px 0; }
  .log-entry {
    display: flex;
    gap: 20px;
    padding: 16px 0;
    border-bottom: 1px solid var(--border);
  }
  .log-phase {
    min-width: 90px;
    font-size: 10px;
    letter-spacing: 2px;
    font-weight: 700;
    text-transform: uppercase;
    padding-top: 2px;
  }
  .log-content { flex: 1; }
  .log-thought { font-size: 12px; color: var(--muted); font-style: italic; margin-bottom: 4px; }
  .log-action { font-size: 13px; font-weight: 600; }
  .log-result { font-size: 12px; color: var(--muted); margin-top: 2px; }
  .log-time { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--muted); min-width: 80px; text-align: right; }
  .status-finding { color: var(--accent2); }
  .status-error { color: var(--high); }
  .status-ok { color: #44ff88; }

  /* FOOTER */
  .footer {
    background: var(--surface);
    border-top: 1px solid var(--border);
    padding: 32px 60px;
    text-align: center;
    font-size: 12px;
    color: var(--muted);
  }
  .footer strong { color: var(--accent); }
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div class="header-logo">⬡ Axiom Red · AI-Powered Red Team Report</div>
  <div class="header-title">Security Assessment<br><span>Findings Report</span></div>
  <div class="header-sub">Generated by AXIOM RED autonomous red team agent · NFSU GUH Hackathon</div>
  <div class="header-meta">
    <div class="meta-item"><label>Target</label><span>{{ target }}</span></div>
    <div class="meta-item"><label>Session ID</label><span>{{ session_id }}</span></div>
    <div class="meta-item"><label>Generated</label><span>{{ generated_at }}</span></div>
    <div class="meta-item"><label>Total Findings</label><span>{{ findings | length }}</span></div>
  </div>
</div>

<div class="container">

  <!-- EXECUTIVE SUMMARY -->
  <div class="exec-summary">
    <div class="section-label">01 · Executive Summary</div>
    <div class="section-title">Engagement Overview</div>
    {% if executive_summary %}
    <div style="background:#0f1219;border-left:3px solid var(--accent);padding:20px 24px;border-radius:8px;margin-bottom:20px;font-size:14px;line-height:1.9;white-space:pre-line;color:#c8cad8;">{{ executive_summary }}</div>
    {% endif %}
    <p>{{ attack_surface_summary }}</p>
    <div class="severity-grid">
      <div class="sev-card sev-critical">
        <div class="count">{{ findings | selectattr('severity','eq','Critical') | list | length }}</div>
        <div class="label">Critical</div>
      </div>
      <div class="sev-card sev-high">
        <div class="count">{{ findings | selectattr('severity','eq','High') | list | length }}</div>
        <div class="label">High</div>
      </div>
      <div class="sev-card sev-medium">
        <div class="count">{{ findings | selectattr('severity','eq','Medium') | list | length }}</div>
        <div class="label">Medium</div>
      </div>
      <div class="sev-card sev-low">
        <div class="count">{{ findings | selectattr('severity','eq','Low') | list | length }}</div>
        <div class="label">Low</div>
      </div>
    </div>
  </div>

  <!-- OWASP TOP 10 COMPLIANCE -->
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:12px;margin-bottom:40px;overflow:hidden;">
    <div style="padding:24px 32px 16px;">
      <div class="section-label">01b · Compliance</div>
      <div class="section-title">OWASP Top 10 (2021) Assessment</div>
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
      <thead>
        <tr style="border-bottom:1px solid var(--border);">
          <th style="text-align:left;padding:10px 32px;color:var(--muted);font-size:10px;letter-spacing:2px;text-transform:uppercase;">Category</th>
          <th style="text-align:left;padding:10px 16px;color:var(--muted);font-size:10px;letter-spacing:2px;text-transform:uppercase;">Status</th>
          <th style="text-align:left;padding:10px 16px;color:var(--muted);font-size:10px;letter-spacing:2px;text-transform:uppercase;">Findings</th>
        </tr>
      </thead>
      <tbody>
        {% set owasp_cats = [
          ("A01","A01:2021 Broken Access Control"),("A02","A02:2021 Cryptographic Failures"),
          ("A03","A03:2021 Injection"),("A04","A04:2021 Insecure Design"),
          ("A05","A05:2021 Security Misconfiguration"),("A06","A06:2021 Vulnerable Components"),
          ("A07","A07:2021 Auth Failures"),("A08","A08:2021 Data Integrity Failures"),
          ("A09","A09:2021 Logging Failures"),("A10","A10:2021 SSRF")
        ] %}
        {% for cat_id, cat_name in owasp_cats %}
          {% set matched = findings | selectattr('owasp_id','eq',cat_id) | list %}
          <tr style="border-bottom:1px solid var(--border);{% if matched %}background:rgba(255,58,58,0.04);{% endif %}">
            <td style="padding:12px 32px;font-weight:600;">{{ cat_name }}</td>
            <td style="padding:12px 16px;font-family:'JetBrains Mono',monospace;font-size:12px;{% if matched %}color:#ff3a3a;{% elif findings %}color:#00e676;{% else %}color:var(--muted);{% endif %}">
              {% if matched %}🔴 FAIL{% elif findings %}🟢 PASS{% else %}⚪ N/A{% endif %}
            </td>
            <td style="padding:12px 16px;font-size:12px;color:{% if matched %}#ff8080{% else %}var(--muted){% endif %};">
              {% if matched %}{{ matched | map(attribute='title') | join(', ') }}{% else %}—{% endif %}
            </td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <!-- FINDINGS -->
  <div class="findings-section">
    <div class="section-label">02 · Technical Findings</div>
    <div class="section-title">Vulnerability Details</div>

    {% for f in findings %}
    <div class="finding-card">
      <div class="finding-header">
        <span class="finding-id">F-{{ "%03d" | format(loop.index) }}</span>
        <span class="severity-badge" style="background:{{ severity_colors[f.severity] }}22; color:{{ severity_colors[f.severity] }}; border:1px solid {{ severity_colors[f.severity] }}44;">
          {{ f.severity }}
        </span>
        <span class="finding-title">{{ f.title }}</span>
        <span class="cvss-score" style="color:{{ severity_colors[f.severity] }}">{{ f.cvss_score }}</span>
      </div>
      <div class="finding-body">
        <div class="finding-section">
          <h4>Description</h4>
          <p>{{ f.description }}</p>
        </div>
        <div class="finding-section">
          <h4>Endpoint</h4>
          <pre>{{ f.method }} {{ f.endpoint }}</pre>
        </div>
        {% if f.payload %}
        <div class="finding-section">
          <h4>Payload Used</h4>
          <pre>{{ f.payload }}</pre>
        </div>
        {% endif %}
        {% if f.evidence %}
        <div class="finding-section">
          <h4>Evidence</h4>
          <pre>{{ f.evidence }}</pre>
        </div>
        {% endif %}
        <div class="finding-section">
          <h4>Remediation</h4>
          <ul class="remediation-list">
            {% for line in f.remediation.split('\n') %}
            {% if line.strip() %}
            <li>{{ line.strip().lstrip('1234567890. ') }}</li>
            {% endif %}
            {% endfor %}
          </ul>
        </div>
      </div>
    </div>
    {% endfor %}
  </div>

  <!-- AGENT ACTIVITY LOG -->
  <div class="log-section">
    <div class="section-label">03 · Agent Activity Log</div>
    <div class="section-title">Reasoning Chain</div>
    {% for log in activity_log %}
    <div class="log-entry">
      <div class="log-phase" style="color:{% if log.phase == 'RECON' %}#44aaff{% elif log.phase == 'ANALYSE' %}#aa44ff{% elif log.phase == 'PLAN' %}#ffaa44{% elif log.phase == 'TEST' %}#ff4444{% elif log.phase == 'VALIDATE' %}#44ffaa{% else %}#aaaaaa{% endif %}">
        {{ log.phase }}
      </div>
      <div class="log-content">
        {% if log.thought %}
        <div class="log-thought">💭 {{ log.thought }}</div>
        {% endif %}
        <div class="log-action">⚡ {{ log.action }}</div>
        {% if log.result %}
        <div class="log-result class-status-{{ log.status }}">{{ log.result }}</div>
        {% endif %}
      </div>
      <div class="log-time">{{ log.timestamp[11:19] }}</div>
    </div>
    {% endfor %}
  </div>

</div>

<div class="footer">
  {% if evidence_root_hash %}
  <div style="margin-bottom:12px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--accent2);">
    🔒 Evidence root (SHA-256): {{ evidence_root_hash }} — verify with <code>python verify.py</code>
  </div>
  {% endif %}
  Generated by <strong>AXIOM RED</strong> · AI-Powered Red Team Agent ·
  National Forensic Sciences University (NFSU) ·
  <strong>For authorised use only — controlled sandbox environment</strong>
</div>

</body>
</html>
"""


def generate_report(state: AgentState) -> str:
    """Render the Jinja2 template and write HTML report."""
    env = Environment(loader=BaseLoader())
    template = env.from_string(REPORT_TEMPLATE)

    html = template.render(
        session_id=state.session_id,
        target=state.target,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        attack_surface_summary=state.attack_surface_summary or "Engagement completed. See findings below.",
        executive_summary=state.executive_summary or "",
        evidence_root_hash=state.evidence_root_hash or "",
        findings=state.findings,
        activity_log=state.activity_log,
        severity_colors=SEVERITY_COLOR,
    )

    report_path = os.path.join(REPORT_DIR, f"report_{state.session_id}.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    return report_path
