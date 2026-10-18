# AXIOM RED 🛡️
### AI-Powered Red Team Agent | NFSU GUH Hackathon

> *"Think Like a Hacker. Move Like an Agent."*

---

## What is AXIOM RED?

AXIOM RED is an autonomous AI red team agent that conducts end-to-end penetration testing without human intervention at each step. It uses a **LangGraph ReAct loop** to reason, plan, execute attacks, validate findings, and generate a full pentest report.

**This is NOT a scanner with an LLM summary.** The LLM actively *decides* the next attack vector based on what it discovers.

---

## Architecture

```
RECON → ANALYSE → PLAN → TEST → VALIDATE → REPORT
  ↑___________ Adaptive Feedback Loop ____________|
```

| Phase | What Happens |
|---|---|
| **Recon** | Port scan, endpoint discovery, tech fingerprint |
| **Analyse** | LLM reasons over attack surface, rates risk |
| **Plan** | LLM builds prioritised attack graph |
| **Test** | Executes: SQLi, IDOR, JWT bypass, cmd injection, Redis RCE |
| **Validate** | Confirms exploits, chains findings, assesses impact |
| **Report** | Auto-generates HTML pentest report with CVSS scores |

---

## Quick Start

### 1. Prerequisites
- Docker + Docker Compose
- Python 3.11+
- A Google Gemini API key (free) **or** OpenAI API key

### 2. Setup

```bash
# Clone / navigate to project
cd axiom-red

# Copy and fill in your API key
cp .env.example .env
# Edit .env and add GOOGLE_API_KEY=...

# Install Python dependencies (for local run)
pip install -r requirements.txt
```

### 3. Start the sandbox targets

```bash
docker-compose up dvwa dvwa-db juice-shop vulnerable-api redis-exposed
```

Targets will be available at:
| Target | URL |
|---|---|
| Custom Vulnerable API | http://localhost:5000 |
| DVWA | http://localhost:8080 |
| Juice Shop | http://localhost:3000 |
| Redis | localhost:6379 |

### 4. Run the dashboard (local)

```bash
# Open the dashboard directly in browser (demo mode — no backend needed)
# styling/JS load via relative paths; no backend needed for demo mode
start dashboard/index.html

# OR run the full backend + dashboard
cd axiom-red
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
# Then open http://localhost:8000
```

### 5. Launch a scan

- Open the dashboard
- Enter target URL: `http://localhost:5000`
- Click **▶ Launch AXIOM RED**
- Watch the agent reason, test, and report in real time

> **Demo mode available**: Click "▷ Run Demo" in the dashboard to see a full simulated engagement with 6 findings — no backend required.

---

## Project Structure

```
axiom-red/
├── docker-compose.yml          ← Sandbox: DVWA, Juice Shop, Redis, custom API
├── targets/
│   └── vulnerable-api/         ← Intentionally vulnerable Flask API (7 vulns)
├── agent/
│   ├── core/
│   │   ├── state.py            ← Pydantic AgentState model
│   │   └── react_agent.py      ← LangGraph ReAct loop (6 nodes)
│   ├── tools/
│   │   ├── recon.py            ← Port scan, endpoint discovery, Redis probe
│   │   └── attacks.py          ← SQLi, IDOR, JWT bypass, cmd injection, RCE
│   └── reporting/
│       └── report_gen.py       ← Jinja2 HTML report generator
├── backend/
│   └── main.py                 ← FastAPI + WebSocket server
├── dashboard/
│   ├── index.html              ← 5-panel live dashboard
│   ├── style.css               ← Premium dark theme
│   └── app.js                  ← WebSocket client + demo mode
└── requirements.txt
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| LLM | Google Gemini (Flash, configurable via GEMINI_MODEL) / OpenAI GPT-4o |
| Agent Framework | LangChain + LangGraph |
| Language | Python 3.11 |
| Backend | FastAPI + WebSocket |
| Frontend | Vanilla HTML/CSS/JS |
| Report | Jinja2 HTML |
| Sandbox | Docker Compose |

---

## Vulnerabilities Demonstrated

| # | Vulnerability | CVSS | Target |
|---|---|---|---|
| F-001 | Redis Unauthenticated RCE | 9.8 Critical | Redis |
| F-002 | OS Command Injection | 9.8 Critical | /api/v1/ping |
| F-003 | JWT alg:none Bypass | 9.3 Critical | /api/v1/admin |
| F-004 | SQL Injection | 9.1 Critical | /api/v1/search |
| F-005 | Sensitive Config Exposure | 7.7 High | /api/v1/config |
| F-006 | IDOR / PII Exposure | 7.5 High | /api/v1/users |
| F-007 | XSS — Reflected (+ Stored) | 8.8 Critical / 7.2 High | /api/v1/greet, /api/v1/comment |

---

## Ethics & Safety

- **All targets are isolated Docker containers** — no external systems are ever touched
- Scope is enforced fail-closed via `agent/core/scope.py`; out-of-scope hosts abort the engagement
- Evidence is stored locally only, never transmitted
- Tool is intended for authorised security research and education only

---

## Team

Built by the NFSU team for the GUH Hackathon.

*National Forensic Sciences University, Gandhinagar, Gujarat*
