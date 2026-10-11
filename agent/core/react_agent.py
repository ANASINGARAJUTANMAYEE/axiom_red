"""
AXIOM RED — Core ReAct Agent (LangGraph-powered)
The decision engine: RECON → ANALYSE → PLAN → TEST → VALIDATE → REPORT
Each node is an LLM-reasoned step that updates and passes the AgentState.
"""

import os, json
from typing import Literal, Callable, Optional
from langgraph.graph import StateGraph, END
from langchain_core.messages import SystemMessage, HumanMessage

from agent.core.state import AgentState, ActivityLog, Finding
from agent.tools.recon import run_recon
from agent.tools.attacks import (
    test_sqli, test_idor, test_jwt_none,
    test_command_injection, test_config_exposure, test_redis_rce, test_xss
)
from agent.reporting.report_gen import generate_report


# ── LLM Setup ────────────────────────────────────────────────────────────────
def get_llm():
    provider = os.getenv("LLM_PROVIDER", "gemini").lower()
    if provider == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model="gpt-4o", temperature=0.1)
    else:
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(model="gemini-3.8-flash", temperature=0.1)


SYSTEM_PROMPT = """You are AXIOM RED, an elite AI red team operator. 
You analyse security recon data and reason like a senior penetration tester.
You must be precise, technical, and strategic. 
Return ONLY valid JSON — never include markdown fences or extra text."""


# ── Node 1: RECON ─────────────────────────────────────────────────────────────
_on_state_update_ref = None  # thread-local callback set before each run

def node_recon(state: AgentState) -> AgentState:
    """Run automated recon tools and populate attack surface data."""
    return run_recon(state, on_update=_on_state_update_ref)


# ── Node 2: ANALYSE ───────────────────────────────────────────────────────────
def node_analyse(state: AgentState) -> AgentState:
    """LLM reasons over recon data to build attack surface summary."""
    llm = get_llm()

    prompt = f"""
You are an expert penetration tester. Analyse this recon data and provide a concise attack surface summary.

TARGET: {state.target}

OPEN PORTS:
{json.dumps(state.open_ports, indent=2)}

WEB ENDPOINTS FOUND:
{chr(10).join(state.web_endpoints[:30])}

TECHNOLOGIES DETECTED:
{chr(10).join(state.technologies)}

SERVICES:
{json.dumps(state.services, indent=2)}

Return a JSON object with:
{{
  "attack_surface_summary": "2-3 sentence overview of the attack surface",
  "high_value_targets": ["list of most promising targets"],
  "risk_level": "Critical|High|Medium|Low",
  "thought": "your reasoning process as a pentester"
}}
"""
    try:
        response = llm.invoke([
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt)
        ])
        raw = response.content.strip()
        # Strip markdown fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        data = json.loads(raw)
        state.attack_surface_summary = data.get("attack_surface_summary", "")
        state.activity_log.append(ActivityLog(
            phase="ANALYSE",
            thought=data.get("thought", ""),
            action="LLM attack surface analysis complete",
            result=f"Risk level: {data.get('risk_level','Unknown')}. "
                   f"High-value targets: {data.get('high_value_targets',[])}",
            status="finding"
        ))
    except Exception as e:
        state.attack_surface_summary = f"Analysis error: {e}"
        state.activity_log.append(ActivityLog(
            phase="ANALYSE", action="LLM analysis", result=str(e), status="error"
        ))

    state.phase_complete["ANALYSE"] = True
    state.current_phase = "PLAN"
    return state


# ── Node 3: PLAN ──────────────────────────────────────────────────────────────
def node_plan(state: AgentState) -> AgentState:
    """LLM builds a prioritised attack plan based on the surface analysis."""
    llm = get_llm()

    prompt = f"""
You are planning a penetration test. Based on the attack surface analysis, create a prioritised attack plan.

ATTACK SURFACE SUMMARY:
{state.attack_surface_summary}

TARGET BASE URL: {state.target}

AVAILABLE ATTACK VECTORS (tools available):
- sqli: SQL Injection testing
- idor: Insecure Direct Object Reference
- jwt_none: JWT alg:none bypass
- cmd_injection: OS Command Injection
- config_exposure: Sensitive config endpoint check
- redis_rce: Redis unauthenticated RCE

Return a JSON array of attack steps, ordered by priority (highest impact first):
[
  {{
    "vector": "sqli|idor|jwt_none|cmd_injection|config_exposure|redis_rce",
    "priority": 1,
    "target_endpoint": "/api/v1/search",
    "param": "q",
    "rationale": "why this is the first vector to test",
    "expected_impact": "what we gain if successful"
  }}
]

Include ALL relevant vectors. Be aggressive but stay within the defined attack surface.
"""
    try:
        response = llm.invoke([
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt)
        ])
        raw = response.content.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        plan = json.loads(raw)
        state.attack_plan = plan if isinstance(plan, list) else []
        state.activity_log.append(ActivityLog(
            phase="PLAN",
            thought=f"I've identified {len(state.attack_plan)} attack vectors to test, ordered by potential impact.",
            action="Attack plan generated",
            result=f"Plan: {[p.get('vector') for p in state.attack_plan]}",
            status="ok"
        ))
    except Exception as e:
        # Fallback default plan if LLM fails
        state.attack_plan = [
            {"vector": "redis_rce",      "priority": 1, "target_endpoint": "", "param": "", "rationale": "Unauthenticated Redis is critical"},
            {"vector": "cmd_injection",  "priority": 2, "target_endpoint": "/api/v1/ping", "param": "host", "rationale": "Ping endpoint likely uses shell"},
            {"vector": "config_exposure","priority": 3, "target_endpoint": "/api/v1/config", "param": "", "rationale": "Config endpoint may leak secrets"},
            {"vector": "sqli",           "priority": 4, "target_endpoint": "/api/v1/search", "param": "q", "rationale": "Search likely hits DB directly"},
            {"vector": "jwt_none",       "priority": 5, "target_endpoint": "/api/v1/admin", "param": "", "rationale": "Admin endpoint, test JWT bypass"},
            {"vector": "idor",           "priority": 6, "target_endpoint": "/api/v1/users/<id>", "param": "", "rationale": "User endpoint without visible auth"},
            {"vector": "xss",            "priority": 7, "target_endpoint": "/api/v1/greet", "param": "name", "rationale": "Greet endpoint reflects user input in HTML"},
        ]
        state.activity_log.append(ActivityLog(
            phase="PLAN", action="Fallback plan used", result=str(e), status="error"
        ))

    state.phase_complete["PLAN"] = True
    state.current_phase = "TEST"
    return state


# ── Node 4: TEST ──────────────────────────────────────────────────────────────
def node_test(state: AgentState) -> AgentState:
    """Execute attack plan — test each vector, collect findings."""
    base_url = state.target.rstrip("/")
    host = base_url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    ATTACK_MAP = {
        "sqli":           lambda step: test_sqli(base_url, step.get("target_endpoint","/api/v1/search"), step.get("param","q")),
        "idor":           lambda step: test_idor(base_url, "/api/v1/users/<id>"),
        "jwt_none":       lambda step: test_jwt_none(base_url, step.get("target_endpoint","/api/v1/admin")),
        "cmd_injection":  lambda step: test_command_injection(base_url, step.get("target_endpoint","/api/v1/ping"), step.get("param","host")),
        "config_exposure":lambda step: test_config_exposure(base_url, step.get("target_endpoint","/api/v1/config")),
        "redis_rce":      lambda step: test_redis_rce(host),
        "xss":            lambda step: test_xss(base_url, step.get("target_endpoint","/api/v1/greet"), step.get("param","name")),
    }

    for step in sorted(state.attack_plan, key=lambda x: x.get("priority", 99)):
        vector = step.get("vector")
        if vector in state.tested_vectors:
            continue

        state.activity_log.append(ActivityLog(
            phase="TEST",
            thought=step.get("rationale", ""),
            action=f"Testing: {vector} on {step.get('target_endpoint','')}",
            result="Running...",
            status="ok"
        ))

        try:
            fn = ATTACK_MAP.get(vector)
            finding: Finding | None = fn(step) if fn else None

            if finding:
                state.findings.append(finding)
                state.activity_log.append(ActivityLog(
                    phase="TEST",
                    thought=f"CONFIRMED: {finding.title}. CVSS {finding.cvss_score}. Moving to capture evidence.",
                    action=f"Vulnerability confirmed: {vector}",
                    result=f"[{finding.severity}] {finding.title}",
                    status="finding"
                ))
            else:
                state.blocked_vectors.append(vector)
                state.activity_log.append(ActivityLog(
                    phase="TEST",
                    action=f"Vector {vector}: not exploitable or hardened",
                    result="No vulnerability confirmed",
                    status="ok"
                ))
        except Exception as e:
            state.activity_log.append(ActivityLog(
                phase="TEST", action=f"{vector} error", result=str(e), status="error"
            ))

        state.tested_vectors.append(vector)

    state.phase_complete["TEST"] = True
    state.current_phase = "VALIDATE"
    return state


# ── Node 5: VALIDATE ──────────────────────────────────────────────────────────

# Risk domain mapping for radar chart
RISK_DOMAIN_MAP = {
    "SQL Injection": "Injection",
    "OS Command Injection": "Injection",
    "IDOR": "Access Control",
    "JWT Algorithm Confusion": "Authentication",
    "Sensitive Configuration Exposure": "Configuration",
    "Unauthenticated Redis": "Configuration",
}

def _compute_risk_scores(findings) -> dict:
    """Compute risk scores (0-10) per security domain from findings."""
    scores = {
        "Authentication": 0.0, "Injection": 0.0, "Configuration": 0.0,
        "Encryption": 0.0, "Access Control": 0.0, "Data Exposure": 0.0
    }
    for f in findings:
        domain = None
        for keyword, dom in RISK_DOMAIN_MAP.items():
            if keyword.lower() in f.title.lower():
                domain = dom
                break
        if not domain:
            domain = "Data Exposure"
        scores[domain] = min(10.0, scores[domain] + f.cvss_score * 1.1)

    for f in findings:
        if "jwt" in f.title.lower():
            scores["Encryption"] = min(10.0, scores["Encryption"] + f.cvss_score * 0.8)
        if any(k in f.title.lower() for k in ["idor", "sql", "config"]):
            scores["Data Exposure"] = min(10.0, scores["Data Exposure"] + f.cvss_score * 0.6)

    return scores


def node_validate(state: AgentState) -> AgentState:
    """LLM reviews findings, builds attack chains, and scores risk domains."""
    llm = get_llm()

    if not state.findings:
        state.activity_log.append(ActivityLog(
            phase="VALIDATE", action="No findings to validate", result="Clean scan", status="ok"
        ))
        state.phase_complete["VALIDATE"] = True
        state.current_phase = "REPORT"
        return state

    state.risk_scores = _compute_risk_scores(state.findings)

    findings_summary = [
        {"title": f.title, "severity": f.severity, "cvss": f.cvss_score, "endpoint": f.endpoint}
        for f in state.findings
    ]

    prompt = f"""
You are validating the results of a penetration test. Review these findings and provide:
1. Confirmation that the attack chain is logical
2. A structured list of attack chain edges showing how vulnerabilities connect
3. Overall engagement risk rating

FINDINGS:
{json.dumps(findings_summary, indent=2)}

Return JSON:
{{
  "validated": true,
  "chain_narrative": "How these vulnerabilities connect into an attack chain",
  "overall_risk": "Critical|High|Medium|Low",
  "thought": "your validation reasoning",
  "attack_chains": [
    {{"from_node": "Finding A title", "to_node": "Finding B title", "label": "how A leads to B"}}
  ]
}}
"""
    try:
        response = llm.invoke([
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt)
        ])
        raw = response.content.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        data = json.loads(raw)

        chains = data.get("attack_chains", [])
        if isinstance(chains, list):
            state.attack_chains = chains

        state.activity_log.append(ActivityLog(
            phase="VALIDATE",
            thought=data.get("thought", ""),
            action="Finding validation and chain analysis complete",
            result=f"Overall risk: {data.get('overall_risk')}. Chain: {data.get('chain_narrative','')}",
            status="finding"
        ))
    except Exception as e:
        if len(state.findings) >= 2:
            state.attack_chains = [
                {"from_node": state.findings[i].title, "to_node": state.findings[i+1].title, "label": "enables"}
                for i in range(len(state.findings) - 1)
            ]
        state.activity_log.append(ActivityLog(
            phase="VALIDATE", action="Validation", result=str(e), status="error"
        ))

    state.phase_complete["VALIDATE"] = True
    state.current_phase = "REPORT"
    return state


# ── Node 6: REPORT ────────────────────────────────────────────────────────────
def _generate_executive_summary(state: AgentState) -> str:
    """Generate a board-level executive summary using LLM."""
    try:
        llm = get_llm()
        severities = [f"{f.title} ({f.severity}, CVSS {f.cvss_score})" for f in state.findings]
        prompt = f"""Write a concise 3-paragraph executive summary for a board of directors about this penetration test.

TARGET: {state.target}
TOTAL FINDINGS: {len(state.findings)}
VULNERABILITIES: {', '.join(severities)}

Paragraph 1: Brief overview of what was tested and the overall risk level.
Paragraph 2: Key business impacts — what could an attacker do? Focus on data breach risk, financial impact, and regulatory implications (GDPR, PCI-DSS).
Paragraph 3: Recommended immediate actions for the leadership team.

Keep it non-technical, professional, and under 200 words. Do NOT use markdown formatting."""
        response = llm.invoke([
            SystemMessage(content="You are a cybersecurity consultant writing for C-suite executives. Be concise and business-focused."),
            HumanMessage(content=prompt)
        ])
        return response.content.strip()
    except Exception as e:
        return f"Executive summary generation failed: {e}"


def node_report(state: AgentState) -> AgentState:
    """Generate AI executive summary and the final HTML pentest report."""
    # ── Innovation: Generate AI Executive Summary ─────────────────────
    if state.findings:
        state.executive_summary = _generate_executive_summary(state)
        state.activity_log.append(ActivityLog(
            phase="REPORT",
            thought="Generating board-level executive summary for non-technical stakeholders.",
            action="AI Executive Summary generated",
            result=state.executive_summary[:150] + "...",
            status="ok"
        ))

    try:
        report_path = generate_report(state)
        state.report_path = report_path
        state.activity_log.append(ActivityLog(
            phase="REPORT",
            action="Pentest report generated",
            result=f"Report saved: {report_path}",
            status="ok"
        ))
    except Exception as e:
        state.activity_log.append(ActivityLog(
            phase="REPORT", action="Report generation", result=str(e), status="error"
        ))

    state.phase_complete["REPORT"] = True
    state.current_phase = "DONE"
    state.done = True
    return state


# ── Routing ───────────────────────────────────────────────────────────────────
def route_phase(state: AgentState) -> Literal["analyse", "plan", "test", "validate", "report", "__end__"]:
    """
    Fix Bug 6: This function is now properly wired into the graph via
    add_conditional_edges so early-exit on state.done / state.error works.
    """
    if state.done or state.error:
        return END
    phase = state.current_phase
    return {
        "ANALYSE": "analyse",
        "PLAN":    "plan",
        "TEST":    "test",
        "VALIDATE":"validate",
        "REPORT":  "report",
    }.get(phase, END)


# ── Build Graph ───────────────────────────────────────────────────────────────
def build_agent() -> StateGraph:
    from langgraph.graph import StateGraph

    # Adapt AgentState ↔ dict for LangGraph's dict-based state
    def adapt(fn):
        def wrapper(state_dict):
            s = AgentState(**state_dict)
            result = fn(s)
            return result.model_dump()
        return wrapper

    # Fix Bug 6: adapt route_phase to work with dict state
    def adapt_route(fn):
        def wrapper(state_dict):
            s = AgentState(**state_dict)
            return fn(s)
        return wrapper

    graph = StateGraph(dict)
    graph.add_node("recon",    adapt(node_recon))
    graph.add_node("analyse",  adapt(node_analyse))
    graph.add_node("plan",     adapt(node_plan))
    graph.add_node("test",     adapt(node_test))
    graph.add_node("validate", adapt(node_validate))
    graph.add_node("report",   adapt(node_report))

    # Fix Bug 6: Use conditional edges so done/error flags trigger early exit
    graph.set_entry_point("recon")
    graph.add_edge("recon", "analyse")
    graph.add_conditional_edges(
        "analyse", adapt_route(route_phase),
        {"plan": "plan", "__end__": END}
    )
    graph.add_conditional_edges(
        "plan", adapt_route(route_phase),
        {"test": "test", "__end__": END}
    )
    graph.add_conditional_edges(
        "test", adapt_route(route_phase),
        {"validate": "validate", "__end__": END}
    )
    graph.add_conditional_edges(
        "validate", adapt_route(route_phase),
        {"report": "report", "__end__": END}
    )
    graph.add_edge("report", END)

    return graph.compile()


# ── Entry Point ───────────────────────────────────────────────────────────────
def run_agent(
    target: str,
    scope: list[str] = None,
    on_state_update: Optional[Callable[[dict], None]] = None,
) -> AgentState:
    """
    Entry point: run the full AXIOM RED agent against a target.

    Fix Bug 2d: on_state_update is a thread-safe callback (no global monkey-patching).
    The backend passes push_update here; the agent calls it after each node completes.
    """
    global _on_state_update_ref
    _on_state_update_ref = on_state_update  # make available to node_recon

    initial = AgentState(target=target, scope=scope or [target])
    agent = build_agent()

    if on_state_update:
        # Wrap invoke to call back after every step using LangGraph stream
        result_dict = initial.model_dump()
        for chunk in agent.stream(initial.model_dump()):
            # chunk is {node_name: state_dict}
            for node_name, state_dict in chunk.items():
                result_dict = state_dict
                try:
                    on_state_update(state_dict)
                except Exception:
                    pass
        return AgentState(**result_dict)
    else:
        result_dict = agent.invoke(initial.model_dump())
        return AgentState(**result_dict)
