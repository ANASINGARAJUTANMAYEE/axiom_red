"""
AXIOM RED — Agent State Model
Defines the shared state object that flows through every node of the LangGraph.
"""

from typing import Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime
import uuid


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str
    severity: str           # Critical / High / Medium / Low / Info
    cvss_score: float
    description: str
    endpoint: str
    method: str = "GET"
    payload: Optional[str] = None
    evidence: Optional[str] = None
    request_dump: Optional[str] = None
    response_dump: Optional[str] = None
    remediation: str
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    # ── Innovation: OWASP Top 10 mapping ─────────────────────────────
    owasp_id: str = ""                # e.g. "A03"
    owasp_category: str = ""          # e.g. "A03:2021 Injection"
    # ── Innovation: Auto-generated PoC ───────────────────────────────
    poc_curl: str = ""                # reproducible curl command


class ActivityLog(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    phase: str
    thought: Optional[str] = None
    action: str
    result: Optional[str] = None
    status: str = "ok"   # ok | error | finding


class AgentState(BaseModel):
    # ── Engagement metadata ──────────────────────────────────────────
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:12])
    target: str = ""
    scope: list[str] = Field(default_factory=list)
    start_time: str = Field(default_factory=lambda: datetime.now().isoformat())

    # ── Phase tracking ───────────────────────────────────────────────
    current_phase: str = "RECON"   # RECON → ANALYSE → PLAN → TEST → VALIDATE → REPORT
    phase_complete: dict[str, bool] = Field(default_factory=lambda: {
        "RECON": False, "ANALYSE": False, "PLAN": False,
        "TEST": False, "VALIDATE": False, "REPORT": False
    })

    # ── Recon results ────────────────────────────────────────────────
    open_ports: list[dict] = Field(default_factory=list)
    services: list[dict] = Field(default_factory=list)
    web_endpoints: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)

    # ── Attack surface / plan ────────────────────────────────────────
    attack_surface_summary: str = ""
    attack_plan: list[dict] = Field(default_factory=list)   # [{vector, priority, target, rationale}]
    tested_vectors: list[str] = Field(default_factory=list)
    blocked_vectors: list[str] = Field(default_factory=list)

    # ── Findings ─────────────────────────────────────────────────────
    findings: list[Finding] = Field(default_factory=list)

    # ── Agent reasoning log ──────────────────────────────────────────
    activity_log: list[ActivityLog] = Field(default_factory=list)
    last_thought: str = ""

    # ── Control flags ────────────────────────────────────────────────
    done: bool = False
    error: Optional[str] = None
    report_path: Optional[str] = None

    # ── Innovation: AI Executive Summary ─────────────────────────────
    executive_summary: str = ""

    # ── Innovation: Attack Chain Graph ───────────────────────────────
    attack_chains: list[dict] = Field(default_factory=list)  # [{from_node, to_node, label}]

    # ── Innovation: Risk Radar Scores ────────────────────────────────
    risk_scores: dict[str, float] = Field(default_factory=lambda: {
        "Authentication": 0.0, "Injection": 0.0, "Configuration": 0.0,
        "Encryption": 0.0, "Access Control": 0.0, "Data Exposure": 0.0
    })

    class Config:
        arbitrary_types_allowed = True
