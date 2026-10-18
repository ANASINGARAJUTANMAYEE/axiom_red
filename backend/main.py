"""
AXIOM RED — FastAPI Backend
Bridges the agent with the live dashboard via REST API + WebSocket.
"""

import asyncio, json, os, sys, threading
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from typing import Optional

# ── Fix Bug 5: Move sys.path setup to module level (thread-safe) ──────────────
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

app = FastAPI(title="AXIOM RED", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# Serve dashboard
DASHBOARD_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "dashboard"))
REPORTS_DIR   = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "reports"))
os.makedirs(REPORTS_DIR, exist_ok=True)

# Mount dashboard assets (style.css, app.js) and reports
app.mount("/reports", StaticFiles(directory=REPORTS_DIR), name="reports")
app.mount("/static",  StaticFiles(directory=DASHBOARD_DIR), name="static")

# ── In-memory session store ───────────────────────────────────────────────────
sessions: dict = {}         # session_id → AgentState dict
ws_clients: dict = {}       # session_id → list[WebSocket]


# ── Models ────────────────────────────────────────────────────────────────────
class StartScanRequest(BaseModel):
    target: str
    llm_provider: Optional[str] = "gemini"


# ── WebSocket Manager ─────────────────────────────────────────────────────────
async def broadcast(session_id: str, event: dict):
    clients = ws_clients.get(session_id, [])
    dead = []
    for ws in clients:
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)
    for ws in dead:
        clients.remove(ws)


# ── Background agent runner ───────────────────────────────────────────────────
def _run_agent_thread(
    session_id: str,
    target: str,
    llm_provider: str,
    main_loop: asyncio.AbstractEventLoop,      # Fix Bug 2c: use the uvicorn main loop
):
    """
    Runs the agent synchronously in a worker thread.
    All WebSocket broadcasts are scheduled on the main uvicorn event loop via
    run_coroutine_threadsafe — the ONLY correct way to send from a thread.
    """
    os.environ["LLM_PROVIDER"] = llm_provider

    # Fix Bug 2d: Instead of monkey-patching global module attributes (not
    # thread-safe), we use a callback-based push_update passed into run_agent.
    def push_update(state_dict: dict) -> None:
        sessions[session_id] = state_dict
        coro = broadcast(session_id, {"type": "state_update", "data": state_dict})
        # Fix Bug 2a/2b: Schedule on the RUNNING uvicorn loop, not a new loop.
        # .result(timeout=5) blocks this thread until the send completes so we
        # never race against loop teardown.
        try:
            future = asyncio.run_coroutine_threadsafe(coro, main_loop)
            future.result(timeout=5)
        except Exception:
            pass   # WebSocket may have disconnected — not fatal

    try:
        from agent.core.react_agent import run_agent
        final_state = run_agent(target, on_state_update=push_update)
        sessions[session_id] = final_state.model_dump()
        done_payload = {"type": "done", "data": final_state.model_dump()}
        try:
            future = asyncio.run_coroutine_threadsafe(
                broadcast(session_id, done_payload), main_loop
            )
            future.result(timeout=5)
        except Exception:
            pass

    except Exception as e:
        err_payload = {"type": "error", "message": str(e), "session_id": session_id}
        try:
            future = asyncio.run_coroutine_threadsafe(
                broadcast(session_id, err_payload), main_loop
            )
            future.result(timeout=5)
        except Exception:
            pass


# ── REST Endpoints ────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    index = os.path.join(DASHBOARD_DIR, "index.html")
    if os.path.isfile(index):
        return FileResponse(index, media_type="text/html")
    return HTMLResponse("<h1>AXIOM RED API running</h1>")


@app.get("/style.css")
async def _dashboard_css():
    return FileResponse(os.path.join(DASHBOARD_DIR, "style.css"), media_type="text/css")

@app.get("/app.js")
async def _dashboard_js():
    return FileResponse(os.path.join(DASHBOARD_DIR, "app.js"), media_type="application/javascript")


@app.post("/api/scan/start")
async def start_scan(req: StartScanRequest):
    from agent.core.state import AgentState
    state = AgentState(target=req.target, scope=[req.target])
    session_id = state.session_id
    sessions[session_id] = state.model_dump()
    ws_clients[session_id] = []

    # Fix Bug 2a: get_running_loop() is the correct API inside an async context.
    # Fix Bug 2b: No dedicated thread loop created — we pass the uvicorn loop directly.
    main_loop = asyncio.get_running_loop()
    t = threading.Thread(
        target=_run_agent_thread,
        args=(session_id, req.target, req.llm_provider or "gemini", main_loop),
        daemon=True,
        name=f"agent-{session_id}",
    )
    t.start()

    return {"session_id": session_id, "status": "started", "target": req.target}


@app.get("/api/scan/{session_id}")
async def get_session(session_id: str):
    # Fix Bug 3: FastAPI does NOT support (dict, status_code) tuple returns.
    # Always use HTTPException or JSONResponse for non-200 responses.
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    return sessions[session_id]


@app.get("/api/sessions")
async def list_sessions():
    return [
        {
            "session_id": sid,
            "target": s.get("target"),
            "phase": s.get("current_phase"),
            "findings": len(s.get("findings", [])),
            "done": s.get("done", False)
        }
        for sid, s in sessions.items()
    ]


@app.get("/api/report/{session_id}")
async def get_report(session_id: str):
    path = os.path.join(REPORTS_DIR, f"report_{session_id}.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")
    raise HTTPException(status_code=404, detail="Report not generated yet")


# ── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/ws/{session_id}")
async def websocket_endpoint(ws: WebSocket, session_id: str):
    await ws.accept()
    if session_id not in ws_clients:
        ws_clients[session_id] = []
    ws_clients[session_id].append(ws)

    # Send current state immediately on connect
    if session_id in sessions:
        await ws.send_json({"type": "state_update", "data": sessions[session_id]})

    try:
        while True:
            await ws.receive_text()  # Keep alive
    except WebSocketDisconnect:
        if session_id in ws_clients and ws in ws_clients[session_id]:
            ws_clients[session_id].remove(ws)
