#!/usr/bin/env python3
"""
+==============================================================================+
|              AXIOM RED -- Unified Launcher                                  |
|  Usage:  python run.py [command] [options]                                  |
|                                                                              |
|  Commands:                                                                   |
|    backend      Start the FastAPI backend server (default port 8000)        |
|    targets      Start the vulnerable Flask API target (default port 5000)   |
|    docker       Build & start all services with docker-compose              |
|    docker-down  Stop & remove all docker containers                         |
|    scan         Run the agent directly (CLI mode, no backend needed)        |
|    check        Check environment: Python, deps, API keys, Docker           |
|    all          Start backend + targets together (no Docker)                |
+==============================================================================+
"""

import argparse
import os
import sys
import subprocess
import signal
import threading
import time
import shutil
from pathlib import Path

# ── Constants ─────────────────────────────────────────────────────────────────
ROOT     = Path(__file__).parent.resolve()
ENV_FILE = ROOT / ".env"
ENV_EX   = ROOT / ".env.example"
BANNER = r"""
  ___  _  _____ ___  __  __   ____  _____ ____
 / _ \| |/ /_ _/ _ \|  \/  | |  _ \| ____|  _ \\
| |_| | ' / | | | | | |\/| | | |_) |  _| | | | |
|  _  | . \ | | |_| | |  | | |  _ <| |___| |_| |
|_| |_|_|\_\___\___/|_|  |_| |_| \_\_____|____/

    AI-Powered Red Team Agent  |  NFSU GUH Hackathon
"""

# Ensure stdout can handle ASCII output on Windows (cp1252 terminals)
import io as _io
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ANSI colours (disabled automatically on Windows if not supported)
_ansi = sys.stdout.isatty() or os.environ.get("FORCE_COLOR")
R    = "\033[91m" if _ansi else ""
G    = "\033[92m" if _ansi else ""
Y    = "\033[93m" if _ansi else ""
B    = "\033[94m" if _ansi else ""
C    = "\033[96m" if _ansi else ""
M    = "\033[95m" if _ansi else ""
DIM  = "\033[2m"  if _ansi else ""
BOLD = "\033[1m"  if _ansi else ""
RST  = "\033[0m"  if _ansi else ""


# ── Helpers ───────────────────────────────────────────────────────────────────
def _print(msg: str) -> None:
    print(msg, flush=True)

def ok(msg):   _print(f"  {G}✔{RST}  {msg}")
def warn(msg): _print(f"  {Y}⚠{RST}  {msg}")
def err(msg):  _print(f"  {R}✘{RST}  {msg}")
def info(msg): _print(f"  {C}→{RST}  {msg}")
def head(msg): _print(f"\n{BOLD}{B}{msg}{RST}")

def banner():
    print(f"{R}{BANNER}{RST}")
    print(f"  {DIM}Root: {ROOT}{RST}\n")

def _load_dotenv():
    """Load .env into os.environ (no third-party dependency)."""
    target = ENV_FILE if ENV_FILE.exists() else None
    if not target:
        return
    with open(target, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

def _setup_sys_path():
    """Ensure project root is on sys.path for direct agent imports."""
    root_str = str(ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)

def _require_env_file():
    """Warn if .env doesn't exist and offer to copy from .env.example."""
    if not ENV_FILE.exists():
        warn(".env file not found.")
        if ENV_EX.exists():
            try:
                answer = input(f"  {Y}Copy .env.example → .env now?{RST} [y/N] ").strip().lower()
                if answer == "y":
                    shutil.copy(ENV_EX, ENV_FILE)
                    ok("Created .env — please fill in your API keys.")
                    sys.exit(0)
            except (EOFError, KeyboardInterrupt):
                pass
        err("Please create .env (copy from .env.example) and set your API keys.")
        sys.exit(1)


# ── Command: check ────────────────────────────────────────────────────────────
def cmd_check(_args):
    banner()
    head("Environment Check")

    # Python version
    v = sys.version_info
    if v >= (3, 10):
        ok(f"Python {v.major}.{v.minor}.{v.micro}")
    else:
        err(f"Python {v.major}.{v.minor} — requires ≥ 3.10")

    # .env
    if ENV_FILE.exists():
        ok(".env file found")
    else:
        warn(".env not found — run: cp .env.example .env")

    _load_dotenv()

    # API keys
    google_key = os.environ.get("GOOGLE_API_KEY", "")
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    provider   = os.environ.get("LLM_PROVIDER", "gemini")

    if provider == "gemini":
        if google_key and not google_key.startswith("your_"):
            ok(f"GOOGLE_API_KEY set (provider=gemini)")
        else:
            err("GOOGLE_API_KEY missing or placeholder — set it in .env")
    else:
        if openai_key and not openai_key.startswith("your_"):
            ok(f"OPENAI_API_KEY set (provider=openai)")
        else:
            err("OPENAI_API_KEY missing or placeholder — set it in .env")

    # Key Python packages
    head("Package Check")
    packages = {
        "fastapi":              "FastAPI (backend)",
        "uvicorn":              "Uvicorn (ASGI server)",
        "langgraph":            "LangGraph (agent graph)",
        "langchain_core":       "LangChain core",
        "langchain_google_genai": "LangChain Gemini",
        "langchain_openai":     "LangChain OpenAI",
        "httpx":                "httpx (HTTP client)",
        "pydantic":             "Pydantic (data models)",
        "jinja2":               "Jinja2 (report templating)",
        "redis":                "redis-py (Redis attacks)",
        "flask":                "Flask (vulnerable target)",
    }
    missing = []
    for pkg, label in packages.items():
        try:
            __import__(pkg)
            ok(label)
        except ImportError:
            err(f"{label}  → pip install {pkg}")
            missing.append(pkg)

    if missing:
        warn(f"{len(missing)} package(s) missing. Run:\n\n    pip install -r requirements.txt\n")
    else:
        ok("All required packages installed")

    # Docker
    head("Docker Check")
    if shutil.which("docker"):
        result = subprocess.run(["docker", "info"], capture_output=True, text=True)
        if result.returncode == 0:
            ok("Docker daemon running")
        else:
            warn("Docker installed but daemon not running — start Docker Desktop")
    else:
        warn("Docker not found — install Docker Desktop to use docker mode")

    if shutil.which("docker") and shutil.which("docker-compose") or _docker_compose_v2():
        ok("docker-compose available")
    else:
        warn("docker-compose not found — Docker mode unavailable")

    head("Directories")
    for d in ["agent", "backend", "dashboard", "reports", "targets"]:
        p = ROOT / d
        if p.exists():
            ok(f"./{d}/")
        else:
            err(f"./{d}/ missing!")

    _print("")


def _docker_compose_v2() -> bool:
    """Check for `docker compose` (v2, no hyphen)."""
    try:
        r = subprocess.run(["docker", "compose", "version"], capture_output=True)
        return r.returncode == 0
    except Exception:
        return False

def _compose_cmd() -> list[str]:
    """Return the correct docker compose command (v1 or v2)."""
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    if _docker_compose_v2():
        return ["docker", "compose"]
    err("Neither 'docker-compose' nor 'docker compose' found.")
    sys.exit(1)


# ── Command: backend ──────────────────────────────────────────────────────────
def cmd_backend(args):
    banner()
    _require_env_file()
    _load_dotenv()
    _setup_sys_path()

    port = getattr(args, "port", 8000)
    host = getattr(args, "host", "0.0.0.0")

    head(f"Starting AXIOM RED Backend  →  http://localhost:{port}")
    info(f"Dashboard at  http://localhost:{port}/")
    info(f"API docs at   http://localhost:{port}/docs")
    info("Press Ctrl+C to stop.\n")

    try:
        import uvicorn
    except ImportError:
        err("uvicorn not installed. Run: pip install -r requirements.txt")
        sys.exit(1)

    # Ensure reports dir exists
    (ROOT / "reports").mkdir(exist_ok=True)

    uvicorn.run(
        "backend.main:app",
        host=host,
        port=port,
        reload=False,         # Never use --reload (Bug 4 fix)
        log_level="info",
        workers=1,
    )


# ── Command: targets ──────────────────────────────────────────────────────────
def cmd_targets(args):
    banner()
    port = getattr(args, "port", 5000)
    head(f"Starting Vulnerable Flask API Target  →  http://localhost:{port}")
    info("⚠  Intentionally insecure — run only in an isolated sandbox!")
    info("Press Ctrl+C to stop.\n")

    target_app = ROOT / "targets" / "vulnerable-api" / "app.py"
    if not target_app.exists():
        err(f"Target app not found: {target_app}")
        sys.exit(1)

    # Add target dir to path so app.py imports work
    sys.path.insert(0, str(target_app.parent))
    os.environ["FLASK_APP"]   = str(target_app)
    os.environ["FLASK_ENV"]   = "development"
    os.environ["FLASK_DEBUG"] = "0"

    try:
        from flask import Flask as _Flask   # just confirm flask available
    except ImportError:
        err("Flask not installed. Run: pip install flask pyjwt")
        sys.exit(1)

    subprocess.run(
        [sys.executable, str(target_app)],
        env={**os.environ, "PORT": str(port)},
    )


# ── Command: docker ───────────────────────────────────────────────────────────
def cmd_docker(args):
    banner()
    _require_env_file()

    compose = _compose_cmd()
    pull    = not getattr(args, "no_pull", False)
    build   = getattr(args, "build", False)

    head("Starting all services with Docker Compose")
    info("Services: axiom-backend, vulnerable-api, dvwa, juice-shop, redis-exposed")
    info("Press Ctrl+C to stop (containers keep running unless you run: python run.py docker-down)\n")

    cmd = compose + ["-f", str(ROOT / "docker-compose.yml")]

    if build:
        info("Building images…")
        subprocess.run(cmd + ["build", "--no-cache"], cwd=ROOT, check=True)

    up_flags = ["up", "--remove-orphans"]
    if pull:
        up_flags.append("--pull=missing")

    subprocess.run(cmd + up_flags, cwd=ROOT)


# ── Command: docker-down ──────────────────────────────────────────────────────
def cmd_docker_down(_args):
    banner()
    compose = _compose_cmd()
    head("Stopping and removing all AXIOM RED containers")
    subprocess.run(
        compose + ["-f", str(ROOT / "docker-compose.yml"), "down", "--remove-orphans"],
        cwd=ROOT,
    )
    ok("All containers stopped.")


# ── Command: scan (CLI agent mode) ────────────────────────────────────────────
def cmd_scan(args):
    banner()
    _require_env_file()
    _load_dotenv()
    _setup_sys_path()

    target = args.target
    provider = getattr(args, "llm", None) or os.environ.get("LLM_PROVIDER", "gemini")
    os.environ["LLM_PROVIDER"] = provider

    head(f"CLI Scan Mode  →  Target: {target}")
    info(f"LLM provider: {provider}")
    info("Running full RECON → ANALYSE → PLAN → TEST → VALIDATE → REPORT pipeline")
    info("This runs the agent directly — no backend / WebSocket needed.\n")

    try:
        from agent.core.react_agent import run_agent
        from rich.console import Console
        from rich.table import Table
        from rich import box
        console = Console()
        _rich = True
    except ImportError:
        _rich = False

    start = time.time()

    def on_update(state_dict: dict):
        phase  = state_dict.get("current_phase", "")
        logs   = state_dict.get("activity_log", [])
        if logs:
            last = logs[-1]
            status = last.get("status", "ok")
            colour = {"finding": "red", "error": "yellow", "ok": "green"}.get(status, "white")
            icon   = {"finding": "🔴", "error": "⚠", "ok": "✔"}.get(status, "→")
            if _rich:
                console.print(
                    f"  [{colour}]{icon}[/{colour}]  "
                    f"[bold]{last.get('phase','?')}[/bold]  "
                    f"{last.get('action','')}",
                    highlight=False,
                )
            else:
                print(f"  [{last.get('phase','?')}] {last.get('action','')}")

    try:
        from agent.core.react_agent import run_agent
        final = run_agent(target, on_state_update=on_update)
    except Exception as e:
        err(f"Agent error: {e}")
        sys.exit(1)

    elapsed = time.time() - start

    # ── Summary ──────────────────────────────────────────────────────────────
    print()
    head("Scan Complete")
    info(f"Duration : {elapsed:.1f}s")
    info(f"Findings : {len(final.findings)}")

    if _rich and final.findings:
        table = Table(box=box.ROUNDED, style="dim", border_style="red")
        table.add_column("ID",       style="dim",    no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("CVSS",     justify="right", style="bold")
        table.add_column("Title",    style="white")
        table.add_column("Endpoint", style="cyan",   overflow="fold")

        sev_colour = {"Critical": "red", "High": "orange3",
                      "Medium": "yellow", "Low": "blue", "Info": "white"}
        for i, f in enumerate(final.findings, 1):
            c = sev_colour.get(f.severity, "white")
            table.add_row(
                f"F-{i:03d}",
                f"[{c}]{f.severity}[/{c}]",
                f"[{c}]{f.cvss_score}[/{c}]",
                f.title,
                f.endpoint,
            )
        Console().print(table)
    elif final.findings:
        for i, f in enumerate(final.findings, 1):
            print(f"  F-{i:03d}  [{f.severity}]  CVSS {f.cvss_score}  {f.title}")

    if final.report_path:
        ok(f"Report: {final.report_path}")
    print()


# ── Command: all (backend + targets together) ─────────────────────────────────
def cmd_all(args):
    banner()
    _require_env_file()
    _load_dotenv()
    _setup_sys_path()

    head("Starting backend + vulnerable-api target (no Docker)")
    info("Backend   → http://localhost:8000")
    info("Target    → http://localhost:5000")
    info("Dashboard → http://localhost:8000/")
    info("Press Ctrl+C to stop both.\n")

    processes = []

    def _start(cmd, label):
        proc = subprocess.Popen(
            cmd,
            cwd=ROOT,
            env=os.environ.copy(),
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        info(f"{label} started (PID {proc.pid})")
        processes.append(proc)
        return proc

    backend_cmd = [
        sys.executable, "-m", "uvicorn",
        "backend.main:app",
        "--host", "0.0.0.0",
        "--port", str(getattr(args, "backend_port", 8000)),
        "--workers", "1",
        "--log-level", "info",
    ]

    target_cmd = [
        sys.executable,
        str(ROOT / "targets" / "vulnerable-api" / "app.py"),
    ]

    # Give backend a head start
    _start(backend_cmd, "Backend (FastAPI)")
    time.sleep(1.5)
    _start(target_cmd, "Target (Flask API)")

    def _shutdown(sig, frame):
        warn("\nShutting down all processes…")
        for p in processes:
            try:
                p.terminate()
            except Exception:
                pass
        time.sleep(1)
        for p in processes:
            try:
                p.kill()
            except Exception:
                pass
        ok("Done.")
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Wait for all child processes
    for p in processes:
        p.wait()


# ── CLI Entry Point ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="run.py",
        description="AXIOM RED — Unified Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py check                        # verify environment
  python run.py backend                      # start API server on :8000
  python run.py backend --port 9000          # custom port
  python run.py targets                      # start vulnerable Flask app on :5000
  python run.py all                          # backend + target together
  python run.py docker                       # full docker-compose stack
  python run.py docker --build               # rebuild images first
  python run.py docker-down                  # stop docker stack
  python run.py scan http://localhost:5000   # run agent from CLI
  python run.py scan http://localhost:5000 --llm openai
        """,
    )

    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = False

    # check
    sub.add_parser("check", help="Verify environment, packages, and API keys")

    # backend
    p_back = sub.add_parser("backend", help="Start the FastAPI backend server")
    p_back.add_argument("--host", default="0.0.0.0",  help="Bind host (default: 0.0.0.0)")
    p_back.add_argument("--port", default=8000, type=int, help="Port (default: 8000)")

    # targets
    p_tgt = sub.add_parser("targets", help="Start the vulnerable Flask API target")
    p_tgt.add_argument("--port", default=5000, type=int, help="Port (default: 5000)")

    # docker
    p_doc = sub.add_parser("docker", help="Start full stack with docker-compose")
    p_doc.add_argument("--build",   action="store_true", help="Rebuild images before starting")
    p_doc.add_argument("--no-pull", action="store_true", help="Skip pulling base images")

    # docker-down
    sub.add_parser("docker-down", help="Stop and remove all Docker containers")

    # scan
    p_scan = sub.add_parser("scan", help="Run agent directly from CLI (no backend needed)")
    p_scan.add_argument("target", help="Target URL, e.g. http://localhost:5000")
    p_scan.add_argument("--llm",  default=None,
                        choices=["gemini", "openai"],
                        help="LLM provider override (default: from .env)")

    # all
    p_all = sub.add_parser("all", help="Start backend + vulnerable target together")
    p_all.add_argument("--backend-port", default=8000, type=int, dest="backend_port")

    args = parser.parse_args()

    dispatch = {
        "check":       cmd_check,
        "backend":     cmd_backend,
        "targets":     cmd_targets,
        "docker":      cmd_docker,
        "docker-down": cmd_docker_down,
        "scan":        cmd_scan,
        "all":         cmd_all,
        None:          lambda _: (banner(), parser.print_help()),
    }

    handler = dispatch.get(args.command, lambda _: parser.print_help())
    handler(args)


if __name__ == "__main__":
    main()
