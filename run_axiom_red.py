#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                      AXIOM RED — UNIFIED MISSION LAUNCHER                  ║
║                                                                            ║
║   One script to rule them all: checks, installs, launches, monitors,       ║
║   and logs the entire AXIOM RED platform (backend + frontend).             ║
║                                                                            ║
║   Usage:   python run_axiom_red.py                                         ║
║            python run_axiom_red.py --skip-install                          ║
║            python run_axiom_red.py --backend-port 9000 --target-port 6000  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import datetime
import io
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import textwrap
import threading
import time
import traceback
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════
ROOT = Path(__file__).parent.resolve()
ENV_FILE = ROOT / ".env"
ENV_EXAMPLE = ROOT / ".env.example"
REQUIREMENTS = ROOT / "requirements.txt"
LOGS_DIR = ROOT / "logs"
REPORTS_DIR = ROOT / "reports"

BACKEND_MODULE = "backend.main:app"
TARGET_SCRIPT = ROOT / "targets" / "vulnerable-api" / "app.py"
DASHBOARD_DIR = ROOT / "dashboard"

# Ensure UTF-8 on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════════════════════════
#  ANSI COLOUR SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════
_FORCE = os.environ.get("FORCE_COLOR")
_TTY = sys.stdout.isatty() or _FORCE

# Enable ANSI on Windows 10+
if os.name == "nt":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        _TTY = True
    except Exception:
        pass

def _c(code):
    return f"\033[{code}m" if _TTY else ""

# Core colours
RST   = _c(0)
BOLD  = _c(1)
DIM   = _c(2)
ITAL  = _c(3)
ULINE = _c(4)
BLINK = _c(5)

# Foreground
BLACK   = _c(30)
RED     = _c(91)
GREEN   = _c(92)
YELLOW  = _c(93)
BLUE    = _c(94)
MAGENTA = _c(95)
CYAN    = _c(96)
WHITE   = _c(97)
GRAY    = _c(90)

# Background
BG_RED    = _c(41)
BG_GREEN  = _c(42)
BG_YELLOW = _c(43)
BG_BLUE   = _c(44)
BG_GRAY   = _c(100)

# ═══════════════════════════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════════════════════════
_LOG_LOCK = threading.Lock()
_LOG_FILE = None


def _init_log():
    global _LOG_FILE
    LOGS_DIR.mkdir(exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = LOGS_DIR / f"axiom_red_{ts}.log"
    _LOG_FILE = open(log_path, "w", encoding="utf-8")
    return log_path


def _log(msg: str):
    """Write to both terminal and log file (thread-safe)."""
    with _LOG_LOCK:
        print(msg, flush=True)
        if _LOG_FILE:
            # Strip ANSI for the log file
            clean = re.sub(r"\033\[[0-9;]*m", "", msg)
            _LOG_FILE.write(clean + "\n")
            _LOG_FILE.flush()


def _log_raw(msg: str):
    """Write only to log file."""
    with _LOG_LOCK:
        if _LOG_FILE:
            clean = re.sub(r"\033\[[0-9;]*m", "", msg)
            _LOG_FILE.write(clean + "\n")
            _LOG_FILE.flush()


# ═══════════════════════════════════════════════════════════════════════════════
#  PRETTY PRINTERS
# ═══════════════════════════════════════════════════════════════════════════════
def ok(msg):       _log(f"  {GREEN}✔{RST}  {msg}")
def warn(msg):     _log(f"  {YELLOW}⚠{RST}  {YELLOW}{msg}{RST}")
def err(msg):      _log(f"  {RED}✘{RST}  {RED}{msg}{RST}")
def info(msg):     _log(f"  {CYAN}→{RST}  {msg}")
def debug(msg):    _log(f"  {GRAY}·{RST}  {DIM}{msg}{RST}")
def head(msg):     _log(f"\n  {BOLD}{BLUE}{'─' * 60}{RST}\n  {BOLD}{BLUE}  {msg}{RST}\n  {BOLD}{BLUE}{'─' * 60}{RST}")
def subhead(msg):  _log(f"\n  {BOLD}{CYAN}▸ {msg}{RST}")
def divider():     _log(f"  {DIM}{'━' * 62}{RST}")

def tag(label, colour, msg):
    _log(f"  {colour}{BOLD}[{label}]{RST} {msg}")

def backend_log(msg):
    tag("BACKEND ", BG_BLUE + WHITE, msg)

def target_log(msg):
    tag("TARGET  ", BG_YELLOW + BLACK, msg)

def system_log(msg):
    tag("SYSTEM  ", BG_GRAY + WHITE, msg)

def success_box(msg):
    w = len(msg) + 4
    _log(f"\n  {GREEN}╔{'═' * w}╗{RST}")
    _log(f"  {GREEN}║  {BOLD}{msg}{RST}{GREEN}  ║{RST}")
    _log(f"  {GREEN}╚{'═' * w}╝{RST}\n")

def error_box(msg):
    w = len(msg) + 4
    _log(f"\n  {RED}╔{'═' * w}╗{RST}")
    _log(f"  {RED}║  {BOLD}{msg}{RST}{RED}  ║{RST}")
    _log(f"  {RED}╚{'═' * w}╝{RST}\n")


# ═══════════════════════════════════════════════════════════════════════════════
#  BANNER & PROJECT BRIEFING
# ═══════════════════════════════════════════════════════════════════════════════
BANNER = f"""{RED}{BOLD}
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║      █████╗ ██╗  ██╗██╗ ██████╗ ███╗   ███╗                 ║
    ║     ██╔══██╗╚██╗██╔╝██║██╔═══██╗████╗ ████║                 ║
    ║     ███████║ ╚███╔╝ ██║██║   ██║██╔████╔██║                 ║
    ║     ██╔══██║ ██╔██╗ ██║██║   ██║██║╚██╔╝██║                 ║
    ║     ██║  ██║██╔╝ ██╗██║╚██████╔╝██║ ╚═╝ ██║                 ║
    ║     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝     ╚═╝                 ║
    ║                                                              ║
    ║          {WHITE}██████╗ ███████╗██████╗{RED}                            ║
    ║          {WHITE}██╔══██╗██╔════╝██╔══██╗{RED}                           ║
    ║          {WHITE}██████╔╝█████╗  ██║  ██║{RED}                           ║
    ║          {WHITE}██╔══██╗██╔══╝  ██║  ██║{RED}                           ║
    ║          {WHITE}██║  ██║███████╗██████╔╝{RED}                           ║
    ║          {WHITE}╚═╝  ╚═╝╚══════╝╚═════╝{RED}                            ║
    ║                                                              ║
    ║     {CYAN}AI-Powered Autonomous Red-Team Agent{RED}                   ║
    ║     {DIM}{WHITE}Spectrona 2026 · NFSU Guwahati{RED}                       ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝{RST}
"""


def print_project_brief():
    """Display a comprehensive project briefing before launch."""
    _log(BANNER)
    _log(f"  {DIM}Root Directory: {ROOT}{RST}")
    _log(f"  {DIM}Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RST}")
    _log(f"  {DIM}Platform: {platform.system()} {platform.release()} ({platform.machine()}){RST}")
    _log(f"  {DIM}Python: {sys.version.split()[0]}{RST}")
    _log("")

    head("📋 PROJECT BRIEFING")

    subhead("Problem Statement")
    _log(f"""  {WHITE}\"Teach AI to Break It\" — Build an AI-powered red-team agent that{RST}
  {WHITE}autonomously analyses a controlled vulnerable environment, identifies{RST}
  {WHITE}security weaknesses, and demonstrates exploitation — with forensic-{RST}
  {WHITE}grade evidence that is cryptographically verifiable.{RST}""")

    subhead("What AXIOM RED Does")
    _log(f"""  {WHITE}A LangGraph state-machine agent running the full offensive lifecycle:{RST}
  {CYAN}  🔍 RECON → 🧠 ANALYSE → 🗺️ PLAN → ⚔️ TEST → 🔁 REFLECT → ✅ VALIDATE → 🔒 EVIDENCE → 📄 REPORT{RST}""")

    subhead("Key Features")
    features = [
        ("🔁 Adaptive Reflect-Loop",       "Re-plans and loops when new attacks are unlocked"),
        ("🧠 Knowledge Base",              "Persistent belief state across attack steps"),
        ("⛓️  Attack Chaining",             "Leaked secrets → forged tokens → full PII breach"),
        ("🔒 Tamper-Evident Evidence",      "SHA-256 chain-of-custody + one-command verifier"),
        ("🔬 Differential Proof",           "Boolean/time differential + unique canary proofs"),
        ("🛡️  Fail-Closed Scope Guard",      "Refuses any host outside authorised scope"),
        ("📡 Live Reasoning Dashboard",     "Real-time Thought → Action → Result via WebSocket"),
        ("📊 Benchmark Harness",            "Coverage scoring vs ground-truth vulnerabilities"),
    ]
    for icon_title, desc in features:
        _log(f"    {GREEN}•{RST} {BOLD}{icon_title}{RST}  {DIM}— {desc}{RST}")

    subhead("Architecture Overview")
    _log(f"""    {CYAN}┌─────────────────────────────────────────────────────────┐{RST}
    {CYAN}│{RST}  {BOLD}Dashboard{RST} (HTML/CSS/JS) ←──WebSocket──→ {BOLD}FastAPI Backend{RST}  {CYAN}│{RST}
    {CYAN}│{RST}                                           │              {CYAN}│{RST}
    {CYAN}│{RST}                                  {BOLD}LangGraph Agent{RST}        {CYAN}│{RST}
    {CYAN}│{RST}                                     │     │              {CYAN}│{RST}
    {CYAN}│{RST}                               reason │     │ attack      {CYAN}│{RST}
    {CYAN}│{RST}                                     ↕     ↓              {CYAN}│{RST}
    {CYAN}│{RST}                                  {BOLD}LLM{RST}   {BOLD}Sandbox{RST}          {CYAN}│{RST}
    {CYAN}│{RST}                              (Gemini)  (Flask API)      {CYAN}│{RST}
    {CYAN}└─────────────────────────────────────────────────────────┘{RST}""")

    subhead("Vulnerabilities in Target API")
    vulns = [
        ("IDOR",                 "9.8",  "A01", "/api/v1/users/<id>"),
        ("SQL Injection",        "9.1",  "A03", "/api/v1/search?q="),
        ("JWT alg:none Bypass",  "9.3",  "A02", "/api/v1/admin"),
        ("Command Injection",    "9.8",  "A03", "/api/v1/ping?host="),
        ("Config Exposure",      "7.7",  "A05", "/api/v1/config"),
        ("Unrestricted Upload",  "8.0",  "A04", "/api/v1/upload"),
        ("Reflected XSS",        "7.2",  "A03", "/api/v1/greet?name="),
        ("Stored XSS",           "8.8",  "A03", "/api/v1/comment"),
    ]
    _log(f"    {DIM}{'Vulnerability':<25} {'CVSS':>5}  {'OWASP':>5}  {'Endpoint'}{RST}")
    _log(f"    {DIM}{'─' * 65}{RST}")
    for name, cvss, owasp, ep in vulns:
        sev_colour = RED if float(cvss) >= 9.0 else YELLOW if float(cvss) >= 7.0 else GREEN
        _log(f"    {WHITE}{name:<25}{RST} {sev_colour}{cvss:>5}{RST}  {CYAN}{owasp:>5}{RST}  {DIM}{ep}{RST}")

    subhead("Team")
    _log(f"    {BOLD}Team Lead:{RST} Himanshu Yadav")
    _log(f"    {DIM}A. Tanmayee · Om Prakash · Raju Ranjan · Umesh Gupta{RST}")
    _log(f"    {DIM}National Forensic Sciences University · Guwahati Campus{RST}")
    _log("")


# ═══════════════════════════════════════════════════════════════════════════════
#  ENVIRONMENT & DEPENDENCY CHECKS
# ═══════════════════════════════════════════════════════════════════════════════
def check_python():
    """Verify Python >= 3.10."""
    v = sys.version_info
    if v >= (3, 10):
        ok(f"Python {v.major}.{v.minor}.{v.micro}")
        return True
    else:
        err(f"Python {v.major}.{v.minor} detected — requires ≥ 3.10")
        return False


def check_env_file():
    """Check for .env, offer to create from .env.example."""
    if ENV_FILE.exists():
        ok(f".env file found")
        return True

    warn(".env file not found!")
    if ENV_EXAMPLE.exists():
        info("Found .env.example — creating .env from template...")
        shutil.copy(ENV_EXAMPLE, ENV_FILE)
        ok("Created .env from .env.example")
        warn("⚠  Please edit .env and set your API keys (GOOGLE_API_KEY or OPENAI_API_KEY)")
        warn("   The project will attempt to start but LLM features need valid keys.")
        return True
    else:
        err("No .env.example found either! Creating minimal .env...")
        ENV_FILE.write_text(
            "LLM_PROVIDER=gemini\n"
            "GOOGLE_API_KEY=your_google_api_key_here\n"
            "OPENAI_API_KEY=your_openai_api_key_here\n"
        )
        warn("Created minimal .env — please add your API keys!")
        return True


def load_dotenv():
    """Load .env into os.environ without third-party deps."""
    if not ENV_FILE.exists():
        return
    with open(ENV_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())


def check_api_keys():
    """Verify LLM API keys are configured."""
    provider = os.environ.get("LLM_PROVIDER", "gemini").lower()
    issues = []

    if provider == "gemini":
        key = os.environ.get("GOOGLE_API_KEY", "")
        if key and not key.startswith("your_"):
            ok(f"GOOGLE_API_KEY configured (provider=gemini)")
        else:
            warn("GOOGLE_API_KEY missing or placeholder — LLM features won't work")
            issues.append("GOOGLE_API_KEY")
    elif provider == "openai":
        key = os.environ.get("OPENAI_API_KEY", "")
        if key and not key.startswith("your_"):
            ok(f"OPENAI_API_KEY configured (provider=openai)")
        else:
            warn("OPENAI_API_KEY missing or placeholder — LLM features won't work")
            issues.append("OPENAI_API_KEY")
    elif provider == "ollama":
        ok(f"LLM_PROVIDER=ollama (no API key needed, ensure Ollama is running)")
    else:
        warn(f"Unknown LLM_PROVIDER={provider}")

    return issues


def check_directories():
    """Verify all required project directories exist."""
    required = {
        "agent":     "Agent core (LangGraph engine)",
        "backend":   "FastAPI backend server",
        "dashboard": "Live reasoning dashboard (HTML/JS)",
        "reports":   "Generated reports output",
        "targets":   "Vulnerable target applications",
    }
    all_good = True
    for d, desc in required.items():
        p = ROOT / d
        if p.exists():
            ok(f"./{d}/  — {DIM}{desc}{RST}")
        else:
            err(f"./{d}/ MISSING! — {desc}")
            all_good = False

    REPORTS_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)
    return all_good


def check_packages():
    """
    Check all required Python packages. Returns (installed, missing) lists.
    """
    # Map: import_name → (pip_name, description)
    packages = {
        "fastapi":                ("fastapi",              "FastAPI (backend server)"),
        "uvicorn":                ("uvicorn[standard]",    "Uvicorn (ASGI server)"),
        "langgraph":              ("langgraph",            "LangGraph (agent graph engine)"),
        "langchain_core":         ("langchain",            "LangChain core"),
        "langchain_google_genai": ("langchain-google-genai", "LangChain Gemini provider"),
        "langchain_openai":       ("langchain-openai",     "LangChain OpenAI provider"),
        "httpx":                  ("httpx",                "httpx (async HTTP client)"),
        "pydantic":               ("pydantic",             "Pydantic (data models)"),
        "jinja2":                 ("jinja2",               "Jinja2 (report templating)"),
        "redis":                  ("redis",                "redis-py (Redis attacks)"),
        "flask":                  ("flask",                "Flask (vulnerable target API)"),
        "jwt":                    ("pyjwt",                "PyJWT (JWT attack tools)"),
        "rich":                   ("rich",                 "Rich (terminal formatting)"),
        "websockets":             ("websockets",           "WebSockets (live dashboard)"),
        "dotenv":                 ("python-dotenv",        "python-dotenv (env loading)"),
        "bs4":                    ("beautifulsoup4",       "BeautifulSoup (HTML parsing)"),
        "requests":               ("requests",             "Requests (HTTP fallback)"),
        "aiofiles":               ("aiofiles",             "aiofiles (async file I/O)"),
    }

    installed = []
    missing = []

    for import_name, (pip_name, desc) in packages.items():
        try:
            __import__(import_name)
            ok(f"{desc}")
            installed.append(pip_name)
        except ImportError:
            err(f"{desc}  {DIM}→ pip install {pip_name}{RST}")
            missing.append((pip_name, desc))

    return installed, missing


def install_packages(missing_list):
    """Install missing packages using pip."""
    if not missing_list:
        return True

    pkg_names = [p[0] for p in missing_list]
    divider()
    _log(f"\n  {YELLOW}{BOLD}📦 {len(missing_list)} package(s) need to be installed:{RST}")
    for pip_name, desc in missing_list:
        _log(f"     {YELLOW}•{RST} {pip_name}  {DIM}({desc}){RST}")
    _log("")

    try:
        answer = input(f"  {CYAN}Install all missing packages now? [Y/n]: {RST}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        _log("")
        err("Installation cancelled.")
        return False

    if answer and answer != "y":
        warn("Skipping installation. Some features may not work.")
        return False

    _log("")
    info(f"Installing {len(pkg_names)} package(s)...")
    _log("")

    # Try from requirements.txt first (preferred — has pinned versions)
    if REQUIREMENTS.exists():
        info(f"Using {REQUIREMENTS.name} for version-pinned install...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS)],
            capture_output=False,
            cwd=str(ROOT),
        )
        if result.returncode == 0:
            success_box("All packages installed successfully!")
            return True
        else:
            warn("requirements.txt install had issues, falling back to individual install...")

    # Fallback: install individually
    failed = []
    for pip_name, desc in missing_list:
        info(f"Installing {pip_name}...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", pip_name],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            ok(f"Installed {pip_name}")
        else:
            err(f"Failed to install {pip_name}")
            _log_raw(result.stderr)
            failed.append(pip_name)

    if failed:
        error_box(f"{len(failed)} package(s) failed to install: {', '.join(failed)}")
        return False

    success_box("All packages installed successfully!")
    return True


def check_port_available(port: int) -> bool:
    """Check if a TCP port is available."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.bind(("127.0.0.1", port))
            return True
    except OSError:
        return False


def check_docker():
    """Check Docker availability (informational, not required)."""
    if shutil.which("docker"):
        try:
            result = subprocess.run(
                ["docker", "info"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                ok("Docker daemon is running")
                return True
            else:
                warn("Docker installed but daemon not running")
                return False
        except Exception:
            warn("Docker check timed out")
            return False
    else:
        info(f"Docker not found {DIM}(optional — only needed for full sandbox mode){RST}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
#  PROCESS MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════
_PROCESSES = []
_SHUTDOWN_EVENT = threading.Event()


def stream_output(proc, label, colour, log_fn):
    """Read stdout/stderr from a subprocess and log each line with a tag."""
    try:
        for raw_line in iter(proc.stdout.readline, b""):
            if _SHUTDOWN_EVENT.is_set():
                break
            try:
                line = raw_line.decode("utf-8", errors="replace").rstrip()
            except Exception:
                line = str(raw_line).rstrip()
            if line:
                log_fn(line)
                _log_raw(f"[{label}] {line}")
    except Exception:
        pass


def wait_for_port(port: int, timeout: float = 15.0) -> bool:
    """Block until a TCP port is accepting connections, or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _SHUTDOWN_EVENT.is_set():
            return False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect(("127.0.0.1", port))
                return True
        except (ConnectionRefusedError, OSError, socket.timeout):
            time.sleep(0.5)
    return False


def health_check(url: str, timeout: float = 5.0) -> bool:
    """Simple HTTP GET health check."""
    try:
        import urllib.request
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def start_process(cmd, label, colour, log_fn, env=None, cwd=None):
    """Start a subprocess with streamed output."""
    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    # Force unbuffered Python output
    full_env["PYTHONUNBUFFERED"] = "1"

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=full_env,
        cwd=cwd or str(ROOT),
        bufsize=0,
    )

    thread = threading.Thread(
        target=stream_output,
        args=(proc, label, colour, log_fn),
        daemon=True,
        name=f"stream-{label}",
    )
    thread.start()

    _PROCESSES.append((proc, label, thread))
    return proc


def shutdown_all():
    """Gracefully terminate all child processes."""
    _SHUTDOWN_EVENT.set()
    system_log(f"{YELLOW}Shutting down all processes...{RST}")

    for proc, label, thread in _PROCESSES:
        try:
            if proc.poll() is None:
                system_log(f"Terminating {label} (PID {proc.pid})...")
                proc.terminate()
        except Exception:
            pass

    # Wait up to 5 seconds for graceful exit
    deadline = time.time() + 5
    for proc, label, thread in _PROCESSES:
        try:
            remaining = max(0.1, deadline - time.time())
            proc.wait(timeout=remaining)
            system_log(f"{label} exited (code {proc.returncode})")
        except subprocess.TimeoutExpired:
            system_log(f"{YELLOW}Force-killing {label}...{RST}")
            try:
                proc.kill()
            except Exception:
                pass
        except Exception:
            pass

    success_box("All processes stopped. Goodbye!")


# ═══════════════════════════════════════════════════════════════════════════════
#  HEALTH MONITOR (background thread)
# ═══════════════════════════════════════════════════════════════════════════════
def health_monitor(backend_port, target_port, interval=30):
    """Periodically check if both services are alive."""
    time.sleep(20)  # Let things stabilize first
    while not _SHUTDOWN_EVENT.is_set():
        for proc, label, _ in _PROCESSES:
            if proc.poll() is not None:
                error_box(f"{label} CRASHED (exit code {proc.returncode})")
                _log(f"  {RED}Check the log file for details.{RST}")
                _log_raw(f"[HEALTH] {label} crashed with exit code {proc.returncode}")

        _SHUTDOWN_EVENT.wait(interval)


# ═══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE API KEY SETUP
# ═══════════════════════════════════════════════════════════════════════════════
def _prompt_and_save_api_key():
    """
    Interactively ask the user to paste their Gemini API key if the current
    one is missing or a placeholder. Saves it directly to .env so it persists.
    """
    provider = os.environ.get("LLM_PROVIDER", "gemini").lower()

    if provider == "ollama":
        ok("LLM_PROVIDER=ollama — no API key needed")
        return

    # Determine which key to check
    if provider == "openai":
        key_name = "OPENAI_API_KEY"
        display_name = "OpenAI"
    else:
        key_name = "GOOGLE_API_KEY"
        display_name = "Gemini"

    current_key = os.environ.get(key_name, "")
    placeholder_prefixes = ("your_", "sk-your", "placeholder", "")

    # Check if key is valid (not a placeholder)
    is_placeholder = (
        not current_key
        or any(current_key.lower().startswith(p) for p in placeholder_prefixes if p)
        or current_key == ""
    )

    if not is_placeholder:
        ok(f"{display_name} API key is configured ({DIM}{key_name}={current_key[:8]}...{RST})")
        _show_fallback_models()
        return

    # ── Ask user for their key ───────────────────────────────────────
    _log("")
    _log(f"  {YELLOW}{BOLD}🔑 API KEY SETUP{RST}")
    _log(f"  {YELLOW}{'─' * 50}{RST}")
    _log(f"  {WHITE}AXIOM RED needs a {BOLD}{display_name} API key{RST}{WHITE} to power the AI agent.{RST}")
    _log(f"  {DIM}Get one free at: https://aistudio.google.com/apikey{RST}")
    _log(f"  {DIM}The key will be saved to .env and reused on future runs.{RST}")
    _log("")

    try:
        user_key = input(f"  {CYAN}🔑 Paste your {display_name} API key here (or press Enter to skip): {RST}").strip()
    except (EOFError, KeyboardInterrupt):
        _log("")
        warn("Skipped API key setup.")
        return

    if not user_key:
        warn("No key entered. LLM features will not work until a key is configured.")
        return

    # ── Save to .env ─────────────────────────────────────────────────
    _save_key_to_env(key_name, user_key)
    os.environ[key_name] = user_key
    success_box(f"{display_name} API key saved to .env!")
    _show_fallback_models()


def _save_key_to_env(key_name: str, value: str):
    """Write or update a key=value pair in the .env file."""
    if not ENV_FILE.exists():
        ENV_FILE.write_text(f"{key_name}={value}\n", encoding="utf-8")
        return

    lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
    found = False
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(f"{key_name}=") or stripped.startswith(f"{key_name} ="):
            new_lines.append(f"{key_name}={value}")
            found = True
        else:
            new_lines.append(line)

    if not found:
        new_lines.append(f"{key_name}={value}")

    ENV_FILE.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def _show_fallback_models():
    """Display the configured Gemini fallback model chain."""
    provider = os.environ.get("LLM_PROVIDER", "gemini").lower()
    if provider != "gemini":
        return

    fallback_str = os.environ.get("GEMINI_FALLBACK_MODELS", "")
    if fallback_str:
        models = [m.strip() for m in fallback_str.split(",") if m.strip()]
    else:
        primary = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        models = [primary]

    _log(f"  {DIM}Gemini model fallback chain:{RST}")
    for i, model in enumerate(models):
        arrow = f"{GREEN}▶{RST}" if i == 0 else f"{DIM}→{RST}"
        label = f" {BOLD}(primary){RST}" if i == 0 else f" {DIM}(fallback {i}){RST}"
        _log(f"    {arrow} {model}{label}")
    _log("")


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN LAUNCH SEQUENCE
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="AXIOM RED — Unified Mission Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--backend-port", type=int, default=8000,
                        help="Backend (FastAPI) port (default: 8000)")
    parser.add_argument("--target-port", type=int, default=5000,
                        help="Vulnerable target (Flask) port (default: 5000)")
    parser.add_argument("--skip-install", action="store_true",
                        help="Skip package installation prompts")
    parser.add_argument("--no-target", action="store_true",
                        help="Don't start the vulnerable target API")
    parser.add_argument("--no-briefing", action="store_true",
                        help="Skip project briefing display")
    args = parser.parse_args()

    bp = args.backend_port
    tp = args.target_port

    # ── Initialize logging ───────────────────────────────────────────
    log_path = _init_log()

    # ── 0. Banner & Briefing ─────────────────────────────────────────
    if not args.no_briefing:
        print_project_brief()
    else:
        _log(BANNER)

    head("🚀 LAUNCH SEQUENCE INITIATED")
    info(f"Log file: {DIM}{log_path}{RST}")
    _log("")

    # ── 1. Python Version ────────────────────────────────────────────
    subhead("Step 1/7 — Python Environment")
    if not check_python():
        error_box("Python 3.10+ required. Aborting.")
        sys.exit(1)

    # ── 2. Environment & API Key Setup ────────────────────────────────
    subhead("Step 2/7 — Environment & API Key Configuration")
    check_env_file()
    load_dotenv()

    # Interactive API key prompt — ask user to paste key if missing/placeholder
    _prompt_and_save_api_key()

    # Reload .env after potential key update
    load_dotenv()
    api_issues = check_api_keys()

    # ── 3. Project Structure ─────────────────────────────────────────
    subhead("Step 3/7 — Project Structure Verification")
    if not check_directories():
        error_box("Critical directories missing. Aborting.")
        sys.exit(1)

    # Verify critical files
    critical_files = [
        ("backend/main.py",                "FastAPI application"),
        ("targets/vulnerable-api/app.py",  "Vulnerable target API"),
        ("dashboard/index.html",           "Dashboard HTML"),
        ("dashboard/app.js",               "Dashboard JavaScript"),
        ("dashboard/style.css",            "Dashboard Styles"),
        ("agent/core/react_agent.py",      "LangGraph agent core"),
        ("agent/core/state.py",            "Agent state model"),
        ("agent/tools/attacks.py",         "Attack tool library"),
        ("agent/tools/recon.py",           "Recon tool library"),
        ("verify.py",                      "Evidence chain verifier"),
    ]
    for fpath, desc in critical_files:
        p = ROOT / fpath
        if p.exists():
            ok(f"{fpath}  {DIM}({desc}){RST}")
        else:
            err(f"{fpath} MISSING — {desc}")

    # ── 4. Package Dependencies ──────────────────────────────────────
    subhead("Step 4/7 — Python Package Dependencies")
    installed, missing = check_packages()

    if missing and not args.skip_install:
        if not install_packages(missing):
            warn("Some packages may be missing. Attempting to proceed anyway...")
        _log("")
        # Re-check after install
        _, still_missing = check_packages()
        if still_missing:
            critical_pkgs = {"fastapi", "uvicorn[standard]", "flask", "pyjwt"}
            critical_missing = [p for p, _ in still_missing if p in critical_pkgs]
            if critical_missing:
                error_box(f"Critical packages still missing: {', '.join(critical_missing)}")
                err("Cannot start without these. Please install manually and retry.")
                sys.exit(1)
            warn(f"{len(still_missing)} non-critical packages still missing. Proceeding...")
    elif missing and args.skip_install:
        warn(f"{len(missing)} packages missing (--skip-install used)")
    else:
        success_box("All dependencies satisfied!")

    # ── 5. Port Availability ─────────────────────────────────────────
    subhead("Step 5/7 — Port Availability")

    if check_port_available(bp):
        ok(f"Port {bp} is available (Backend)")
    else:
        warn(f"Port {bp} is in use! Backend may fail to start.")
        warn(f"Try: python run_axiom_red.py --backend-port {bp + 1}")

    if not args.no_target:
        if check_port_available(tp):
            ok(f"Port {tp} is available (Target API)")
        else:
            warn(f"Port {tp} is in use! Target may fail to start.")
            warn(f"Try: python run_axiom_red.py --target-port {tp + 1}")

    # ── 5b. Docker (informational) ───────────────────────────────────
    subhead("Step 6/7 — Docker (Optional)")
    check_docker()

    # ── 6. Launch Services ───────────────────────────────────────────
    head("🔥 LAUNCHING SERVICES")
    _log("")

    # Setup signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        _log("")
        system_log(f"{YELLOW}Received interrupt signal (Ctrl+C){RST}")
        shutdown_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    # ── 6a. Start Vulnerable Target API ──────────────────────────────
    if not args.no_target:
        info(f"Starting Vulnerable Target API on port {tp}...")
        target_cmd = [
            sys.executable, str(TARGET_SCRIPT),
        ]
        target_env = {"PORT": str(tp), "FLASK_ENV": "development", "FLASK_DEBUG": "0"}
        target_proc = start_process(
            target_cmd, "TARGET", BG_YELLOW, target_log, env=target_env
        )
        info(f"Target API PID: {target_proc.pid}")

        # Wait for target to be ready
        info(f"Waiting for Target API to start on :{tp}...")
        if wait_for_port(tp, timeout=15):
            ok(f"Target API is UP on port {tp}")
        else:
            warn(f"Target API not responding on :{tp} yet (may still be starting)")
        _log("")

    # ── 6b. Start FastAPI Backend ────────────────────────────────────
    info(f"Starting FastAPI Backend on port {bp}...")
    backend_cmd = [
        sys.executable, "-m", "uvicorn",
        BACKEND_MODULE,
        "--host", "0.0.0.0",
        "--port", str(bp),
        "--workers", "1",
        "--log-level", "info",
    ]
    backend_proc = start_process(
        backend_cmd, "BACKEND", BG_BLUE, backend_log
    )
    info(f"Backend PID: {backend_proc.pid}")

    # Wait for backend to be ready
    info(f"Waiting for Backend to start on :{bp}...")
    if wait_for_port(bp, timeout=20):
        ok(f"Backend is UP on port {bp}")
    else:
        warn(f"Backend not responding on :{bp} yet (may still be starting)")
    _log("")

    # ── 7. Launch Summary ────────────────────────────────────────────
    head("✅ ALL SYSTEMS GO")
    _log("")

    _log(f"  {GREEN}{BOLD}┌─────────────────────────────────────────────────────────────┐{RST}")
    _log(f"  {GREEN}{BOLD}│                     SERVICE ENDPOINTS                       │{RST}")
    _log(f"  {GREEN}{BOLD}├─────────────────────────────────────────────────────────────┤{RST}")
    _log(f"  {GREEN}{BOLD}│{RST}                                                             {GREEN}{BOLD}│{RST}")
    _log(f"  {GREEN}{BOLD}│{RST}  {CYAN}📊 Dashboard:{RST}     {BOLD}{ULINE}http://localhost:{bp}/{RST}                  {GREEN}{BOLD}│{RST}")
    _log(f"  {GREEN}{BOLD}│{RST}  {BLUE}⚡ Backend API:{RST}    {BOLD}{ULINE}http://localhost:{bp}/docs{RST}             {GREEN}{BOLD}│{RST}")
    _log(f"  {GREEN}{BOLD}│{RST}  {MAGENTA}🔌 WebSocket:{RST}      {BOLD}ws://localhost:{bp}/ws/<session>{RST}         {GREEN}{BOLD}│{RST}")
    if not args.no_target:
        _log(f"  {GREEN}{BOLD}│{RST}  {YELLOW}🎯 Target API:{RST}     {BOLD}{ULINE}http://localhost:{tp}/{RST}                  {GREEN}{BOLD}│{RST}")
    _log(f"  {GREEN}{BOLD}│{RST}                                                             {GREEN}{BOLD}│{RST}")
    _log(f"  {GREEN}{BOLD}│{RST}  {DIM}📁 Logs:           {log_path}{RST}      {GREEN}{BOLD}│{RST}")
    _log(f"  {GREEN}{BOLD}│{RST}  {DIM}📄 Reports:        {REPORTS_DIR}/{RST}               {GREEN}{BOLD}│{RST}")
    _log(f"  {GREEN}{BOLD}│{RST}                                                             {GREEN}{BOLD}│{RST}")
    _log(f"  {GREEN}{BOLD}└─────────────────────────────────────────────────────────────┘{RST}")
    _log("")

    _log(f"  {BOLD}🎮 QUICK START:{RST}")
    _log(f"     1. Open {CYAN}{ULINE}http://localhost:{bp}/{RST} in your browser")
    _log(f"     2. Enter target: {YELLOW}http://localhost:{tp}{RST}")
    _log(f"     3. Click {GREEN}▶ Launch AXIOM RED{RST}")
    _log(f"     4. Watch the AI reason, attack, and report in real time!")
    _log("")

    if api_issues:
        _log(f"  {YELLOW}{BOLD}⚠  WARNING:{RST} {YELLOW}LLM API keys not configured.{RST}")
        _log(f"  {YELLOW}   Edit .env and set your API key, or use Demo Mode in the dashboard.{RST}")
        _log("")

    _log(f"  {DIM}Press {BOLD}Ctrl+C{RST}{DIM} to stop all services.{RST}")
    divider()
    _log("")

    # ── 8. Start health monitor ──────────────────────────────────────
    health_thread = threading.Thread(
        target=health_monitor,
        args=(bp, tp),
        daemon=True,
        name="health-monitor",
    )
    health_thread.start()

    # ── 9. Stream logs until interrupted ─────────────────────────────
    _log(f"  {GRAY}{'═' * 62}{RST}")
    _log(f"  {GRAY}{BOLD}  LIVE LOG STREAM (Backend + Target){RST}")
    _log(f"  {GRAY}{'═' * 62}{RST}")
    _log("")

    try:
        # Wait for all child processes to exit (blocks main thread)
        while not _SHUTDOWN_EVENT.is_set():
            all_dead = True
            for proc, label, _ in _PROCESSES:
                if proc.poll() is None:
                    all_dead = False
                    break
            if all_dead:
                system_log("All processes have exited.")
                break
            _SHUTDOWN_EVENT.wait(1)  # Check every second

    except KeyboardInterrupt:
        pass
    finally:
        if not _SHUTDOWN_EVENT.is_set():
            shutdown_all()
        if _LOG_FILE:
            _LOG_FILE.close()


# ═══════════════════════════════════════════════════════════════════════════════
#  POTENTIAL ISSUES ANALYSIS (printed before launch)
# ═══════════════════════════════════════════════════════════════════════════════
# Documented here for reference — these are inspected during the check phase:
#
#  1. Missing .env file → auto-created from .env.example
#  2. Missing API keys → warned, LLM features disabled
#  3. Port conflicts → warned with alternative suggestions
#  4. Missing packages → prompted for install
#  5. Python < 3.10 → hard abort
#  6. Flask target crash → health monitor detects and reports
#  7. Backend crash → health monitor detects and reports
#  8. Windows encoding → UTF-8 reconfigured at startup
#  9. ANSI colour support → auto-detected, Windows VT100 enabled via ctypes
# 10. Thread safety → all logging uses a lock, processes stream via dedicated threads


if __name__ == "__main__":
    main()
