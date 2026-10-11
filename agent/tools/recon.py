"""
AXIOM RED — Recon Tools
Phase 1: Attack surface discovery — ports, services, endpoints, tech fingerprinting.
"""

import socket
import httpx
import json
from typing import Optional
from agent.core.state import AgentState, ActivityLog


# ── Port Scanner (pure Python — no nmap binary required for demo) ────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    80: "HTTP", 443: "HTTPS", 3000: "HTTP-Alt",
    3306: "MySQL", 5000: "HTTP-Flask", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 9200: "Elasticsearch"
}

def scan_ports(target: str, timeout: float = 0.5) -> list[dict]:
    """Scan common ports and return open ones with service guesses."""
    open_ports = []
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    for port, service in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                banner = _grab_banner(sock, port)
                open_ports.append({
                    "port": port,
                    "service": service,
                    "state": "open",
                    "banner": banner
                })
        except Exception:
            pass
        finally:
            # Fix Bug 8: Always close the socket to prevent fd leaks,
            # even if _grab_banner() or connect_ex() raises.
            sock.close()
    return open_ports


def _grab_banner(sock: socket.socket, port: int) -> str:
    try:
        sock.settimeout(1)
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        return sock.recv(256).decode(errors="ignore").strip()[:100]
    except Exception:
        return ""


# ── Web Endpoint Discovery ───────────────────────────────────────────────────
COMMON_PATHS = [
    "/", "/admin", "/login", "/api", "/api/v1", "/api/v1/users",
    "/api/v1/users/1", "/api/v1/users/2", "/api/v1/search",
    "/api/v1/config", "/api/v1/ping", "/api/v1/upload",
    "/api/v1/admin", "/api/v1/login", "/backup", "/config",
    "/robots.txt", "/.env", "/swagger.json", "/openapi.json",
    "/health", "/metrics", "/debug", "/console", "/phpmyadmin",
    "/wp-admin", "/wp-login.php", "/uploads", "/static",
]

def discover_endpoints(base_url: str, timeout: float = 2.0) -> list[str]:
    """Brute-force common paths and return responsive endpoints."""
    found = []
    base = base_url.rstrip("/")
    with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
        for path in COMMON_PATHS:
            try:
                r = client.get(f"{base}{path}")
                if r.status_code not in (404, 403):
                    found.append(f"{base}{path} [{r.status_code}]")
            except Exception:
                pass
    return found


# ── Technology Fingerprinting ────────────────────────────────────────────────
def fingerprint_tech(base_url: str) -> list[str]:
    """Extract server tech from HTTP headers and body."""
    techs = []
    try:
        with httpx.Client(timeout=5, verify=False, follow_redirects=True) as client:
            r = client.get(base_url)
            headers = r.headers

            if server := headers.get("server"):
                techs.append(f"Server: {server}")
            if powered := headers.get("x-powered-by"):
                techs.append(f"X-Powered-By: {powered}")
            if "flask" in r.text.lower():
                techs.append("Framework: Flask")
            if "django" in r.text.lower():
                techs.append("Framework: Django")
            if "react" in r.text.lower() or "__reactFiber" in r.text:
                techs.append("Frontend: React")
            if "jquery" in r.text.lower():
                techs.append("Frontend: jQuery")
            if "swagger" in r.text.lower() or "openapi" in r.text.lower():
                techs.append("API Docs: Swagger/OpenAPI")
            if "wp-content" in r.text:
                techs.append("CMS: WordPress")

            # Check for JWT in response
            if "eyJ" in r.text:
                techs.append("Auth: JWT detected in response")

    except Exception as e:
        techs.append(f"Fingerprint error: {e}")
    return techs


# ── Redis Check ──────────────────────────────────────────────────────────────
def check_redis(host: str, port: int = 6379) -> dict:
    """Check if Redis is open and unauthenticated."""
    try:
        import redis
        r = redis.Redis(host=host, port=port, socket_timeout=3)
        info = r.info()
        r.set("axiom_red_probe", "test_rce_vector")
        return {
            "status": "OPEN — NO AUTH",
            "version": info.get("redis_version", "unknown"),
            "rce_vector": True,
            "config_rewrite": True
        }
    except Exception as e:
        err = str(e)
        if "NOAUTH" in err:
            return {"status": "OPEN — AUTH required", "rce_vector": False}
        return {"status": f"closed/error: {err}", "rce_vector": False}


# ── Run Full Recon ───────────────────────────────────────────────────────────
def run_recon(state: AgentState, on_update=None) -> AgentState:
    """Execute all recon tasks and update agent state."""
    target = state.target
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    def _push():
        if on_update:
            try:
                on_update(state.model_dump())
            except Exception:
                pass

    state.activity_log.append(ActivityLog(
        phase="RECON",
        thought=f"Starting recon on {target}. I'll scan ports first, then discover web endpoints and fingerprint technologies.",
        action=f"Port scan + endpoint discovery on {target}",
        result="Initiating..."
    ))
    _push()

    # 1. Port scan
    ports = scan_ports(host)
    state.open_ports = ports

    state.activity_log.append(ActivityLog(
        phase="RECON",
        action="Port scan complete",
        result=f"Found {len(ports)} open ports: {[p['port'] for p in ports]}",
        status="finding" if ports else "ok"
    ))
    _push()

    # 2. Endpoint discovery
    endpoints = discover_endpoints(target)
    state.web_endpoints = endpoints

    state.activity_log.append(ActivityLog(
        phase="RECON",
        action="Endpoint discovery complete",
        result=f"Found {len(endpoints)} live endpoints",
        status="finding" if endpoints else "ok"
    ))
    _push()

    # 3. Tech fingerprint
    techs = fingerprint_tech(target)
    state.technologies = techs

    state.activity_log.append(ActivityLog(
        phase="RECON",
        action="Technology fingerprint complete",
        result=", ".join(techs) if techs else "No identifiable technologies",
        status="ok"
    ))
    _push()

    # 4. Redis check (if port 6379 found)
    redis_host = host
    redis_result = check_redis(redis_host)
    if redis_result.get("rce_vector"):
        state.services.append({"service": "Redis", "host": redis_host, "detail": redis_result})
        state.activity_log.append(ActivityLog(
            phase="RECON",
            thought="Redis is open with NO authentication. This is a critical misconfiguration. I should plan RCE via config rewrite in the next phase.",
            action="Redis unauthenticated probe",
            result=f"CRITICAL: {redis_result}",
            status="finding"
        ))
        _push()

    state.phase_complete["RECON"] = True
    state.current_phase = "ANALYSE"
    return state
