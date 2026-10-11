"""
Custom Vulnerable API — Intentionally insecure Flask app for AXIOM RED sandbox.
Vulnerabilities included:
  - IDOR on /api/v1/users/<id>
  - SQL Injection on /api/v1/search
  - JWT alg:none bypass on /api/v1/admin
  - Unrestricted file upload on /api/v1/upload
  - Reflected XSS on /api/v1/ping
  - Sensitive data exposure on /api/v1/config
"""

from flask import Flask, request, jsonify, send_from_directory
import sqlite3, jwt, os, subprocess, json

app = Flask(__name__)
SECRET_KEY = "supersecret123"  # Intentionally weak

# ── Database setup ───────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("/tmp/users.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        name TEXT, email TEXT, role TEXT,
        ssn TEXT, credit_card TEXT, password TEXT
    )""")
    c.executemany("INSERT OR IGNORE INTO users VALUES (?,?,?,?,?,?,?)", [
        (1, "admin",   "admin@corp.local",  "admin",  "000-00-0000", "4111111111111111", "admin123"),
        (2, "alice",   "alice@corp.local",  "user",   "123-45-6789", "4222222222222222", "alice2024"),
        (3, "bob",     "bob@corp.local",    "user",   "987-65-4321", "4333333333333333", "bob@pass"),
        (4, "charlie", "charlie@corp.local","manager","555-12-3456", "4444444444444444", "ch4rlie!"),
    ])
    conn.commit()
    conn.close()

init_db()

# ── Home ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return jsonify({
        "name": "CorpAPI v1.0",
        "endpoints": [
            "GET  /api/v1/users/<id>",
            "GET  /api/v1/search?q=<query>",
            "POST /api/v1/login",
            "GET  /api/v1/admin",
            "POST /api/v1/upload",
            "GET  /api/v1/ping?host=<host>",
            "GET  /api/v1/config",
        ]
    })

# ── VULN 1: IDOR ─────────────────────────────────────────────────────────────
@app.route("/api/v1/users/<int:user_id>")
def get_user(user_id):
    """No authorization check — any ID returns full PII data."""
    conn = sqlite3.connect("/tmp/users.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "id": row[0], "name": row[1], "email": row[2],
        "role": row[3], "ssn": row[4], "credit_card": row[5]
    })

# ── VULN 2: SQL Injection ─────────────────────────────────────────────────────
@app.route("/api/v1/search")
def search():
    """Unsanitised query parameter directly embedded in SQL."""
    q = request.args.get("q", "")
    conn = sqlite3.connect("/tmp/users.db")
    c = conn.cursor()
    try:
        # Intentionally vulnerable: f-string in SQL
        c.execute(f"SELECT id, name, email FROM users WHERE name LIKE '%{q}%'")
        rows = c.fetchall()
        return jsonify({"results": [{"id": r[0], "name": r[1], "email": r[2]} for r in rows]})
    except Exception as e:
        return jsonify({"error": str(e), "query": q}), 500
    finally:
        conn.close()

# ── VULN 3: Login (returns JWT with weak secret) ─────────────────────────────
@app.route("/api/v1/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    conn = sqlite3.connect("/tmp/users.db")
    c = conn.cursor()
    c.execute("SELECT id, name, role FROM users WHERE name=? AND password=?", (username, password))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Invalid credentials"}), 401
    token = jwt.encode(
        {"user_id": row[0], "username": row[1], "role": row[2]},
        SECRET_KEY, algorithm="HS256"
    )
    return jsonify({"token": token, "role": row[2]})

# ── VULN 4: JWT alg:none bypass ──────────────────────────────────────────────
@app.route("/api/v1/admin")
def admin_panel():
    """Accepts JWT with alg:none — no signature verification."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "No token"}), 401
    token = auth[7:]
    try:
        # Intentionally vulnerable: algorithms=["HS256","none"]
        payload = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256", "none"])
        if payload.get("role") == "admin":
            conn = sqlite3.connect("/tmp/users.db")
            c = conn.cursor()
            c.execute("SELECT * FROM users")
            rows = c.fetchall()
            conn.close()
            return jsonify({
                "message": "Welcome to the admin panel",
                "all_users": [{"id":r[0],"name":r[1],"email":r[2],"ssn":r[4],"cc":r[5],"pass":r[6]} for r in rows]
            })
        return jsonify({"error": "Not admin"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ── VULN 5: Command Injection in ping ────────────────────────────────────────
@app.route("/api/v1/ping")
def ping():
    """Passes user input directly to shell."""
    host = request.args.get("host", "127.0.0.1")
    try:
        # Intentionally vulnerable: shell=True with user input
        result = subprocess.check_output(
            f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT, timeout=5
        )
        return jsonify({"output": result.decode()})
    except Exception as e:
        return jsonify({"output": str(e)})

# ── VULN 6: Sensitive Config Exposure ────────────────────────────────────────
@app.route("/api/v1/config")
def config():
    """Exposes internal config including DB credentials."""
    return jsonify({
        "db_host": "172.20.0.11",
        "db_user": "dvwa",
        "db_pass": "p@ssw0rd",
        "jwt_secret": SECRET_KEY,
        "internal_api_key": "sk-internal-abc123xyz",
        "admin_email": "admin@corp.local",
        "debug_mode": True
    })

# ── VULN 7: Unrestricted File Upload ─────────────────────────────────────────
UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route("/api/v1/upload", methods=["POST"])
def upload():
    """No file type validation — accepts any file including .php shells."""
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    f = request.files["file"]
    path = os.path.join(UPLOAD_DIR, f.filename)
    f.save(path)
    return jsonify({"message": "Uploaded", "path": f"/uploads/{f.filename}"})

@app.route("/uploads/<filename>")
def serve_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename)

# ── VULN 8: Reflected XSS ────────────────────────────────────────────────────
@app.route("/api/v1/greet")
def greet():
    """Reflects user input directly into HTML without sanitisation — Reflected XSS."""
    name = request.args.get("name", "World")
    # Intentionally vulnerable: no escaping
    html = f"""<html><body>
    <h1>Hello, {name}!</h1>
    <p>Welcome to CorpAPI.</p>
    </body></html>"""
    from flask import Response
    return Response(html, mimetype="text/html")

# ── VULN 9: Stored XSS ───────────────────────────────────────────────────────
_comments = []  # In-memory store — no persistence

@app.route("/api/v1/comment", methods=["GET", "POST"])
def comment():
    """Stores and renders comments without sanitisation — Stored XSS."""
    if request.method == "POST":
        data = request.get_json() or {}
        msg = data.get("message", "")
        _comments.append(msg)  # No sanitisation
        return jsonify({"status": "Comment saved", "total": len(_comments)})
    # GET: render all comments raw
    from flask import Response
    items = "".join(f"<li>{c}</li>" for c in _comments)
    html = f"<html><body><ul>{items}</ul></body></html>"
    return Response(html, mimetype="text/html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
