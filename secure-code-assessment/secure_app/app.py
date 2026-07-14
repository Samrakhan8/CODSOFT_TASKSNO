"""
TaskVault (hardened) - the remediated version of ../vulnerable_app/app.py.

Every vulnerability documented in ../reports/SECURITY_ASSESSMENT.md is fixed
here. Comments marked "FIX #n" map each change back to the corresponding
finding in the report so the two can be read side by side.

Run:  python app.py   (set TASKVAULT_SECRET and TASKVAULT_ADMIN_PASSWORD first)
"""

import ipaddress
import json
import os
import secrets
import sqlite3
import subprocess
from functools import wraps

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    session,
    send_from_directory,
)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# FIX #2 / #14: secret key comes from the environment, never source control.
# A random per-process fallback keeps dev usable without weakening prod.
app.secret_key = os.environ.get("TASKVAULT_SECRET") or secrets.token_hex(32)

# FIX #14: harden the session cookie.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # not readable from JavaScript
    SESSION_COOKIE_SAMESITE="Lax",  # basic CSRF mitigation on navigation
    SESSION_COOKIE_SECURE=bool(os.environ.get("TASKVAULT_HTTPS")),
)

DB_PATH = os.environ.get("TASKVAULT_DB", "taskvault.db")
# FIX #2: admin bootstrap password from the environment, with no shipped default.
DB_ADMIN_PASSWORD = os.environ.get("TASKVAULT_ADMIN_PASSWORD")

FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS notes "
        "(id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT)"
    )
    c.execute("SELECT COUNT(*) AS n FROM users")
    if c.fetchone()["n"] == 0 and DB_ADMIN_PASSWORD:
        c.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash(DB_ADMIN_PASSWORD), "admin"),
        )
    conn.commit()
    conn.close()


# FIX #4: strong, salted, slow password hashing (PBKDF2-SHA256 via werkzeug).
def hash_password(password):
    return generate_password_hash(password)


# FIX #12: cryptographically secure tokens.
def make_token():
    return secrets.token_urlsafe(32)


# --- Access-control decorators ------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect("/login")
        return view(*args, **kwargs)

    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        # FIX #10: the admin area now enforces an authenticated admin role.
        if session.get("role") != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapper


# --- Routes --------------------------------------------------------------
@app.route("/")
def index():
    return render_template("page.html", body_html=None, home=True, user=session.get("user"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            return render_template("message.html", message="Username and password required.",
                                   user=None), 400
        conn = get_db()
        c = conn.cursor()
        try:
            # FIX #1: parameterised query - input can never alter SQL structure.
            c.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, 'user')",
                (username, hash_password(password)),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return render_template("message.html", message="Username already taken.",
                                   user=None), 409
        finally:
            conn.close()
        return redirect("/login")
    return render_template("register.html", user=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        c = conn.cursor()
        # FIX #1: parameterised lookup by username only; verify the hash in code.
        c.execute("SELECT username, role, password FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        # FIX #4: constant-time hash verification instead of trusting the DB row.
        if row and check_password_hash(row["password"], password):
            session.clear()
            session["user"] = row["username"]
            session["role"] = row["role"]
            session["token"] = make_token()
            return redirect("/dashboard")
        # FIX: generic error - no username enumeration.
        return render_template("message.html", message="Invalid credentials.", user=None), 401
    return render_template("login.html", user=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/dashboard")
@login_required
def dashboard():
    user = session["user"]
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, title FROM notes WHERE owner = ?", (user,))
    notes = c.fetchall()
    conn.close()
    # FIX #8: data passed to an auto-escaping template, not concatenated HTML.
    return render_template("dashboard.html", notes=notes, user=user)


@app.route("/note/add", methods=["POST"])
@login_required
def add_note():
    user = session["user"]
    title = request.form.get("title", "")
    body = request.form.get("body", "")
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)", (user, title, body))
    conn.commit()
    conn.close()
    return redirect("/dashboard")


@app.route("/note/<int:note_id>")
@login_required
def view_note(note_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT owner, title, body FROM notes WHERE id = ?", (note_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        abort(404)
    # FIX #11: enforce ownership - stop insecure direct object reference.
    if row["owner"] != session["user"]:
        abort(403)
    # FIX #8: template autoescapes title/body, killing stored XSS.
    return render_template("note.html", title=row["title"], body=row["body"],
                           user=session["user"])


@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "")
    # FIX #8: value is escaped and rendered by the template; no raw HTML echo.
    return render_template("search.html", q=q, user=session["user"])


@app.route("/admin")
@admin_required
def admin():
    host = request.args.get("host", "127.0.0.1")
    # FIX #5: validate input as an IP address, then run ping with an argument
    # list and shell=False so there is no shell for injection to reach.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return render_template("message.html", message="Invalid IP address.",
                               user=session.get("user")), 400
    try:
        result = subprocess.run(
            ["ping", "-n", "1", host],
            capture_output=True, text=True, timeout=5, shell=False,
        ).stdout
    except subprocess.TimeoutExpired:
        result = "ping timed out."
    return render_template("admin.html", result=result, user=session.get("user"))


@app.route("/download")
@login_required
def download():
    name = request.args.get("file", "")
    # FIX #6: send_from_directory rejects any path that escapes FILES_DIR,
    # neutralising ../ traversal.
    try:
        return send_from_directory(FILES_DIR, name, as_attachment=True)
    except (NotADirectoryError, FileNotFoundError):
        abort(404)


@app.route("/import", methods=["GET", "POST"])
@login_required
def import_notes():
    if request.method == "POST":
        blob = request.files["data"].read()
        # FIX #7: JSON instead of pickle - data, never code, is deserialised.
        try:
            obj = json.loads(blob.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return render_template("message.html", message="Invalid JSON file.",
                                   user=session["user"]), 400
        return render_template("message.html",
                               message="Imported %d item(s)." % len(obj)
                               if isinstance(obj, (list, dict)) else "Imported.",
                               user=session["user"])
    return render_template("import.html", user=session["user"])


@app.route("/api/config")
@admin_required
def api_config():
    # FIX #9 / #13: never expose secrets. Only non-sensitive, admin-gated status.
    return {"db_path": os.path.basename(DB_PATH), "debug": app.debug}


# FIX #14: security response headers on every response.
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


if __name__ == "__main__":
    init_db()
    # FIX #3: debug is off and the bind address is configurable (loopback by
    # default), so the Werkzeug debugger is never exposed.
    debug = os.environ.get("TASKVAULT_DEBUG") == "1"
    host = os.environ.get("TASKVAULT_HOST", "127.0.0.1")
    app.run(host=host, port=5000, debug=debug)
