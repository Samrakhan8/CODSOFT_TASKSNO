"""
TaskVault - a small team notes/task web application.

    WARNING - DELIBERATELY INSECURE DEMO
    ------------------------------------
    This application is the *target* of the secure code assessment in this
    project. It is intentionally riddled with common, realistic vulnerabilities
    so that a static analyser (Bandit) and a manual review have something real
    to find. DO NOT deploy it, expose it to a network, or reuse any pattern
    from it. The hardened rewrite lives in ../secure_app/app.py and the
    findings are written up in ../reports/SECURITY_ASSESSMENT.md.
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

from flask import Flask, request, redirect, session, render_template_string, send_file

app = Flask(__name__)

# --- Configuration -------------------------------------------------------
# Hardcoded secret used to sign session cookies, committed to source control.
app.secret_key = "sup3r-s3cret-key-do-not-change-1234"

# Hardcoded database credentials, also committed.
DB_PATH = "taskvault.db"
DB_ADMIN_PASSWORD = "admin123"

# Root directory the download endpoint is *supposed* to serve from.
FILES_DIR = os.path.join(os.path.dirname(__file__), "uploads")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
    )
    c.execute(
        "CREATE TABLE IF NOT EXISTS notes "
        "(id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT)"
    )
    # Seed an admin account if the table is empty.
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", hashlib.md5(DB_ADMIN_PASSWORD.encode()).hexdigest(), "admin"),
        )
    conn.commit()
    conn.close()


# --- Password handling ---------------------------------------------------
def hash_password(password):
    # MD5, unsalted: fast, broken, and trivially reversible via rainbow tables.
    return hashlib.md5(password.encode()).hexdigest()


def make_token():
    # Predictable "random" token using the non-cryptographic PRNG.
    return str(random.randint(100000, 999999))


# --- Routes --------------------------------------------------------------
@app.route("/")
def index():
    return render_template_string(PAGE, body=HOME_BODY, user=session.get("user"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        c = conn.cursor()
        # String-built INSERT: SQL injection on registration.
        c.execute(
            "INSERT INTO users (username, password, role) VALUES ('%s', '%s', 'user')"
            % (username, hash_password(password))
        )
        conn.commit()
        conn.close()
        return redirect("/login")
    form = """
      <h2>Register</h2>
      <form method="post">
        <input name="username" placeholder="username">
        <input name="password" type="password" placeholder="password">
        <button>Create account</button>
      </form>"""
    return render_template_string(PAGE, body=form, user=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        c = conn.cursor()
        # Classic SQL injection: user input concatenated straight into the query.
        query = (
            "SELECT username, role FROM users WHERE username = '%s' AND password = '%s'"
            % (username, hash_password(password))
        )
        c.execute(query)
        row = c.fetchone()
        conn.close()
        if row:
            session["user"] = row[0]
            session["role"] = row[1]
            session["token"] = make_token()
            return redirect("/dashboard")
        return render_template_string(PAGE, body="<p>Login failed.</p>", user=None)
    form = """
      <h2>Login</h2>
      <form method="post">
        <input name="username" placeholder="username">
        <input name="password" type="password" placeholder="password">
        <button>Sign in</button>
      </form>"""
    return render_template_string(PAGE, body=form, user=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/dashboard")
def dashboard():
    user = session.get("user")
    if not user:
        return redirect("/login")
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, title FROM notes WHERE owner = ?", (user,))
    notes = c.fetchall()
    conn.close()
    items = "".join(
        '<li><a href="/note/%d">%s</a></li>' % (n[0], n[1]) for n in notes
    )
    body = (
        "<h2>Your notes</h2><ul>%s</ul>"
        '<form method="post" action="/note/add">'
        '<input name="title" placeholder="title">'
        '<textarea name="body" placeholder="body"></textarea>'
        "<button>Add note</button></form>" % items
    )
    return render_template_string(PAGE, body=body, user=user)


@app.route("/note/add", methods=["POST"])
def add_note():
    user = session.get("user")
    if not user:
        return redirect("/login")
    title = request.form.get("title", "")
    body = request.form.get("body", "")
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)", (user, title, body)
    )
    conn.commit()
    conn.close()
    return redirect("/dashboard")


@app.route("/note/<int:note_id>")
def view_note(note_id):
    # No ownership check: any logged-in user can read any note by guessing the
    # id (insecure direct object reference / broken access control).
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT title, body FROM notes WHERE id = ?", (note_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return "Not found", 404
    # Note body rendered without escaping -> stored XSS.
    body = "<h2>%s</h2><p>%s</p>" % (row[0], row[1])
    return render_template_string(PAGE, body=body, user=session.get("user"))


@app.route("/search")
def search():
    # Reflected XSS: the query is echoed back into the template unescaped.
    q = request.args.get("q", "")
    body = "<h2>Search</h2><p>You searched for: " + q + "</p>"
    return render_template_string(PAGE, body=body, user=session.get("user"))


@app.route("/admin")
def admin():
    # Broken access control: the admin panel never checks session role.
    host = request.args.get("host", "127.0.0.1")
    # Command injection: user-controlled host interpolated into a shell command.
    result = subprocess.check_output(
        "ping -n 1 " + host, shell=True, stderr=subprocess.STDOUT
    )
    body = "<h2>Admin - connectivity check</h2><pre>%s</pre>" % result.decode(
        errors="replace"
    )
    return render_template_string(PAGE, body=body, user=session.get("user"))


@app.route("/download")
def download():
    # Path traversal: filename is joined without validation, so ../ escapes
    # the intended uploads directory.
    name = request.args.get("file", "")
    path = os.path.join(FILES_DIR, name)
    return send_file(path)


@app.route("/import", methods=["GET", "POST"])
def import_notes():
    if request.method == "POST":
        blob = request.files["data"].read()
        # Insecure deserialization: pickle.loads on attacker-supplied bytes is
        # remote code execution.
        obj = pickle.loads(blob)
        return "Imported: %r" % (obj,)
    return render_template_string(
        PAGE,
        body='<form method="post" enctype="multipart/form-data">'
        '<input type="file" name="data"><button>Import</button></form>',
        user=session.get("user"),
    )


@app.route("/api/config")
def api_config():
    # Information disclosure: dumps internal configuration, including the
    # signing secret and DB password, to anyone who asks.
    return {
        "secret_key": app.secret_key,
        "db_path": DB_PATH,
        "db_admin_password": DB_ADMIN_PASSWORD,
        "debug": app.debug,
    }


PAGE = """
<!doctype html>
<title>TaskVault</title>
<nav>
  <a href="/">Home</a> |
  <a href="/dashboard">Dashboard</a> |
  <a href="/search">Search</a> |
  {% if user %}<a href="/logout">Logout ({{ user }})</a>
  {% else %}<a href="/login">Login</a> | <a href="/register">Register</a>{% endif %}
</nav>
<hr>
{{ body|safe }}
"""

HOME_BODY = "<h1>TaskVault</h1><p>A tiny team notes app.</p>"


if __name__ == "__main__":
    init_db()
    # Debug mode enabled: exposes the interactive Werkzeug debugger (RCE) and
    # binds to all interfaces.
    app.run(host="0.0.0.0", port=5000, debug=True)
