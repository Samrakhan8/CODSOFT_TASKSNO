"""
app.py - SecureShare: an authenticated, encrypted file-sharing service.

Features
  * user accounts with PBKDF2-hashed passwords and roles (admin | user)
  * upload/download over authenticated sessions
  * every file encrypted at rest with AES-256-GCM envelope encryption
  * role-based access control plus per-file grants (to a user or a role)
  * temporary, expiring, use-limited download links (bonus)

Security posture mirrors the hardened patterns from the secure-code-assessment
task: parameterised SQL, salted-slow password hashing, secrets from the
environment, server-generated file ids (no path traversal), authorisation
checks on every file operation, an upload size cap, session-cookie hardening,
and security response headers.

Run:
    set SFS_SECRET / SFS_MASTER_KEY / SFS_ADMIN_PASSWORD, then  python app.py
"""

import io
import os
import secrets
import time
import uuid
from functools import wraps

from flask import (
    Flask, abort, flash, redirect, render_template, request,
    send_file, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from cryptography.exceptions import InvalidTag

import db as database
from crypto_store import CryptoStore

HERE = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(HERE, "storage")
DB_PATH = os.environ.get("SFS_DB", os.path.join(HERE, "secureshare.db"))
ROLES = ("admin", "user")
MAX_UPLOAD_MB = 16

app = Flask(__name__)
app.secret_key = os.environ.get("SFS_SECRET") or secrets.token_hex(32)
app.config.update(
    MAX_CONTENT_LENGTH=MAX_UPLOAD_MB * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("SFS_HTTPS")),
)

crypto = CryptoStore(STORAGE_DIR)


def get_db():
    conn = getattr(get_db, "_conn", None)
    if conn is None:
        conn = database.connect(DB_PATH)
        database.init_schema(conn)
        get_db._conn = conn
    return conn


# --- Auth helpers --------------------------------------------------------
def current_user():
    uname = session.get("user")
    if not uname:
        return None
    return get_db().execute(
        "SELECT * FROM users WHERE username = ?", (uname,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapper(*a, **k):
        if not session.get("user"):
            return redirect(url_for("login"))
        return view(*a, **k)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*a, **k):
        u = current_user()
        if not u or u["role"] != "admin":
            abort(403)
        return view(*a, **k)
    return wrapper


def can_access(user, file_row):
    """Core RBAC decision for reading/downloading a file."""
    if user is None or file_row is None:
        return False
    if user["role"] == "admin":
        return True
    if file_row["owner"] == user["username"]:
        return True
    rows = get_db().execute(
        "SELECT principal_type, principal FROM grants WHERE file_id = ?",
        (file_row["id"],)).fetchall()
    for g in rows:
        if g["principal_type"] == "user" and g["principal"] == user["username"]:
            return True
        if g["principal_type"] == "role" and g["principal"] == user["role"]:
            return True
    return False


def can_manage(user, file_row):
    """Owner or admin may share/grant/delete."""
    return user is not None and (
        user["role"] == "admin" or file_row["owner"] == user["username"])


# --- Bootstrap admin -----------------------------------------------------
def ensure_admin():
    conn = get_db()
    pw = os.environ.get("SFS_ADMIN_PASSWORD")
    have_admin = conn.execute(
        "SELECT COUNT(*) AS n FROM users WHERE role='admin'").fetchone()["n"]
    if not have_admin and pw:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) "
            "VALUES (?,?,?,?)",
            ("admin", generate_password_hash(pw), "admin", time.time()))
        conn.commit()


# --- Routes: auth --------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if session.get("user") else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(password) < 8:
            flash("Username min 3 chars, password min 8 chars.")
            return render_template("register.html", user=None), 400
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) "
                "VALUES (?,?,?,?)",
                (username, generate_password_hash(password), "user", time.time()))
            conn.commit()
        except database.sqlite3.IntegrityError:
            flash("That username is taken.")
            return render_template("register.html", user=None), 409
        database.log(conn, username, "register")
        flash("Account created. Please sign in.")
        return redirect(url_for("login"))
    return render_template("register.html", user=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        row = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["user"] = row["username"]
            database.log(get_db(), username, "login")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.")
        return render_template("login.html", user=None), 401
    return render_template("login.html", user=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- Routes: files -------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    conn = get_db()
    if user["role"] == "admin":
        files = conn.execute("SELECT * FROM files ORDER BY created_at DESC").fetchall()
    else:
        files = [f for f in conn.execute(
            "SELECT * FROM files ORDER BY created_at DESC").fetchall()
            if can_access(user, f)]
    return render_template("dashboard.html", user=user, files=files,
                           roles=ROLES, max_mb=MAX_UPLOAD_MB)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    user = current_user()
    up = request.files.get("file")
    if not up or not up.filename:
        flash("No file selected.")
        return redirect(url_for("dashboard"))
    data = up.read()
    if not data:
        flash("File is empty.")
        return redirect(url_for("dashboard"))

    file_id = uuid.uuid4().hex
    orig_name = secure_filename(up.filename) or "file"
    meta = crypto.encrypt(file_id, data)

    conn = get_db()
    conn.execute(
        "INSERT INTO files (id, owner, orig_name, size, sha256, nonce, "
        "wrapped_key, wrap_nonce, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (file_id, user["username"], orig_name, meta["size"], meta["sha256"],
         meta["nonce"], meta["wrapped_key"], meta["wrap_nonce"], time.time()))
    conn.commit()
    database.log(conn, user["username"], "upload", file_id,
                 "%s (%d bytes)" % (orig_name, meta["size"]))
    flash("Uploaded and encrypted: %s" % orig_name)
    return redirect(url_for("dashboard"))


def _file_or_404(file_id):
    row = get_db().execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not row:
        abort(404)
    return row


@app.route("/files/<file_id>/download")
@login_required
def download(file_id):
    user = current_user()
    row = _file_or_404(file_id)
    if not can_access(user, row):
        database.log(get_db(), user["username"], "download_denied", file_id)
        abort(403)
    try:
        plaintext = crypto.decrypt(file_id, row)
    except (InvalidTag, ValueError, FileNotFoundError):
        database.log(get_db(), user["username"], "integrity_error", file_id)
        abort(500, "The stored file could not be decrypted or verified.")
    database.log(get_db(), user["username"], "download", file_id, row["orig_name"])
    return send_file(io.BytesIO(plaintext), as_attachment=True,
                     download_name=row["orig_name"],
                     mimetype="application/octet-stream")


@app.route("/files/<file_id>/grant", methods=["POST"])
@login_required
def grant(file_id):
    user = current_user()
    row = _file_or_404(file_id)
    if not can_manage(user, row):
        abort(403)
    ptype = request.form.get("principal_type", "user")
    principal = request.form.get("principal", "").strip()
    if ptype not in ("user", "role") or not principal:
        flash("Invalid grant.")
        return redirect(url_for("dashboard"))
    if ptype == "role" and principal not in ROLES:
        flash("Unknown role.")
        return redirect(url_for("dashboard"))
    if ptype == "user" and not get_db().execute(
            "SELECT 1 FROM users WHERE username = ?", (principal,)).fetchone():
        flash("No such user.")
        return redirect(url_for("dashboard"))
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO grants (file_id, principal_type, principal) VALUES (?,?,?)",
            (file_id, ptype, principal))
        conn.commit()
    except database.sqlite3.IntegrityError:
        pass  # grant already exists
    database.log(conn, user["username"], "grant", file_id, "%s:%s" % (ptype, principal))
    flash("Access granted to %s '%s'." % (ptype, principal))
    return redirect(url_for("dashboard"))


@app.route("/files/<file_id>/delete", methods=["POST"])
@login_required
def delete(file_id):
    user = current_user()
    row = _file_or_404(file_id)
    if not can_manage(user, row):
        abort(403)
    conn = get_db()
    conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
    conn.commit()
    crypto.remove(file_id)
    database.log(conn, user["username"], "delete", file_id, row["orig_name"])
    flash("Deleted %s." % row["orig_name"])
    return redirect(url_for("dashboard"))


# --- Routes: temporary links (bonus) ------------------------------------
@app.route("/files/<file_id>/share", methods=["POST"])
@login_required
def share(file_id):
    user = current_user()
    row = _file_or_404(file_id)
    if not can_manage(user, row):
        abort(403)
    try:
        minutes = max(1, min(int(request.form.get("minutes", "60")), 10080))
        max_dl = max(0, int(request.form.get("max_downloads", "0")))
    except ValueError:
        flash("Invalid link settings.")
        return redirect(url_for("dashboard"))

    token = secrets.token_urlsafe(32)
    now = time.time()
    conn = get_db()
    conn.execute(
        "INSERT INTO links (token, file_id, created_by, expires_at, "
        "max_downloads, downloads, revoked, created_at) VALUES (?,?,?,?,?,0,0,?)",
        (token, file_id, user["username"], now + minutes * 60, max_dl, now))
    conn.commit()
    database.log(conn, user["username"], "share", file_id,
                 "expires in %dm, max %s" % (minutes, max_dl or "unlimited"))
    link = url_for("temp_download", token=token, _external=True)
    flash("Temporary link (valid %d min%s): %s" % (
        minutes, ", %d download(s)" % max_dl if max_dl else "", link))
    return redirect(url_for("dashboard"))


@app.route("/d/<token>")
def temp_download(token):
    """Public capability URL - no login; the token IS the authorisation."""
    conn = get_db()
    link = conn.execute("SELECT * FROM links WHERE token = ?", (token,)).fetchone()
    if not link or link["revoked"]:
        abort(404)
    if time.time() > link["expires_at"]:
        abort(410, "This link has expired.")
    if link["max_downloads"] and link["downloads"] >= link["max_downloads"]:
        abort(410, "This link has reached its download limit.")

    row = conn.execute("SELECT * FROM files WHERE id = ?",
                       (link["file_id"],)).fetchone()
    if not row:
        abort(404)
    try:
        plaintext = crypto.decrypt(row["id"], row)
    except (InvalidTag, ValueError, FileNotFoundError):
        database.log(conn, None, "integrity_error", row["id"])
        abort(500, "The stored file could not be decrypted or verified.")
    conn.execute("UPDATE links SET downloads = downloads + 1 WHERE token = ?",
                 (token,))
    conn.commit()
    database.log(conn, None, "temp_download", row["id"],
                 "via link by %s" % link["created_by"])
    return send_file(io.BytesIO(plaintext), as_attachment=True,
                     download_name=row["orig_name"],
                     mimetype="application/octet-stream")


# --- Routes: admin -------------------------------------------------------
@app.route("/admin")
@admin_required
def admin():
    conn = get_db()
    users = conn.execute("SELECT * FROM users ORDER BY created_at").fetchall()
    files = conn.execute("SELECT * FROM files ORDER BY created_at DESC").fetchall()
    audit = conn.execute(
        "SELECT * FROM audit ORDER BY id DESC LIMIT 50").fetchall()
    return render_template("admin.html", user=current_user(), users=users,
                           files=files, audit=audit, roles=ROLES)


@app.route("/admin/role", methods=["POST"])
@admin_required
def set_role():
    conn = get_db()
    target = request.form.get("username", "")
    role = request.form.get("role", "")
    if role not in ROLES:
        abort(400)
    if target == current_user()["username"]:
        flash("You cannot change your own role.")
        return redirect(url_for("admin"))
    conn.execute("UPDATE users SET role = ? WHERE username = ?", (role, target))
    conn.commit()
    database.log(conn, current_user()["username"], "set_role", target, role)
    flash("Role for %s set to %s." % (target, role))
    return redirect(url_for("admin"))


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.template_filter("dt")
def _dt(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else ""


if __name__ == "__main__":
    with app.app_context():
        ensure_admin()
    debug = os.environ.get("SFS_DEBUG") == "1"
    host = os.environ.get("SFS_HOST", "127.0.0.1")
    app.run(host=host, port=5001, debug=debug)
