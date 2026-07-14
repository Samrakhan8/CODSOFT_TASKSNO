"""
verify.py - runnable proof that (a) the vulnerable app is exploitable and
(b) the hardened app blocks the same attacks. Uses Flask's in-process test
client, so nothing binds to the network. Run:

    python verify.py

Exit code is 0 only if every vulnerable-app attack succeeds AND every
hardened-app attack is blocked - i.e. the remediation is proven.
"""

import importlib.util
import os
import tempfile

RESULTS = []


def load_app(path, module_name, env=None):
    """Load an app.py by file path as an isolated module."""
    if env:
        os.environ.update(env)
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.init_db()
    return mod


def record(name, passed, detail):
    RESULTS.append((name, passed, detail))
    tag = "OK  " if passed else "FAIL"
    print(f"[{tag}] {name}: {detail}")


HERE = os.path.dirname(os.path.abspath(__file__))
VULN = os.path.join(HERE, "vulnerable_app", "app.py")
SECURE = os.path.join(HERE, "secure_app", "app.py")

# Isolated throwaway databases so the demo never touches real data.
vuln_db = os.path.join(tempfile.gettempdir(), "tv_vuln_demo.db")
sec_db = os.path.join(tempfile.gettempdir(), "tv_secure_demo.db")
for p in (vuln_db, sec_db):
    if os.path.exists(p):
        os.remove(p)

# ----------------------------------------------------------------------
# VULNERABLE APP - every attack below is expected to SUCCEED.
# ----------------------------------------------------------------------
print("\n=== TARGET: vulnerable_app (attacks should SUCCEED) ===")
os.chdir(os.path.join(HERE, "vulnerable_app"))
vuln = load_app(VULN, "vuln_app")
vuln.DB_PATH = vuln_db
vuln.init_db()
vc = vuln.app.test_client()

# 1. SQL injection auth bypass: log in as admin with no valid password.
r = vc.post("/login", data={"username": "admin'--", "password": "wrong"},
            follow_redirects=False)
bypassed = r.status_code == 302 and r.headers.get("Location", "").endswith("/dashboard")
record("SQL injection auth bypass", bypassed,
       "logged in as admin via \"admin'--\" without the password" if bypassed
       else "unexpectedly rejected")

# 2. Reflected XSS: the payload is echoed back unescaped.
r = vc.get("/search?q=<script>alert(1)</script>")
xss = b"<script>alert(1)</script>" in r.data
record("Reflected XSS", xss,
       "raw <script> reflected into the page" if xss else "payload was escaped")

# 3. Path traversal: read the app's own source (and its secrets) via ../.
r = vc.get("/download?file=../app.py")
traversal = r.status_code == 200 and b"secret_key" in r.data
record("Path traversal", traversal,
       "read ../app.py outside the uploads dir" if traversal else "blocked")

# 4. Broken access control: reach /admin with no session at all.
r = vc.get("/admin?host=127.0.0.1")
open_admin = r.status_code == 200 and b"connectivity" in r.data
record("Broken access control (/admin)", open_admin,
       "admin panel reachable while logged out" if open_admin else "blocked")

# 5. Sensitive data exposure: /api/config leaks the signing secret.
r = vc.get("/api/config")
leak = r.status_code == 200 and b"secret_key" in r.data
record("Secret disclosure (/api/config)", leak,
       "endpoint returned the secret key + DB password" if leak else "no leak")

# ----------------------------------------------------------------------
# HARDENED APP - every attack below is expected to be BLOCKED.
# ----------------------------------------------------------------------
print("\n=== TARGET: secure_app (same attacks should be BLOCKED) ===")
os.chdir(os.path.join(HERE, "secure_app"))
secure = load_app(SECURE, "secure_app", env={
    "TASKVAULT_SECRET": "test-secret-not-shipped",
    "TASKVAULT_ADMIN_PASSWORD": "S3cure!bootstrap",
    "TASKVAULT_DB": sec_db,
})
secure.DB_PATH = sec_db
secure.init_db()
sc = secure.app.test_client()

# 1. SQL injection auth bypass now fails.
r = sc.post("/login", data={"username": "admin'--", "password": "wrong"})
record("SQL injection blocked", r.status_code == 401,
       "injection payload rejected with 401" if r.status_code == 401
       else f"unexpected status {r.status_code}")

# 2. XSS payload is HTML-escaped by the template.
r = sc.get("/login")  # get a session-free page; search needs login
# log in properly as admin to reach /search
sc.post("/login", data={"username": "admin", "password": "S3cure!bootstrap"})
r = sc.get("/search?q=<script>alert(1)</script>")
escaped = b"<script>alert(1)</script>" not in r.data and b"&lt;script&gt;" in r.data
record("XSS blocked (output escaped)", escaped,
       "payload rendered as inert &lt;script&gt;" if escaped else "NOT escaped")

# 3. Path traversal is rejected.
r = sc.get("/download?file=../app.py")
record("Path traversal blocked", r.status_code == 404,
       "../ traversal returns 404" if r.status_code == 404
       else f"unexpected status {r.status_code}")

# 4. Admin area requires an admin role (we are logged in as admin here, so
#    test the negative case with a fresh, logged-out client).
sc2 = secure.app.test_client()
r = sc2.get("/admin?host=127.0.0.1")
record("Access control enforced (/admin)", r.status_code == 403,
       "logged-out user gets 403" if r.status_code == 403
       else f"unexpected status {r.status_code}")

# 5. Config endpoint requires admin and never leaks secrets.
r = sc2.get("/api/config")
record("Secret disclosure blocked", r.status_code == 403,
       "unauthenticated /api/config returns 403" if r.status_code == 403
       else f"unexpected status {r.status_code}")

# ----------------------------------------------------------------------
print("\n=== SUMMARY ===")
passed = sum(1 for _, ok, _ in RESULTS if ok)
total = len(RESULTS)
print(f"{passed}/{total} checks behaved as expected.")
os.chdir(HERE)
raise SystemExit(0 if passed == total else 1)
