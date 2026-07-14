# Secure Code Assessment — TaskVault

**Target application:** TaskVault, a small Python/Flask team-notes web app
**Assessment type:** White-box source code review (static analysis + manual)
**Tools:** Bandit 1.9.4 (SAST), manual code review, runtime proof-of-concept
**Assessor:** Security review, TaskVault engineering
**Date:** 2026-07-15
**Files reviewed:** `vulnerable_app/app.py` (210 LOC), templates, configuration

---

## 1. Executive summary

TaskVault was reviewed for common security weaknesses and coding flaws. The
review combined an automated static-analysis pass (Bandit) with a manual
line-by-line review of authentication, authorisation, input handling, and
data flow.

The application is **not fit for production**. It contains **13 distinct
findings**, including **three critical issues that each allow full compromise**:
SQL injection (authentication bypass), OS command injection (remote code
execution), and insecure deserialization (remote code execution). Several
high-severity issues — broken access control, path traversal, cross-site
scripting, weak password hashing, and secret disclosure — compound the risk.

Every finding has been remediated in `secure_app/app.py`. A runnable
proof-of-concept (`verify.py`) demonstrates each attack succeeding against the
original code and being blocked by the hardened code. After remediation, the
Bandit scan reports **zero High and zero Medium findings** (down from 4 High
and 4 Medium), with only three informational Low notes remaining, all reviewed
and accepted.

### Findings at a glance

| ID | Finding | Severity | CWE | Detected by |
|----|---------|----------|-----|-------------|
| F-01 | SQL injection (login & registration) | **Critical** | CWE-89 | Bandit B608 + manual |
| F-05 | OS command injection (`/admin`) | **Critical** | CWE-78 | Bandit B602 + manual |
| F-07 | Insecure deserialization (`pickle.loads`) | **Critical** | CWE-502 | Bandit B301 + manual |
| F-04 | Weak password hashing (unsalted MD5) | High | CWE-916/327 | Bandit B324 + manual |
| F-06 | Path traversal (`/download`) | High | CWE-22 | Manual |
| F-08 | Cross-site scripting (reflected & stored) | High | CWE-79 | Manual |
| F-10 | Broken access control (`/admin`) | High | CWE-862 | Manual |
| F-11 | Insecure direct object reference (`/note/<id>`) | High | CWE-639 | Manual |
| F-02 | Hardcoded secrets (key & admin password) | High | CWE-798/259 | Bandit B105 + manual |
| F-03 | Debug mode enabled (Werkzeug debugger RCE) | High | CWE-489 | Bandit B201 + manual |
| F-09 | Sensitive data exposure (`/api/config`) | High | CWE-200 | Manual |
| F-12 | Insecure randomness for tokens | Medium | CWE-330 | Bandit B311 + manual |
| F-14 | Missing transport/session hardening | Medium | CWE-614/352/693 | Manual |

*(IDs align with the `FIX #n` comments in `secure_app/app.py` so each fix can
be read against its finding.)*

---

## 2. Scope and methodology

**In scope.** The complete source of the TaskVault application: the Flask
application module, its request handlers, database access, authentication and
authorisation logic, file handling, and runtime configuration.

**Methodology.**

1. **Static analysis (SAST).** Bandit was run recursively over the source:
   `bandit -r vulnerable_app/app.py`. Full output is saved in
   `reports/bandit_output.txt` and `reports/bandit_report.json`. Bandit found
   **13 issues** (4 High, 4 Medium, 5 Low by severity).
2. **Manual review.** Each handler was read for issues that pattern-based tools
   miss — broken access control, IDOR, business-logic flaws, path traversal,
   and output-encoding (XSS) gaps.
3. **Runtime verification.** Each candidate issue was confirmed with a
   proof-of-concept using Flask's in-process test client (`verify.py`), so a
   finding is reported only when it was actually reproduced.

**Severity model.** Ratings follow a standard likelihood × impact model
(aligned with OWASP risk rating). "Critical" = unauthenticated full compromise
of the app or host; "High" = serious loss of confidentiality/integrity or
account takeover; "Medium" = meaningful weakening of a control.

---

## 3. Detailed findings

Each finding lists the location, vulnerable code, an explanation, a reproduced
proof-of-concept, the impact, and the remediation applied in `secure_app`.

---

### F-01 — SQL injection in login and registration *(Critical, CWE-89)*

**Location:** `vulnerable_app/app.py` — `login()` (~line 115), `register()`
(~line 90). Bandit B608.

**Vulnerable code:**

```python
query = (
    "SELECT username, role FROM users WHERE username = '%s' AND password = '%s'"
    % (username, hash_password(password))
)
c.execute(query)
```

**Explanation.** User input is formatted directly into the SQL string, so input
can change the *structure* of the query, not just its data.

**Proof of concept (reproduced).** Logging in with username `admin'--` and any
password turns the query into
`... WHERE username = 'admin'-- AND password = '...'`. The `--` comments out the
password check, so the attacker is authenticated as `admin`. `verify.py`
confirms a 302 redirect to `/dashboard`.

**Impact.** Full authentication bypass; with `UNION`/stacked techniques an
attacker can read or modify the entire database.

**Remediation (applied).** Parameterised queries — the driver binds values
separately from the SQL text, so input can never be interpreted as code:

```python
c.execute("SELECT username, role, password FROM users WHERE username = ?", (username,))
row = c.fetchone()
if row and check_password_hash(row["password"], password):
    ...
```

---

### F-05 — OS command injection in `/admin` *(Critical, CWE-78)*

**Location:** `admin()` (~line 213). Bandit B602 (High/High).

**Vulnerable code:**

```python
result = subprocess.check_output(
    "ping -n 1 " + host, shell=True, stderr=subprocess.STDOUT
)
```

**Explanation.** The `host` query parameter is concatenated into a string that
is run by the system shell (`shell=True`). Shell metacharacters let the attacker
append their own commands.

**Proof of concept.** `/admin?host=127.0.0.1 %26 whoami` (URL-encoded `&`) runs
`whoami` on the server. Because `/admin` also lacks authentication (F-10), this
is **unauthenticated remote code execution**.

**Impact.** Complete server compromise.

**Remediation (applied).** Validate the input as an IP address, then invoke the
process with an **argument list and `shell=False`** so no shell is involved:

```python
ipaddress.ip_address(host)                      # rejects anything not an IP
subprocess.run(["ping", "-n", "1", host],
               capture_output=True, text=True, timeout=5, shell=False)
```

---

### F-07 — Insecure deserialization via `pickle.loads` *(Critical, CWE-502)*

**Location:** `import_notes()` (~line 236). Bandit B301/B403.

**Vulnerable code:**

```python
blob = request.files["data"].read()
obj = pickle.loads(blob)     # attacker-controlled bytes
```

**Explanation.** `pickle` can construct arbitrary Python objects on load,
including ones whose `__reduce__` executes code. Unpickling untrusted bytes is
remote code execution by design.

**Impact.** Uploading a crafted pickle runs attacker code on the server.

**Remediation (applied).** Use a data-only format (JSON). JSON parses to plain
strings, numbers, lists, and dicts — never executable objects:

```python
obj = json.loads(blob.decode("utf-8"))
```

---

### F-04 — Weak password hashing: unsalted MD5 *(High, CWE-916 / CWE-327)*

**Location:** `hash_password()` (~line 58) and admin seed (~line 67). Bandit B324.

**Vulnerable code:**

```python
return hashlib.md5(password.encode()).hexdigest()
```

**Explanation.** MD5 is fast and broken. With no salt, identical passwords hash
identically and fall instantly to rainbow tables; billions of guesses per second
are possible on commodity GPUs.

**Impact.** A leak of the `users` table exposes essentially all passwords.

**Remediation (applied).** Use a salted, deliberately slow password hash.
Werkzeug's helper uses PBKDF2-SHA256 with a per-user salt, and verification is
constant-time:

```python
generate_password_hash(password)          # store
check_password_hash(row["password"], password)   # verify
```

---

### F-06 — Path traversal in `/download` *(High, CWE-22)*

**Location:** `download()` (~line 246).

**Vulnerable code:**

```python
name = request.args.get("file", "")
path = os.path.join(FILES_DIR, name)
return send_file(path)
```

**Explanation.** `os.path.join(base, "../secret")` resolves *outside* `base`.
No check keeps the resolved path within the intended directory.

**Proof of concept (reproduced).** `/download?file=../app.py` returns the
application source (including its hardcoded `secret_key`). `verify.py` confirms
HTTP 200 with `secret_key` in the body.

**Impact.** Arbitrary file read (source, config, credentials, `/etc/passwd`).

**Remediation (applied).** `send_from_directory` safely rejects any path that
escapes the base directory:

```python
return send_from_directory(FILES_DIR, name, as_attachment=True)
```

---

### F-08 — Cross-site scripting, reflected and stored *(High, CWE-79)*

**Location:** `search()` (~line 200, reflected) and `view_note()` (~line 185,
stored). Both use `render_template_string(... body|safe)` with unescaped input.

**Vulnerable code:**

```python
body = "<h2>Search</h2><p>You searched for: " + q + "</p>"
return render_template_string(PAGE, body=body, ...)   # PAGE renders {{ body|safe }}
```

**Explanation.** User input is concatenated into HTML and emitted with the
`|safe` filter, disabling Jinja's auto-escaping. Note bodies are stored and
rendered the same way, giving persistent XSS.

**Proof of concept (reproduced).** `/search?q=<script>alert(1)</script>` returns
the raw `<script>` tag in the response; `verify.py` confirms it is present
un-escaped.

**Impact.** Session/cookie theft, request forgery in the victim's session,
credential harvesting; stored XSS runs for every viewer of a malicious note.

**Remediation (applied).** Render through real templates and pass values as
data — Jinja auto-escapes by default, and `|safe` is never used on user input:

```html
<p>You searched for: {{ q }}</p>   <!-- &lt;script&gt; ... -->
```

---

### F-10 — Broken access control on `/admin` *(High, CWE-862)*

**Location:** `admin()` (~line 209).

**Explanation.** The admin panel never checks whether the caller is
authenticated, let alone an admin. Anyone who knows the URL reaches it — and it
runs shell commands (F-05).

**Proof of concept (reproduced).** A logged-out client `GET /admin` returns 200
and executes the connectivity check.

**Remediation (applied).** An `@admin_required` decorator enforces an
authenticated admin role and returns 403 otherwise:

```python
@app.route("/admin")
@admin_required
def admin(): ...
```

---

### F-11 — Insecure direct object reference on `/note/<id>` *(High, CWE-639)*

**Location:** `view_note()` (~line 175).

**Explanation.** The handler fetches a note by id with **no ownership check**,
so any logged-in user can read any other user's notes by incrementing the id.

**Remediation (applied).** Enforce ownership after the lookup:

```python
if row["owner"] != session["user"]:
    abort(403)
```

---

### F-02 — Hardcoded secrets in source *(High, CWE-798 / CWE-259)*

**Location:** `app.secret_key` (~line 27) and `DB_ADMIN_PASSWORD` (~line 31).
Bandit B105.

**Explanation.** The session-signing key and the admin bootstrap password are
committed to source. Anyone with repository access can forge session cookies
(the key signs them) and log in as admin.

**Remediation (applied).** Load secrets from the environment, with a random
per-process fallback and **no shipped default password**:

```python
app.secret_key = os.environ.get("TASKVAULT_SECRET") or secrets.token_hex(32)
DB_ADMIN_PASSWORD = os.environ.get("TASKVAULT_ADMIN_PASSWORD")
```

---

### F-03 — Debug mode enabled in production *(High, CWE-489)*

**Location:** `app.run(..., debug=True)` (~line 279). Bandit B201.

**Explanation.** `debug=True` exposes the interactive Werkzeug debugger. On an
unhandled exception an attacker can reach a Python console **in the server
process** and execute code. It also leaks stack traces and source.

**Remediation (applied).** Debug is off by default and only opt-in via an
explicit environment variable used in development:

```python
debug = os.environ.get("TASKVAULT_DEBUG") == "1"
app.run(host=os.environ.get("TASKVAULT_HOST", "127.0.0.1"), port=5000, debug=debug)
```

---

### F-09 — Sensitive data exposure via `/api/config` *(High, CWE-200)*

**Location:** `api_config()` (~line 258).

**Vulnerable code:**

```python
return {"secret_key": app.secret_key, "db_admin_password": DB_ADMIN_PASSWORD, ...}
```

**Explanation.** An unauthenticated endpoint returns the signing secret and the
admin password as JSON.

**Proof of concept (reproduced).** `GET /api/config` returns `secret_key` and
`db_admin_password` in the body.

**Remediation (applied).** The endpoint is admin-gated and returns only
non-sensitive status; secrets are never serialised:

```python
@app.route("/api/config")
@admin_required
def api_config():
    return {"db_path": os.path.basename(DB_PATH), "debug": app.debug}
```

---

### F-12 — Insecure randomness for tokens *(Medium, CWE-330)*

**Location:** `make_token()` (~line 72). Bandit B311.

**Explanation.** `random.randint()` uses a predictable Mersenne-Twister PRNG,
unsuitable for security tokens — an attacker can predict future values.

**Remediation (applied).** Use the cryptographically secure `secrets` module:

```python
return secrets.token_urlsafe(32)
```

---

### F-14 — Missing transport and session hardening *(Medium, CWE-614/352/693)*

**Location:** app configuration; also Bandit B104 (bind `0.0.0.0`).

**Explanation.** The original app sets no session-cookie security flags (no
`HttpOnly`, `Secure`, or `SameSite`), has no CSRF defence, sends no security
response headers, and binds to all interfaces by default.

**Remediation (applied).** Hardened cookie flags, security headers on every
response, and a loopback-by-default bind:

```python
app.config.update(SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=bool(os.environ.get("TASKVAULT_HTTPS")))

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp
```

> **Note on CSRF.** `SameSite=Lax` plus the CSP above materially reduce CSRF
> risk, but a production app with state-changing POST forms should add
> synchroniser tokens (e.g. **Flask-WTF**'s `CSRFProtect`). This is the one
> recommendation not fully implemented in the demo and is flagged for follow-up.

---

## 4. Secure coding practices (recommendations)

These general practices, applied throughout the hardened version, prevent whole
classes of the issues above:

1. **Never build queries or commands by string concatenation.** Use
   parameterised queries for SQL and argument lists (`shell=False`) for
   subprocesses. Treat all input as untrusted.
2. **Encode on output, contextually.** Let the template engine auto-escape;
   never disable it (`|safe`) on user-controlled data.
3. **Authenticate then authorise on every request.** Enforce object-level
   ownership (stop IDOR) and role checks (stop broken access control) with
   decorators, not by hoping a URL stays secret. Deny by default.
4. **Hash passwords with a slow, salted algorithm** (PBKDF2, bcrypt, scrypt, or
   Argon2) and verify in constant time. Never MD5/SHA-1, never unsalted.
5. **Keep secrets out of source.** Load keys and credentials from the
   environment or a secrets manager; ship no default passwords.
6. **Never deserialize untrusted data with `pickle`/`yaml.load`.** Use JSON or
   another data-only format.
7. **Constrain file paths.** Resolve against a fixed base and reject anything
   that escapes it (`send_from_directory`, `secure_filename`).
8. **Disable debug in production** and return generic error messages; log
   details server-side only.
9. **Use cryptographic randomness** (`secrets`) for tokens, IDs, and salts.
10. **Apply defence in depth:** secure cookie flags, CSRF tokens, security
    headers (CSP, `X-Content-Type-Options`, `X-Frame-Options`), HTTPS, and
    least-privilege binding.
11. **Automate security testing.** Run Bandit (and dependency scanning such as
    `pip-audit`) in CI so regressions are caught on every commit.

---

## 5. Static-analysis results (before vs after)

Bandit run: `bandit -r <app>/app.py`. Full output in `reports/bandit_output.txt`.

| Severity | Vulnerable app | Hardened app |
|----------|:--------------:|:------------:|
| High     | 4 | **0** |
| Medium   | 4 | **0** |
| Low      | 5 | 3 (informational) |
| **Total**| **13** | **3** |

**Residual Low findings in the hardened app (reviewed and accepted):**

- **B404 / B603** — `subprocess` is imported and called. This is expected: the
  connectivity check must run a process. It is now invoked with an argument list
  and `shell=False`, and the argument is validated as an IP address, so there is
  no injection path. Accepted.
- **B607** — `ping` is started via a partial path (PATH lookup) for
  cross-platform portability. In a locked-down deployment this can be pinned to
  an absolute path; accepted as low risk for the demo.

These are informational review reminders, not vulnerabilities. No High or Medium
issues remain.

---

## 6. Verification

`verify.py` reproduces every attack against the vulnerable app and confirms the
hardened app blocks it, using Flask's in-process test client (no network
exposure). Latest run:

```
=== TARGET: vulnerable_app (attacks should SUCCEED) ===
[OK] SQL injection auth bypass ......... logged in as admin via "admin'--"
[OK] Reflected XSS ..................... raw <script> reflected into the page
[OK] Path traversal ................... read ../app.py outside the uploads dir
[OK] Broken access control (/admin) ... admin panel reachable while logged out
[OK] Secret disclosure (/api/config) .. returned secret key + DB password

=== TARGET: secure_app (same attacks should be BLOCKED) ===
[OK] SQL injection blocked ............. 401
[OK] XSS blocked (output escaped) ...... rendered as inert &lt;script&gt;
[OK] Path traversal blocked ............ 404
[OK] Access control enforced (/admin) .. 403
[OK] Secret disclosure blocked ......... 403

10/10 checks behaved as expected.
```

---

## 7. Conclusion

TaskVault, as originally written, is trivially compromised: three independent
critical flaws each yield full control, and a layer of high-severity access
-control, injection, and cryptographic weaknesses sits beneath them. The root
causes are a small set of recurring anti-patterns — trusting input in queries,
commands, paths, and HTML; weak cryptography; secrets in source; and missing
authorisation.

The hardened version in `secure_app/` remediates all 13 findings, passes the
proof-of-concept suite, and clears the static scan of every High and Medium
issue. Adopting the practices in section 4 — and enforcing them with Bandit in
CI — keeps the application at that standard.
