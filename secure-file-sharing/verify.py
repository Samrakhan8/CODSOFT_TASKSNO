"""
verify.py - end-to-end self-test for SecureShare, using Flask's in-process
test client (no network). Proves the five requirements plus the bonus:

  * authenticated upload/download round-trips correctly
  * files are encrypted at rest (plaintext never appears in the stored blob)
  * tampering with a stored blob is detected (AES-GCM integrity)
  * role-based access control denies, grants, and admin-overrides correctly
  * temporary links expire and respect their download limit

Run:  python verify.py     (exit 0 only if all checks pass)
"""

import io
import os
import tempfile
import time

# Configure the app BEFORE importing it.
os.environ["SFS_SECRET"] = "test-secret-not-shipped"
os.environ["SFS_ADMIN_PASSWORD"] = "Adm1n!bootstrap"
os.environ["SFS_DB"] = os.path.join(tempfile.gettempdir(), "sfs_verify.db")
if os.path.exists(os.environ["SFS_DB"]):
    os.remove(os.environ["SFS_DB"])

import app as A  # noqa: E402

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(ok)
    print("[%s] %s%s" % ("OK  " if ok else "FAIL", name,
                         ("  - " + detail) if detail else ""))


def client():
    return A.app.test_client()


def register(c, u, p="password123"):
    return c.post("/register", data={"username": u, "password": p})


def login(c, u, p="password123"):
    return c.post("/login", data={"username": u, "password": p})


def upload(c, name, content):
    return c.post("/upload",
                  data={"file": (io.BytesIO(content), name)},
                  content_type="multipart/form-data", follow_redirects=True)


with A.app.app_context():
    A.ensure_admin()

created_blobs = []

# --- Accounts ------------------------------------------------------------
alice, bob, carol = client(), client(), client()
register(alice, "alice"); login(alice, "alice")
register(bob, "bob"); login(bob, "bob")
register(carol, "carol"); login(carol, "carol")
admin = client(); login(admin, "admin", "Adm1n!bootstrap")

SECRET = b"TOP-SECRET-CONTENT-marker-9f3a2b7c payroll.xlsx contents here"
upload(alice, "payroll.xlsx", SECRET)

fid = A.get_db().execute(
    "SELECT id FROM files WHERE owner='alice' ORDER BY created_at DESC LIMIT 1"
).fetchone()["id"]
created_blobs.append(fid)

# --- 1. Encryption at rest ----------------------------------------------
blob_path = os.path.join(A.STORAGE_DIR, fid + ".enc")
blob = open(blob_path, "rb").read()
check("file stored encrypted (blob exists)", os.path.exists(blob_path))
check("plaintext NOT present in stored blob", SECRET not in blob,
      "ciphertext %d bytes" % len(blob))
check("marker string absent from blob", b"TOP-SECRET-CONTENT" not in blob)

# --- 2. Authenticated download round-trip -------------------------------
r = alice.get("/files/%s/download" % fid)
check("owner downloads original bytes", r.status_code == 200 and r.data == SECRET)

# unauthenticated download is refused
r = client().get("/files/%s/download" % fid)
check("anonymous download redirected to login",
      r.status_code in (301, 302) and "/login" in r.headers.get("Location", ""))

# --- 3. RBAC: another user is denied ------------------------------------
r = bob.get("/files/%s/download" % fid)
check("non-owner denied (403)", r.status_code == 403)

# --- 4. Per-user grant ---------------------------------------------------
alice.post("/files/%s/grant" % fid,
           data={"principal_type": "user", "principal": "bob"})
r = bob.get("/files/%s/download" % fid)
check("granted user can now download", r.status_code == 200 and r.data == SECRET)
r = carol.get("/files/%s/download" % fid)
check("ungranted third user still denied", r.status_code == 403)

# --- 5. Role grant -------------------------------------------------------
alice.post("/files/%s/grant" % fid,
           data={"principal_type": "role", "principal": "user"})
r = carol.get("/files/%s/download" % fid)
check("role grant (user) lets carol download", r.status_code == 200)

# --- 6. Admin override ---------------------------------------------------
bob2 = upload_id = None
upload(bob, "bob-notes.txt", b"bob private notes")
bob_fid = A.get_db().execute(
    "SELECT id FROM files WHERE owner='bob' ORDER BY created_at DESC LIMIT 1"
).fetchone()["id"]
created_blobs.append(bob_fid)
r = admin.get("/files/%s/download" % bob_fid)
check("admin can access any file without a grant", r.status_code == 200)
r = alice.get("/files/%s/download" % bob_fid)
check("unrelated user cannot access bob's file", r.status_code == 403)

# --- 7. Admin-only area --------------------------------------------------
check("admin reaches /admin", admin.get("/admin").status_code == 200)
check("regular user gets 403 on /admin", bob.get("/admin").status_code == 403)

# --- 8. Temporary link: download limit ----------------------------------
alice.post("/files/%s/share" % fid, data={"minutes": "60", "max_downloads": "1"})
token = A.get_db().execute(
    "SELECT token FROM links WHERE file_id=? ORDER BY created_at DESC LIMIT 1",
    (fid,)).fetchone()["token"]
anon = client()
r1 = anon.get("/d/%s" % token)
r2 = anon.get("/d/%s" % token)
check("temp link serves file once", r1.status_code == 200 and r1.data == SECRET)
check("temp link blocks 2nd download past limit (410)", r2.status_code == 410)

# --- 9. Temporary link: expiry ------------------------------------------
alice.post("/files/%s/share" % fid, data={"minutes": "60", "max_downloads": "0"})
tok2 = A.get_db().execute(
    "SELECT token FROM links WHERE file_id=? ORDER BY created_at DESC LIMIT 1",
    (fid,)).fetchone()["token"]
# force it to have already expired
A.get_db().execute("UPDATE links SET expires_at=? WHERE token=?",
                   (time.time() - 1, tok2))
A.get_db().commit()
check("expired temp link is refused (410)",
      client().get("/d/%s" % tok2).status_code == 410)
check("unknown temp link 404s", client().get("/d/deadbeeftoken").status_code == 404)

# --- 10. Tamper detection (AES-GCM integrity) ---------------------------
with open(blob_path, "r+b") as fh:
    fh.seek(0)
    first = fh.read(1)
    fh.seek(0)
    fh.write(bytes([first[0] ^ 0xFF]))   # flip one bit
r = alice.get("/files/%s/download" % fid)
check("tampered blob fails to decrypt (not served)", r.status_code != 200,
      "status %d" % r.status_code)

# --- Cleanup -------------------------------------------------------------
for b in created_blobs:
    p = os.path.join(A.STORAGE_DIR, b + ".enc")
    if os.path.exists(p):
        os.remove(p)
if os.path.exists(os.environ["SFS_DB"]):
    try:
        A.get_db().close()
    except Exception:
        pass
    os.remove(os.environ["SFS_DB"])

print("\n%d/%d checks passed." % (sum(RESULTS), len(RESULTS)))
raise SystemExit(0 if all(RESULTS) else 1)
