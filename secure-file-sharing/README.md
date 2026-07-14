# SecureShare — Encrypted File-Sharing System

An authenticated, role-based file-sharing web app (Python/Flask). Every file is
**encrypted at rest** with AES-256-GCM envelope encryption, access is governed
by **role-based access control** plus per-file grants, and files can be shared
through **temporary links that expire and enforce a download limit**.

## Requirements covered

| Requirement | How |
|-------------|-----|
| Build a secure file-sharing app (Python/Node) | Flask app (`app.py`) |
| Authenticated upload/download | Session auth, PBKDF2-hashed passwords, login-gated routes |
| Encrypt files before storing | AES-256-GCM envelope encryption (`crypto_store.py`) |
| Role-based access control | `admin` / `user` roles + per-file user/role grants |
| **Bonus:** temporary links with expiry | `/d/<token>` links with time + download-count limits |

## How the encryption works (envelope encryption)

1. A long-lived **master key** (KEK) is read from `SFS_MASTER_KEY`, or generated
   once and stored in `storage/.masterkey`.
2. Each uploaded file gets its own random **data key** (DEK). The file is
   encrypted with AES-256-GCM under its DEK.
3. The DEK is then itself encrypted ("wrapped") with the master key. Only the
   ciphertext, the wrapped DEK, and the nonces are written to disk — **the
   plaintext and the plaintext DEK never persist**.
4. The file id is bound in as AES-GCM associated data, and a SHA-256 of the
   plaintext is checked on read, so any tampering or record-swapping is
   detected and the file is refused.

This is the pattern KMS-backed systems use, kept dependency-light.

## Access control

- **Owner** — full control of their files (download, share, grant, delete).
- **admin** — can access, and audit, every file; manages user roles.
- **user** — default role; can access files they own or that are shared with
  them, individually or via a role grant.
- **Per-file grants** — an owner/admin can grant a specific **user** or an
  entire **role** read access to a file.

Every file operation re-checks authorisation server-side (`can_access` /
`can_manage`); a missing or wrong role returns 403.

## Running it

```
pip install -r requirements.txt

# Set secrets (PowerShell). SFS_MASTER_KEY must be base64 of 32 bytes; if unset,
# one is generated and persisted to storage/.masterkey.
$env:SFS_SECRET = python -c "import secrets;print(secrets.token_hex(32))"
$env:SFS_MASTER_KEY = python -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
$env:SFS_ADMIN_PASSWORD = "ChangeThisAdminPw!"

python app.py            # http://127.0.0.1:5001   (debug off, loopback only)
```

Sign in as `admin` with `SFS_ADMIN_PASSWORD`, or register a normal user.

### Configuration (environment variables)

| Variable | Purpose | Default |
|----------|---------|---------|
| `SFS_SECRET` | Flask session-signing key | random per process |
| `SFS_MASTER_KEY` | base64 of 32 bytes; the KEK | generated + persisted |
| `SFS_ADMIN_PASSWORD` | bootstrap the first admin account | (no admin created) |
| `SFS_DB` | SQLite database path | `secureshare.db` |
| `SFS_HTTPS` | set when behind TLS (marks cookies Secure) | off |
| `SFS_DEBUG` / `SFS_HOST` | dev only | off / `127.0.0.1` |

## Verify it works

```
python verify.py
```

Runs 18 in-process assertions and prints `18/18 checks passed`, proving:
encryption at rest (plaintext absent from the stored blob), download round-trip,
tamper detection (flipped byte fails AES-GCM), RBAC deny/grant/role-grant/admin
-override, admin-only area, and temporary links honouring their download limit
and expiry.

## Project layout

```
secure-file-sharing/
├── app.py            # Flask app: auth, RBAC, upload/download, links, admin
├── crypto_store.py   # AES-256-GCM envelope encryption at rest
├── db.py             # SQLite schema (users, files, grants, links, audit)
├── templates/        # auto-escaping Jinja UI (login, register, dashboard, admin)
├── storage/          # encrypted blobs + master key (gitignored)
├── verify.py         # 18-check end-to-end self-test
├── requirements.txt
└── README.md
```

## Security notes

- Passwords are salted + PBKDF2-hashed (werkzeug); the DB never stores plaintext.
- File ids are server-generated UUIDs, so stored paths can never be traversed;
  original filenames are sanitised with `secure_filename`.
- Parameterised SQL throughout; uploads capped at 16 MB.
- Session cookies are `HttpOnly` + `SameSite=Lax` (+ `Secure` under `SFS_HTTPS`);
  security headers (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`) on every
  response; debug off by default.
- All actions are written to an append-only audit log (visible to admins).
- Temporary links are high-entropy (`secrets.token_urlsafe(32)`); a link is a
  capability, so treat the URL as sensitive.
