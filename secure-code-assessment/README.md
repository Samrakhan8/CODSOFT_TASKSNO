# Secure Code Assessment — TaskVault

A complete secure code assessment exercise: a deliberately vulnerable Python/
Flask web application, a static + manual security review of it, a hardened
rewrite that fixes every issue, and a report documenting the vulnerabilities
and recommended fixes.

## What's here

```
secure-code-assessment/
├── vulnerable_app/          # the assessment TARGET (intentionally insecure)
│   ├── app.py               #   13 planted, realistic vulnerabilities
│   └── uploads/             #   files the (vulnerable) download endpoint serves
├── secure_app/              # the hardened rewrite — every finding fixed
│   ├── app.py               #   FIX #n comments map to the report findings
│   └── templates/           #   auto-escaping Jinja templates (kills XSS)
├── reports/
│   ├── SECURITY_ASSESSMENT.md   # the full report (read this)
│   ├── bandit_output.txt        # raw Bandit static-analysis output
│   └── bandit_report.json       # machine-readable Bandit results
├── verify.py                # runnable PoC: attacks succeed vs vuln, blocked vs secure
├── requirements.txt
└── README.md
```

> **The vulnerable app is for study only.** Do not deploy it, expose it to a
> network, or copy any pattern from it. It exists so the review has real,
> reproducible flaws to find.

## The assessment

The full write-up is in **[`reports/SECURITY_ASSESSMENT.md`](reports/SECURITY_ASSESSMENT.md)**.
It covers 13 findings — including SQL injection, OS command injection, and
insecure deserialization (all critical) — each with location, vulnerable code,
a reproduced proof-of-concept, impact, and the applied fix, plus a section of
secure coding recommendations.

**Tools used:** [Bandit](https://bandit.readthedocs.io/) for static analysis,
manual code review, and a runtime proof-of-concept harness.

## Running it

Install dependencies (Python 3.9+):

```
pip install -r requirements.txt
```

### Reproduce the assessment

Static analysis:

```
bandit -r vulnerable_app/app.py      # 4 High, 4 Medium, 5 Low
bandit -r secure_app/app.py          # 0 High, 0 Medium, 3 informational Low
```

Prove the exploits and the fixes (no network exposure — uses Flask's test client):

```
python verify.py                     # -> 10/10 checks behaved as expected
```

### Run the apps (optional)

The hardened app reads its secrets from the environment:

```
# PowerShell
$env:TASKVAULT_SECRET="$(python -c 'import secrets;print(secrets.token_hex(32))')"
$env:TASKVAULT_ADMIN_PASSWORD="ChangeThisBootstrapPw!"
python secure_app/app.py             # http://127.0.0.1:5000  (debug OFF, loopback only)
```

Log in as `admin` with the bootstrap password you set.

## Summary of remediation

| Static scan | Vulnerable | Hardened |
|-------------|:----------:|:--------:|
| High        | 4 | **0** |
| Medium      | 4 | **0** |
| Low         | 5 | 3 (informational) |

All 13 findings fixed; PoC suite passes 10/10.
