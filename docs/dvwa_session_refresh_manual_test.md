# Manual DVWA integration test — authenticated replay session refresh

This procedure is intentionally **not** an automated pytest test: it
requires a real, running DVWA instance (e.g. on Kali), so it lives here
as a documented manual test instead of being faked in the unit suite.
Nothing in `backend/replay/session_refresh.py` or its callers is
DVWA-specific — this test exercises the same generic,
environment-variable-configured login flow any form-based-login
target would use.

## What this proves

1. A login/session is actually established using explicit,
   environment-configured credentials — nothing is guessed.
2. The vulnerability request is replayed using that *current* session,
   not the (possibly stale) session captured at scan time.
3. Verification reaches a real classification when the vulnerability
   is genuinely exploitable — not a fabricated result.
4. Killing and restarting the backend does not lose persisted scan
   data (this exercises the separate SQLite persistence branch; only
   relevant if that branch's work is present in the running backend).
5. A *new* verification run obtains a *fresh* session rather than
   reusing the scanner-time cookie, even if that cookie has since
   expired.

## Prerequisites

- DVWA running and reachable, e.g. `http://127.0.0.1/DVWA`, security
  level set to **Low**.
- A ZAP (or Burp) scan report already captured against DVWA's SQLi,
  CSRF, and/or Reflected XSS pages (the same fixtures used by this
  repo's automated tests — `tests/fixtures/zap/zap_sqli_positive.json`
  etc. — are real captures of this exact scenario and can be reused).
- The VulnVerify backend and frontend running normally
  (`uvicorn backend.main:app`, `npm run dev`).

## Step 1 — configure the login

Set these environment variables before starting the backend (a local
`.env` file works too, since `python-dotenv` is already a project
dependency):

```bash
export VULNVERIFY_AUTH_LOGIN_URL="http://127.0.0.1/DVWA/login.php"
export VULNVERIFY_AUTH_USERNAME="admin"
export VULNVERIFY_AUTH_PASSWORD="password"
export VULNVERIFY_AUTH_EXTRA_FIELD_Login="Login"
```

`VULNVERIFY_AUTH_USERNAME_FIELD`/`VULNVERIFY_AUTH_PASSWORD_FIELD`
default to `username`/`password`, which match DVWA's login form field
names, so they don't need to be set here. `VULNVERIFY_AUTH_COOKIE_NAME`
is left unset so every cookie DVWA's login response sets is reused.

Restart the backend after setting these (environment variables are
read once per process, not per request).

## Step 2 — let a scanner-time session go stale

- Note the `Cookie` header captured in the uploaded scan's findings
  (visible in `GET /api/v1/scans/{scan_id}/findings`).
- Wait for DVWA's PHP session to actually expire (or manually clear it
  — e.g. restart DVWA's PHP session store / delete the session file /
  simply wait past `session.gc_maxlifetime`), so a replay using that
  exact captured cookie would now hit DVWA's login page instead of the
  vulnerable page.

## Step 3 — verify and observe the refresh

Upload the scan (or use an already-uploaded one) and either let
automatic verification run, or trigger `/verify` manually for a
SQLi/CSRF/XSS finding. Watch the backend log for lines like:

```
Session refresh succeeded: login_url=http://127.0.0.1/DVWA/login.php status=302 cookie_count=1
```

(never a line containing the actual username/password — confirm this
directly by grepping the log output for the configured password
string and finding no matches).

Confirm in the resulting `VerifiedFinding` (`GET
/api/v1/scans/{scan_id}/verified-findings`) that the classification is
no longer `INCONCLUSIVE` for "authentication/session state
unavailable" reasons — DVWA's Low-security SQLi/CSRF/XSS pages should
now classify TRUE_POSITIVE, using the fresh session rather than the
expired scanner-time cookie.

## Step 4 — restart persistence (if the persistence branch is present)

- `kill` the backend process, then start a new one pointed at the same
  database file.
- Confirm `GET /api/v1/scans` and the scan's findings/verified-findings
  are unchanged after the restart.

## Step 5 — confirm a second run gets its own fresh session

- Let DVWA's session expire again (or manually invalidate it).
- Trigger verification a second time.
- Confirm the backend log shows a **new** `Session refresh succeeded`
  line (a second, independent login), and that verification again
  reaches a real classification rather than falling back to
  INCONCLUSIVE — proving the mechanism obtains a current session each
  time it's actually needed, rather than caching a session
  indefinitely across backend restarts (the in-process session cache
  in `backend/services/auto_verification_service.py` is scoped to one
  `run_auto_verification` call and is not persisted).
