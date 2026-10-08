# Okta Change Auditor

A read-only web UI that answers **who changed what, and when** in Okta — across multiple
Okta orgs (e.g. DEV / STG / PROD) — straight from the System Log API.

## What it does
- Lists administrative changes (apps, policies, rules, groups, users, authenticators) with
  **What / When / Who / Target / Outcome** columns and per-column filters.
- Hides routine noise by default (Okta system actions, bulk assignment churn) with a toggle
  to show everything.
- Nothing is written to Okta.

Typical questions: *"Who deactivated this app yesterday?"*, *"What policy rules changed this
week?"*, *"Who added this user to that group?"*

## Run locally
```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python setup_tokens.py     # one-time: store a read-only API token per org in the OS keyring
.venv/bin/python app.py
```

## Configuration
- API tokens: OS keyring first, environment variables as fallback
  (`OKTA_AUDITOR_{DEV,STG,PROD}_API_TOKEN`). The token only needs System Log read access.
- Optional OIDC sign-in gate: set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
  `APP_BASE_URL` and `FLASK_SECRET_KEY`; when absent the gate is off (local development only).

## Stack
Python 3 · Flask · gunicorn · Pico CSS. A `Dockerfile` is included (port 8080, non-root).
