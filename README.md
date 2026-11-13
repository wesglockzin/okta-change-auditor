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

## Type
A web service (Flask, served by gunicorn in the container).

## Run
```bash
cp .env.example .env   # fill in the required settings
docker compose up
```
Without Docker: `pip install -e . && python app.py` (settings must be in the environment).
Tests: `pip install -e ".[dev]" && pytest`.

## Configuration
Every setting is an environment variable; `.env.example` lists them all with defaults.
Required settings have no default, and the app refuses to start naming the missing one.
- `OKTA_ORGS` (required): `name=url` pairs, comma separated, any number. The page highlights only an org named `prod` (any letter case) as production.
- `OKTA_AUDITOR_<NAME>_API_TOKEN` (one per org): a read-only token with System Log read
  access. The optional OS keyring (`pip install '.[keyring]'`, then `python setup_tokens.py`)
  is only a fallback when the variable is empty.
- `AUTH_MODE`: `oidc` (default) or `none` (no sign-in; local use only). With `oidc`, set
  `FLASK_SECRET_KEY`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and at least one
  of `OIDC_ALLOWED_EMAILS` / `OIDC_ALLOWED_DOMAINS`.
- `HOST` (default `127.0.0.1`; the container uses `0.0.0.0`), `PORT` (default `8080`),
  `APP_BASE_URL` (an https URL makes the session cookie Secure).
- Limits and noise rules (`DEFAULT_CHANGE_LIMIT`, `MAX_HOURS`, `AUTOMATION_UA_SUBSTRINGS`,
  `SYSTEM_ACTOR_ALTERNATE_IDS`, ...): see `.env.example`.

## Stack
Python 3.10+ · Flask · gunicorn · Pico CSS (loaded from a CDN). The `Dockerfile` runs as a
non-root user and reads `PORT`.

## Known limitations
- **Bounded by the System Log.** Okta keeps roughly 90 days of System Log history, so
  older changes simply aren't there.
- **Noise filtering is heuristic.** "Routine" events are hidden by event-type and actor
  rules; an unusual change made through an automated path can be hidden until you toggle
  "show everything".
- **No lockfile yet**; dependencies have version ranges only.
- **Pico CSS comes from a CDN**, so the UI is unstyled offline.
