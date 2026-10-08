from __future__ import annotations

import logging
import os
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Iterable

import requests
from authlib.integrations.flask_client import OAuth
from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from shared_http import make_session
from shared_docs import register_howto

APP_VERSION = "0.6.6"

_session = make_session("ChangeAuditor", APP_VERSION)

OKTA_URLS = {
    "dev":  "https://host.example.com",
    "stg":  "https://host.example.com",
    "prod": "https://host.example.com",
}

TOKEN_VAR = {
    "dev":  "OKTA_AUDITOR_DEV_API_TOKEN",
    "stg":  "OKTA_AUDITOR_STG_API_TOKEN",
    "prod": "OKTA_AUDITOR_PROD_API_TOKEN",
}

KEYRING_SERVICE = "okta-change-auditor"
OKTA_PAGE_LIMIT = 1000
DEFAULT_CHANGE_LIMIT = 500
MAX_CHANGE_LIMIT = 5000
MAX_RAW_COLLAPSE_ROWS = 10000
MAX_RAW_SCAN_EVENTS = 30000
REQUEST_TIMEOUT_SECONDS = 30

OKTA_429_MAX_RETRIES = 3
OKTA_429_MAX_WAIT_SECONDS = 90
OKTA_RATE_LIMIT_FLOOR = 5


SYSTEM_ACTOR_ALTERNATE_IDS = {"system@okta.com"}

AUTOMATION_UA_SUBSTRINGS: tuple[str, ...] = (
    "azuqua",
    "okta-",
    "oktasync",
    "workflows",
    "okta integration",
    "python-requests",
    "go-resty",
    "go-http-client",
    "curl/",
    "wget/",
    "postmanruntime",
    "apache-httpclient",
    "java/",
    "okhttp",
    "node-fetch",
    "axios",
)

SERVER_SIDE_AUTOMATION_UA_EXACT: tuple[str, ...] = (
    "Azuqua",
)


def _event_is_automated(event: dict) -> bool:
    client = event.get("client") or {}
    raw_ua = (client.get("userAgent") or {}).get("rawUserAgent") or ""
    raw_ua_lower = raw_ua.lower()

    if any(s in raw_ua_lower for s in AUTOMATION_UA_SUBSTRINGS):
        return True

    if not raw_ua and not client.get("ipAddress") and not client.get("device"):
        return True

    return False


def _event_is_system(event: dict) -> bool:
    actor = event.get("actor") or {}
    alt_id = (actor.get("alternateId") or "").lower()
    if alt_id in {a.lower() for a in SYSTEM_ACTOR_ALTERNATE_IDS}:
        return True
    if (actor.get("type") or "User") != "User":
        return True
    return False


MEMBERSHIP_PREFIXES: tuple[str, ...] = (
    "application.user_membership.",
    "group.user_membership.",
)
LIFECYCLE_OPS_PREFIXES: tuple[str, ...] = (
    "user.lifecycle.",
    "user.account.update_profile",
)


def _event_type_starts_with(event: dict, prefixes: tuple[str, ...]) -> bool:
    et = event.get("eventType") or ""
    return any(et.startswith(p) for p in prefixes)


def _event_is_membership(event: dict) -> bool:
    return _event_type_starts_with(event, MEMBERSHIP_PREFIXES)


def _event_is_lifecycle_ops(event: dict) -> bool:
    return _event_type_starts_with(event, LIFECYCLE_OPS_PREFIXES)


def _event_flags(event: dict) -> dict[str, bool]:
    return {
        "automated":     _event_is_automated(event),
        "system":        _event_is_system(event),
        "membership":    _event_is_membership(event),
        "lifecycle_ops": _event_is_lifecycle_ops(event),
    }


FLAG_DEFINITIONS = [
    {
        "key": "automated",
        "label": "Hide automated activity",
        "hint": "Workflows, scripts, API tokens — anything not coming from a browser",
        "default_hide": True,
    },
    {
        "key": "system",
        "label": "Hide system principal",
        "hint": "Okta system actions (system@okta.com, SystemPrincipal)",
        "default_hide": True,
    },
    {
        "key": "membership",
        "label": "Hide membership ops",
        "hint": "Bulk user/group assignment churn — application.user_membership.*, group.user_membership.*",
        "default_hide": True,
    },
    {
        "key": "lifecycle_ops",
        "label": "Hide lifecycle ops",
        "hint": "User provisioning churn — user.lifecycle.*, user.account.update_profile",
        "default_hide": True,
    },
]
DEFAULT_HIDE_FLAGS = frozenset(d["key"] for d in FLAG_DEFINITIONS if d["default_hide"])
KNOWN_FLAGS = frozenset(d["key"] for d in FLAG_DEFINITIONS)

CHANGE_EVENT_FILTER: tuple[str, ...] = (
    "user.lifecycle.",
    "user.account.update_profile",
    "user.account.privilege.grant",
    "user.account.privilege.revoke",
    "group.lifecycle.",
    "group.user_membership.",
    "application.lifecycle.",
    "application.user_membership.",
    "application.policy.",
    "policy.lifecycle.",
    "policy.rule.",
    "system.idp.",
    "zone.lifecycle.",
    "authenticator.lifecycle.",
    "iam.",
    "security.protected_action.",
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger("okta-change-auditor")

try:
    import keyring
except ImportError:
    keyring = None


def get_token(env: str) -> str:
    var = TOKEN_VAR.get(env)
    if not var:
        return ""
    if keyring is not None:
        try:
            kr = keyring.get_password(KEYRING_SERVICE, var)
            if kr:
                return kr
        except Exception as e:
            log.debug("keyring lookup failed for %s: %s", var, e)
    return os.environ.get(var, "")


def _build_event_filter(prefixes: Iterable[str]) -> str:
    parts = [f'eventType sw "{p}"' for p in prefixes]
    return "(" + " or ".join(parts) + ")"


def _build_okta_filter(hide_flags: frozenset[str]) -> str:
    excluded_prefixes: set[str] = set()
    if "membership" in hide_flags:
        excluded_prefixes.update(MEMBERSHIP_PREFIXES)
    if "lifecycle_ops" in hide_flags:
        excluded_prefixes.update(LIFECYCLE_OPS_PREFIXES)
    active_prefixes = tuple(p for p in CHANGE_EVENT_FILTER if p not in excluded_prefixes)

    parts = [_build_event_filter(active_prefixes)]
    if "automated" in hide_flags:
        for ua in SERVER_SIDE_AUTOMATION_UA_EXACT:
            parts.append(f'client.userAgent.rawUserAgent ne "{ua}"')
        parts.append('client.userAgent.rawUserAgent pr')
    if "system" in hide_flags:
        parts.append('actor.alternateId ne "system@okta.com"')
        parts.append('actor.type ne "SystemPrincipal"')
    return " and ".join(parts)


def _iso_z(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_okta_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _local_iso(value: str | None) -> str:
    parsed = _parse_okta_datetime(value)
    if not parsed:
        return value or ""
    return parsed.astimezone().isoformat(timespec="seconds")


def _target_label(event: dict) -> str:
    targets = event.get("target") or []
    if not targets:
        return ""

    first = targets[0] or {}
    display = _target_display(first)
    target_type = first.get("type") or ""
    if display and target_type:
        return f"{display} ({target_type})"
    return display or target_type


def _target_display(target: dict) -> str:
    if (target.get("type") or "") == "AppInstance":
        return (
            target.get("alternateId")
            or target.get("displayName")
            or target.get("id")
            or ""
        )
    return (
        target.get("displayName")
        or target.get("alternateId")
        or target.get("id")
        or ""
    )


def _project_change_event(event: dict) -> dict:
    actor = event.get("actor") or {}
    outcome = event.get("outcome") or {}
    return {
        "when": _local_iso(event.get("published")),
        "actor": actor.get("alternateId") or actor.get("displayName") or actor.get("id") or "",
        "flags": _event_flags(event),
        "eventType": event.get("eventType") or "",
        "target": _target_label(event),
        "outcome": outcome.get("result") or "",
        "raw": event,
    }


def _row_datetime(row: dict) -> datetime | None:
    raw = row.get("raw")
    if isinstance(raw, dict):
        parsed = _parse_okta_datetime(raw.get("published"))
        if parsed:
            return parsed
    parsed = _parse_okta_datetime(row.get("when"))
    if parsed and parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _group_key(row: dict) -> tuple[str, str]:
    return (row.get("actor") or "", row.get("eventType") or "")


def _make_burst_group(rows: list[dict]) -> dict:
    if len(rows) == 1:
        return rows[0]

    outcomes: dict[str, int] = {}
    sample_targets: list[str] = []
    seen_targets: set[str] = set()
    raw_events: list[dict] = []

    for row in rows:
        outcome = row.get("outcome") or ""
        outcomes[outcome] = outcomes.get(outcome, 0) + 1

        target = row.get("target") or ""
        if target and target not in seen_targets:
            seen_targets.add(target)
            if len(sample_targets) < 5:
                sample_targets.append(target)

        raw = row.get("raw")
        raw_events.append(raw if isinstance(raw, dict) else row)

    return {
        "when": rows[0].get("when") or "",
        "when_oldest": rows[-1].get("when") or "",
        "actor": rows[0].get("actor") or "",
        "flags": dict(rows[0].get("flags") or {}),
        "eventType": rows[0].get("eventType") or "",
        "count": len(rows),
        "outcomes": outcomes,
        "outcome": next(iter(outcomes)) if len(outcomes) == 1 else "MIXED",
        "sample_targets": sample_targets,
        "raw": raw_events,
    }


def _collapse_bursts(rows: list[dict], window_seconds: int = 60) -> list[dict]:
    grouped: list[dict] = []
    current: list[dict] = []
    current_key: tuple[str, str] | None = None
    current_last: datetime | None = None

    for row in rows:
        row_key = _group_key(row)
        row_time = _row_datetime(row)

        same_burst = False
        if current and row_key == current_key and current_last and row_time:
            same_burst = abs((current_last - row_time).total_seconds()) <= window_seconds

        if same_burst:
            current.append(row)
            current_last = row_time
            continue

        if current:
            grouped.append(_make_burst_group(current))
        current = [row]
        current_key = row_key
        current_last = row_time

    if current:
        grouped.append(_make_burst_group(current))

    return grouped


def _next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    normalized = link_header.replace(">,<", ">, <")
    for link in requests.utils.parse_header_links(normalized):
        if link.get("rel") == "next" and link.get("url"):
            return link["url"]
    return None


def _okta_429_wait_seconds(response: requests.Response) -> float:
    reset = response.headers.get("X-Rate-Limit-Reset")
    if reset:
        try:
            wait = float(reset) - time.time()
            if wait > 0:
                return min(wait + 1.0, OKTA_429_MAX_WAIT_SECONDS)
        except ValueError:
            pass
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            return min(max(float(retry_after), 1.0), OKTA_429_MAX_WAIT_SECONDS)
        except ValueError:
            pass
    return 10.0


def _maybe_pre_throttle(response: requests.Response, env: str) -> None:
    remaining_str = response.headers.get("X-Rate-Limit-Remaining")
    if not remaining_str:
        return
    try:
        remaining = int(remaining_str)
    except ValueError:
        return
    if remaining > OKTA_RATE_LIMIT_FLOOR:
        return
    reset_str = response.headers.get("X-Rate-Limit-Reset")
    if not reset_str:
        return
    try:
        wait = float(reset_str) - time.time()
    except ValueError:
        return
    if wait <= 0 or wait > OKTA_429_MAX_WAIT_SECONDS:
        return
    wait_padded = wait + 1.0
    logging.getLogger(__name__).info(
        "[%s] Okta bucket low (remaining=%d); sleeping %.1fs until reset",
        env, remaining, wait_padded,
    )
    time.sleep(wait_padded)


def _okta_get_with_retry(
    session: requests.Session,
    url: str,
    params: dict | None,
    headers: dict,
    env: str,
) -> requests.Response:
    response: requests.Response | None = None
    for attempt in range(OKTA_429_MAX_RETRIES + 1):
        response = session.get(
            url,
            params=params,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code != 429:
            _maybe_pre_throttle(response, env)
            return response
        if attempt >= OKTA_429_MAX_RETRIES:
            break
        wait = _okta_429_wait_seconds(response)
        logging.getLogger(__name__).warning(
            "[%s] Okta 429; waiting %.1fs (attempt %d/%d)",
            env, wait, attempt + 1, OKTA_429_MAX_RETRIES,
        )
        time.sleep(wait)
    return response


def _count_okta_events_by_prefix(
    env: str,
    since: datetime,
    until: datetime,
    prefixes: tuple[str, ...],
    page_cap: int = 50,
) -> int:
    token = get_token(env)
    if not token:
        return 0
    filter_expr = "(" + " or ".join(f'eventType sw "{p}"' for p in prefixes) + ")"
    params = {
        "since": _iso_z(since),
        "until": _iso_z(until),
        "filter": filter_expr,
        "limit": OKTA_PAGE_LIMIT,
    }
    headers = {"Authorization": f"SSWS {token}"}
    url: str | None = f"{OKTA_URLS[env]}/api/v1/logs"
    next_params: dict | None = params
    count = 0
    pages = 0
    while url and pages < page_cap:
        response = _okta_get_with_retry(_session, url, next_params, headers, env)
        if not response.ok:
            break
        events = response.json()
        if not isinstance(events, list):
            break
        count += len(events)
        link = _next_link(response.headers.get("Link"))
        if not link:
            break
        url = link
        next_params = None
        pages += 1
    return count


PREFIX_HIDE_FAMILIES: dict[str, tuple[str, ...]] = {
    "membership":    MEMBERSHIP_PREFIXES,
    "lifecycle_ops": LIFECYCLE_OPS_PREFIXES,
}


def _fetch_changes(
    env: str,
    since: datetime,
    until: datetime,
    limit: int = DEFAULT_CHANGE_LIMIT,
    hide_flags: frozenset[str] = frozenset(),
) -> dict:
    token = get_token(env)
    if not token:
        raise RuntimeError(f"no API token configured for {env}")

    cap = max(0, int(limit))
    if cap == 0:
        return {"rows": [], "filtered": {}, "truncated": False, "scanned": 0}
    raw_cap = min(cap * 20, MAX_RAW_COLLAPSE_ROWS)

    count_futures: dict[str, "Future[int]"] = {}
    if hide_flags:
        prefix_active = [f for f in hide_flags if f in PREFIX_HIDE_FAMILIES]
        if prefix_active:
            count_executor = ThreadPoolExecutor(max_workers=len(prefix_active))
            for flag in prefix_active:
                count_futures[flag] = count_executor.submit(
                    _count_okta_events_by_prefix,
                    env, since, until, PREFIX_HIDE_FAMILIES[flag],
                )
            count_executor.shutdown(wait=False)

    url = f"{OKTA_URLS[env]}/api/v1/logs"
    params = {
        "since": _iso_z(since),
        "until": _iso_z(until),
        "filter": _build_okta_filter(hide_flags),
        "limit": OKTA_PAGE_LIMIT,
    }
    headers = {"Authorization": f"SSWS {token}"}

    rows: list[dict] = []
    filtered: dict[str, int] = {}
    scanned = 0
    truncated = False
    next_url: str | None = url
    next_params: dict | None = params

    while next_url:
        if len(rows) >= raw_cap or scanned >= MAX_RAW_SCAN_EVENTS:
            truncated = True
            break

        response = _okta_get_with_retry(
            _session, next_url, next_params, headers, env
        )
        if response.status_code == 401:
            raise RuntimeError(f"Okta API returned 401 for {env}; check the API token")
        if response.status_code == 429:
            raise RuntimeError(
                f"Okta {env.upper()} rate limit exhausted (HTTP 429). "
                f"This token's /api/v1/logs bucket resets each minute — "
                f"wait ~60s and retry. If this persists, the token may be "
                f"shared with another tool consuming the bucket."
            )
        if not response.ok:
            detail = response.text[:500].strip()
            raise RuntimeError(
                f"Okta System Log request failed for {env}: "
                f"HTTP {response.status_code} {detail}"
            )

        events = response.json()
        if not isinstance(events, list):
            raise RuntimeError(f"Okta System Log returned unexpected payload for {env}")

        for event in events:
            if not isinstance(event, dict):
                continue
            scanned += 1
            projected = _project_change_event(event)
            flags = projected.get("flags") or {}
            hits = [name for name in hide_flags if flags.get(name)]
            if hits:
                for name in hits:
                    filtered[name] = filtered.get(name, 0) + 1
                continue
            rows.append(projected)
            if len(rows) >= raw_cap or scanned >= MAX_RAW_SCAN_EVENTS:
                break

        next_link = _next_link(response.headers.get("Link"))
        if not next_link:
            next_url = None
        elif len(rows) >= raw_cap or scanned >= MAX_RAW_SCAN_EVENTS:
            truncated = True
            next_url = None
        else:
            next_url = next_link
            next_params = None

    rows.sort(
        key=lambda row: _parse_okta_datetime((row.get("raw") or {}).get("published"))
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    grouped = _collapse_bursts(rows)

    for flag, fut in count_futures.items():
        try:
            n = fut.result(timeout=25)
            if n:
                filtered[flag] = filtered.get(flag, 0) + n
        except Exception as e:
            log.warning("prefix-hide count for %s failed: %s", flag, e)

    return {
        "rows": grouped[:cap],
        "filtered": filtered,
        "truncated": truncated,
        "scanned": scanned,
    }


FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32).hex()
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:8080").rstrip("/")
OIDC_SCOPES = "openid email profile"
OIDC_ENABLED = bool(OIDC_ISSUER and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET)

if not OIDC_ENABLED:
    log.warning(
        "OIDC is NOT configured — auth gate disabled, app is open. "
        "Set OIDC_ISSUER / OIDC_CLIENT_ID / OIDC_CLIENT_SECRET to enable."
    )

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = APP_BASE_URL.startswith("https://")
app.config["SESSION_COOKIE_HTTPONLY"] = True

oauth = OAuth(app)
if OIDC_ENABLED:
    oauth.register(
        name="okta",
        client_id=OIDC_CLIENT_ID,
        client_secret=OIDC_CLIENT_SECRET,
        server_metadata_url=f"{OIDC_ISSUER}/.well-known/openid-configuration",
        client_kwargs={"scope": OIDC_SCOPES, "code_challenge_method": "S256"},
    )

PUBLIC_PATHS = {
    "/health",
    "/login",
    "/oidc/login",
    "/oidc/callback",
    "/logout",
    "/favicon.ico",
}


@app.before_request
def _auth_gate():
    if not OIDC_ENABLED:
        return
    if request.path.startswith("/static/") or request.path in PUBLIC_PATHS:
        return
    if not session.get("user"):
        if request.path.startswith("/api/"):
            return jsonify(error="unauthorized — session expired"), 401
        return redirect(url_for("login", next=request.path))


register_howto(app, tool_name="Okta Change Auditor")


@app.route("/")
def index():
    return render_template("index.html", version=APP_VERSION, user=session.get("user"))


@app.route("/health")
def health():
    return jsonify(status="ok", version=APP_VERSION), 200


LOGIN_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Okta Change Auditor — Sign in</title>
<style>
 body{margin:0;background:#0f172a;color:#e2e8f0;font:14px -apple-system,Segoe UI,Roboto,sans-serif;display:grid;place-items:center;min-height:100vh}
 .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:40px;max-width:420px;width:90%;text-align:center}
 h1{margin:0 0 8px;font-size:20px}
 p{color:#94a3b8;margin:0 0 28px;font-size:13px}
 a.btn{display:inline-block;background:#22c55e;color:#0f172a;text-decoration:none;padding:10px 22px;border-radius:8px;font-weight:600}
 a.btn:hover{background:#16a34a;color:#fff}
 .err{color:#fca5a5;font-size:12px;margin-top:16px}
 .vpn{background:#1f2937;border:1px solid #f59e0b;color:#fbbf24;font-size:13px;margin-top:20px;padding:12px 14px;border-radius:8px;text-align:left;line-height:1.5}
 .vpn b{color:#fde68a}
 .vpn .raw{display:block;color:#94a3b8;font-size:11px;margin-top:8px;font-family:ui-monospace,Menlo,monospace;word-break:break-word}
</style></head><body><div class="card">
<h1>Okta Change Auditor</h1>
<p>Sign in with your work email to continue.</p>
<a class="btn" href="/oidc/login">Sign in</a>
{% if error %}
  {% if 'access_denied' in error %}
  <div class="vpn">
    <b></b> This app is restricted to the internal network. Connect to the VPN client, then click Sign in again.
    <span class="raw">{{ error }}</span>
  </div>
  {% else %}
  <div class="err">{{ error }}</div>
  {% endif %}
{% endif %}
</div></body></html>
"""


@app.get("/login")
def login():
    if session.get("user"):
        return redirect(url_for("index"))
    nxt = request.args.get("next")
    if nxt:
        session["post_login_redirect"] = nxt
    err = session.pop("login_error", None)
    return render_template_string(LOGIN_HTML, error=err)


@app.get("/oidc/login")
def oidc_login():
    if not OIDC_ENABLED:
        session["login_error"] = "OIDC not configured"
        return redirect(url_for("login"))
    redirect_uri = url_for("oidc_callback", _external=True)
    return oauth.okta.authorize_redirect(redirect_uri)


@app.get("/oidc/callback")
def oidc_callback():
    if request.args.get("error"):
        session["login_error"] = f"{request.args.get('error')}: {request.args.get('error_description', '')}"
        return redirect(url_for("login"))
    try:
        token = oauth.okta.authorize_access_token()
    except Exception as e:
        session["login_error"] = f"token exchange failed: {e}"
        return redirect(url_for("login"))

    claims = token.get("userinfo") or {}
    session["user"] = {
        "email": claims.get("email") or claims.get("preferred_username"),
        "name": claims.get("name"),
        "login_time": datetime.now(timezone.utc).isoformat(),
    }
    dest = session.pop("post_login_redirect", None) or url_for("index")
    return redirect(dest)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/envs")
def api_envs():
    return jsonify({env: bool(get_token(env)) for env in OKTA_URLS})


def _parse_iso_arg(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@app.route("/api/changes")
def api_changes():
    env = request.args.get("env", "dev")
    if env not in OKTA_URLS:
        return jsonify(error=f"unknown env: {env}"), 400

    try:
        limit = int(request.args.get("limit", str(DEFAULT_CHANGE_LIMIT)))
    except ValueError:
        return jsonify(error="limit must be an integer"), 400
    limit = max(1, min(limit, MAX_CHANGE_LIMIT))

    since_arg = request.args.get("since")
    until_arg = request.args.get("until")
    if since_arg or until_arg:
        if not (since_arg and until_arg):
            return jsonify(error="since and until must be supplied together"), 400
        try:
            since = _parse_iso_arg(since_arg)
            until = _parse_iso_arg(until_arg)
        except ValueError:
            return jsonify(error="since/until must be ISO-8601"), 400
        if since >= until:
            return jsonify(error="since must be earlier than until"), 400
    else:
        try:
            hours = int(request.args.get("hours", "24"))
        except ValueError:
            return jsonify(error="hours must be an integer"), 400
        until = datetime.now(timezone.utc)
        since = until - timedelta(hours=hours)

    if not get_token(env):
        return jsonify(error=f"no API token configured for {env}"), 401

    hide_arg = request.args.get("hide")
    if hide_arg is None:
        hide_flags = DEFAULT_HIDE_FLAGS
    elif hide_arg == "":
        hide_flags = frozenset()
    else:
        requested = {p.strip() for p in hide_arg.split(",") if p.strip()}
        unknown = requested - KNOWN_FLAGS
        if unknown:
            return jsonify(error=f"unknown hide flags: {sorted(unknown)}; known: {sorted(KNOWN_FLAGS)}"), 400
        hide_flags = frozenset(requested)

    try:
        result = _fetch_changes(env, since, until, limit=limit, hide_flags=hide_flags)
    except Exception as e:
        log.exception("change fetch failed for %s", env)
        return jsonify(error=str(e)), 500

    return jsonify(
        env=env,
        since=_iso_z(since),
        until=_iso_z(until),
        limit=limit,
        hide=sorted(hide_flags),
        rows=result["rows"],
        filtered=result["filtered"],
        truncated=result["truncated"],
        scanned=result.get("scanned", 0),
    ), 200


@app.route("/api/flags")
def api_flags():
    return jsonify({"flags": FLAG_DEFINITIONS})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=False)
