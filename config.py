"""Settings parsing and startup validation. No Flask import, so it is easy to test."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass


class ConfigError(RuntimeError):
    """A required setting is missing or invalid. The message names the setting."""


def parse_orgs(raw: str) -> dict[str, str]:
    """Parse ``name=url,name=url`` into an ordered dict of any length."""
    orgs: dict[str, str] = {}
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        name, sep, url = part.partition("=")
        name, url = name.strip(), url.strip().rstrip("/")
        if not sep or not name or not url.startswith(("https://", "http://")):
            raise ConfigError(f"OKTA_ORGS: entry {part!r} must look like name=https://host")
        if name in orgs:
            raise ConfigError(f"OKTA_ORGS: duplicate org name {name!r}")
        orgs[name] = url
    if not orgs:
        raise ConfigError("OKTA_ORGS is required (for example: name=https://your-org.okta.com)")
    return orgs


def token_var(org: str) -> str:
    """Environment variable (and keyring key) that holds the API token for an org."""
    return "OKTA_AUDITOR_" + re.sub(r"[^A-Za-z0-9]+", "_", org).upper() + "_API_TOKEN"


def csv_set(raw: str | None) -> frozenset[str]:
    return frozenset(p.strip().lower() for p in (raw or "").split(",") if p.strip())


def env_int(env: Mapping[str, str], name: str, default: int, minimum: int = 0) -> int:
    raw = env.get(name)
    if raw in (None, ""):
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer") from None
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    return value


@dataclass(frozen=True)
class AuthSettings:
    mode: str
    secret_key: str
    issuer: str = ""
    client_id: str = ""
    client_secret: str = ""
    allowed_emails: frozenset[str] = frozenset()
    allowed_domains: frozenset[str] = frozenset()

    @property
    def oidc(self) -> bool:
        return self.mode == "oidc"


def load_auth(env: Mapping[str, str], random_key: str) -> AuthSettings:
    """Fail closed: refuse to start without auth unless AUTH_MODE=none is explicit."""
    mode = (env.get("AUTH_MODE") or "oidc").strip().lower()
    if mode not in {"oidc", "none"}:
        raise ConfigError("AUTH_MODE must be 'oidc' or 'none'")
    if mode == "none":
        return AuthSettings(mode="none", secret_key=env.get("FLASK_SECRET_KEY") or random_key)

    for name in ("FLASK_SECRET_KEY", "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"):
        if not env.get(name):
            raise ConfigError(f"{name} is required (or set AUTH_MODE=none to run without sign-in)")
    emails = csv_set(env.get("OIDC_ALLOWED_EMAILS"))
    domains = csv_set(env.get("OIDC_ALLOWED_DOMAINS"))
    if not emails and not domains:
        raise ConfigError("OIDC_ALLOWED_EMAILS or OIDC_ALLOWED_DOMAINS is required")
    return AuthSettings(
        mode="oidc",
        secret_key=env["FLASK_SECRET_KEY"],
        issuer=env["OIDC_ISSUER"].rstrip("/"),
        client_id=env["OIDC_CLIENT_ID"],
        client_secret=env["OIDC_CLIENT_SECRET"],
        allowed_emails=emails,
        allowed_domains=domains,
    )


def is_user_allowed(email: str | None, auth: AuthSettings) -> bool:
    if not email:
        return False
    email = email.strip().lower()
    if email in auth.allowed_emails:
        return True
    return "@" in email and email.rsplit("@", 1)[1] in auth.allowed_domains


def safe_next(target: str | None) -> str | None:
    """Accept only a same-site relative path. ``//host`` and schemes are rejected."""
    if not target or not target.startswith("/") or target.startswith(("//", "/\\")):
        return None
    if "\\" in target or any(ord(c) < 32 for c in target):
        return None
    return target
