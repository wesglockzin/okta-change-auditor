import pytest

from config import (
    ConfigError,
    is_user_allowed,
    load_auth,
    parse_orgs,
    safe_next,
    token_var,
)

OIDC_ENV = {
    "FLASK_SECRET_KEY": "test-key-not-real",
    "OIDC_ISSUER": "https://idp.example.test/",
    "OIDC_CLIENT_ID": "client",
    "OIDC_CLIENT_SECRET": "test-key-not-real",
    "OIDC_ALLOWED_DOMAINS": "Example.test",
}


def test_parse_orgs_any_length():
    orgs = parse_orgs("a=https://a.test/, b-2=http://b.test ,c=https://c.test")
    assert list(orgs) == ["a", "b-2", "c"]
    assert orgs["a"] == "https://a.test"


@pytest.mark.parametrize("raw", ["", "a", "a=ftp://x", "a=https://x,a=https://y"])
def test_parse_orgs_rejects_bad_input(raw):
    with pytest.raises(ConfigError):
        parse_orgs(raw)


def test_token_var():
    assert token_var("prod") == "OKTA_AUDITOR_PROD_API_TOKEN"
    assert token_var("eu-west") == "OKTA_AUDITOR_EU_WEST_API_TOKEN"


def test_auth_refuses_to_start_without_settings():
    with pytest.raises(ConfigError, match="FLASK_SECRET_KEY"):
        load_auth({}, "random")


@pytest.mark.parametrize("missing", ["OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"])
def test_auth_names_missing_setting(missing):
    env = {k: v for k, v in OIDC_ENV.items() if k != missing}
    with pytest.raises(ConfigError, match=missing):
        load_auth(env, "random")


def test_auth_requires_allow_list():
    env = {k: v for k, v in OIDC_ENV.items() if k != "OIDC_ALLOWED_DOMAINS"}
    with pytest.raises(ConfigError, match="OIDC_ALLOWED"):
        load_auth(env, "random")


def test_auth_none_is_explicit_opt_out():
    auth = load_auth({"AUTH_MODE": "none"}, "random")
    assert not auth.oidc
    assert auth.secret_key == "random"


def test_auth_rejects_unknown_mode():
    with pytest.raises(ConfigError, match="AUTH_MODE"):
        load_auth({"AUTH_MODE": "off"}, "random")


def test_allow_list():
    auth = load_auth({**OIDC_ENV, "OIDC_ALLOWED_EMAILS": "Boss@other.test"}, "random")
    assert is_user_allowed("someone@example.test", auth)
    assert is_user_allowed("boss@other.test", auth)
    assert not is_user_allowed("someone@other.test", auth)
    assert not is_user_allowed("x@evil.example.test", auth)
    assert not is_user_allowed(None, auth)


@pytest.mark.parametrize("target", ["//evil.test", "/\\evil.test", "https://evil.test", "evil", "", None])
def test_safe_next_rejects(target):
    assert safe_next(target) is None


def test_safe_next_accepts_relative_path():
    assert safe_next("/howto") == "/howto"
    assert safe_next("/api/changes?env=alpha") == "/api/changes?env=alpha"
