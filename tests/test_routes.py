import pytest

import app as auditor


@pytest.fixture
def client():
    return auditor.app.test_client()


def test_health_is_ok_without_calling_out(client, monkeypatch):
    monkeypatch.setattr(auditor, "_session", None)  # any Okta call would fail
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["status"] == "ok"


def test_envs_come_from_settings(client):
    assert client.get("/api/envs").json == {"alpha": True, "beta": False}


def test_index_renders_buttons_from_settings(client):
    html = client.get("/").get_data(as_text=True)
    assert 'data-env="alpha"' in html
    assert 'data-env="beta"' in html
    assert 'data-env="dev"' not in html
    assert 'let currentEnv = "alpha";' in html


def test_unknown_env_and_bad_hours(client):
    assert client.get("/api/changes?env=nope").status_code == 400
    assert client.get("/api/changes?env=alpha&hours=-5").status_code == 400
    assert client.get("/api/changes?env=alpha&hours=abc").status_code == 400
    assert client.get("/api/changes?env=alpha&hide=bogus").status_code == 400


def test_missing_token_is_401(client):
    assert client.get("/api/changes?env=beta").status_code == 401


def test_fetch_error_does_not_leak_text(client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("secret detail SSWS abc")

    monkeypatch.setattr(auditor, "_fetch_changes", boom)
    response = client.get("/api/changes?env=alpha")
    assert response.status_code == 502
    assert "secret" not in response.get_data(as_text=True)


def test_login_stores_only_safe_next(client):
    client.get("/login?next=//evil.test")
    with client.session_transaction() as sess:
        assert "post_login_redirect" not in sess
    client.get("/login?next=/howto")
    with client.session_transaction() as sess:
        assert sess["post_login_redirect"] == "/howto"


def test_auth_gate_blocks_when_oidc_enabled(client, monkeypatch):
    monkeypatch.setattr(auditor, "OIDC_ENABLED", True)
    assert client.get("/api/envs").status_code == 401
    assert client.get("/health").status_code == 200
    redirect = client.get("/")
    assert redirect.status_code == 302
    assert "/login" in redirect.headers["Location"]
