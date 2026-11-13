from datetime import datetime, timezone

import pytest

import app as auditor


class FakeResponse:
    def __init__(self, status=200, payload=None, headers=None, text=""):
        self.status_code = status
        self._payload = payload if payload is not None else []
        self.headers = headers or {}
        self.text = text

    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        return self._payload


class FakeSession:
    """Returns queued responses in order and records the calls."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, params, headers))
        return self.responses.pop(0)


def event(published="2025-01-01T10:00:00.000Z", event_type="policy.rule.update", **kw):
    base = {
        "published": published,
        "eventType": event_type,
        "actor": {"alternateId": "admin@example.test", "type": "User"},
        "client": {"userAgent": {"rawUserAgent": "Mozilla/5.0"}, "ipAddress": "192.0.2.1"},
        "target": [{"type": "Policy", "displayName": "Rule A"}],
        "outcome": {"result": "SUCCESS"},
    }
    base.update(kw)
    return base


def test_flags_for_browser_admin_are_all_false():
    assert auditor._event_flags(event()) == {
        "automated": False,
        "system": False,
        "membership": False,
        "lifecycle_ops": False,
    }


def test_flags_automated_system_membership_lifecycle():
    script = event(client={"userAgent": {"rawUserAgent": "python-requests/2.0"}, "ipAddress": "x"})
    assert auditor._event_flags(script)["automated"]
    assert auditor._event_flags(event(client={}))["automated"]
    system = event(actor={"alternateId": "SYSTEM@okta.com", "type": "User"})
    assert auditor._event_flags(system)["system"]
    assert auditor._event_flags(event(actor={"type": "SystemPrincipal"}))["system"]
    assert auditor._event_flags(event(event_type="group.user_membership.add"))["membership"]
    assert auditor._event_flags(event(event_type="user.lifecycle.create"))["lifecycle_ops"]


def test_okta_filter_respects_hide_flags():
    everything = auditor._build_okta_filter(frozenset())
    assert 'eventType sw "group.user_membership."' in everything
    assert "rawUserAgent" not in everything

    hidden = auditor._build_okta_filter(auditor.DEFAULT_HIDE_FLAGS)
    assert 'eventType sw "group.user_membership."' not in hidden
    assert 'eventType sw "user.lifecycle."' not in hidden
    assert 'actor.alternateId ne "system@okta.com"' in hidden
    assert "client.userAgent.rawUserAgent pr" in hidden


def test_collapse_bursts_groups_same_actor_and_type_within_window():
    rows = [
        auditor._project_change_event(event(published=f"2025-01-01T10:00:{s:02d}.000Z"))
        for s in (50, 30, 10)
    ]
    other = auditor._project_change_event(event(published="2025-01-01T09:00:00.000Z"))
    grouped = auditor._collapse_bursts(rows + [other])
    assert [g.get("count", 1) for g in grouped] == [3, 1]
    assert grouped[0]["outcome"] == "SUCCESS"


def test_collapse_bursts_splits_on_gap_or_actor():
    a = auditor._project_change_event(event(published="2025-01-01T10:05:00.000Z"))
    b = auditor._project_change_event(event(published="2025-01-01T10:00:00.000Z"))
    assert len(auditor._collapse_bursts([a, b])) == 2


def test_next_link_parsing():
    header = '<https://x.test/a>; rel="self", <https://x.test/b?after=1>; rel="next"'
    assert auditor._next_link(header) == "https://x.test/b?after=1"
    assert auditor._next_link('<https://x.test/a>; rel="self"') is None
    assert auditor._next_link(None) is None


def test_429_retries_then_returns(monkeypatch):
    sleeps = []
    monkeypatch.setattr(auditor.time, "sleep", sleeps.append)
    fake = FakeSession(
        [FakeResponse(429, headers={"Retry-After": "2"}), FakeResponse(200, [event()])]
    )
    response = auditor._okta_get_with_retry(fake, "https://x.test", None, {}, "alpha")
    assert response.status_code == 200
    assert sleeps == [2.0]


def test_429_gives_up_after_max_retries(monkeypatch):
    monkeypatch.setattr(auditor.time, "sleep", lambda s: None)
    fake = FakeSession([FakeResponse(429)] * (auditor.OKTA_429_MAX_RETRIES + 1))
    assert (
        auditor._okta_get_with_retry(fake, "https://x.test", None, {}, "alpha").status_code == 429
    )


def fetch(monkeypatch, responses, **kw):
    fake = FakeSession(responses)
    monkeypatch.setattr(auditor, "_session", fake)
    since = datetime(2025, 1, 1, tzinfo=timezone.utc)
    until = datetime(2025, 1, 2, tzinfo=timezone.utc)
    return auditor._fetch_changes("alpha", since, until, **kw), fake


def test_fetch_changes_paginates_and_counts_filtered(monkeypatch):
    page1 = FakeResponse(
        200,
        [event(), event(actor={"type": "SystemPrincipal"}, published="2025-01-01T09:00:00.000Z")],
        headers={"Link": '<https://alpha.example.test/api/v1/logs?after=2>; rel="next"'},
    )
    page2 = FakeResponse(200, [event(published="2025-01-01T08:00:00.000Z", event_type="iam.x")])
    result, fake = fetch(monkeypatch, [page1, page2], hide_flags=frozenset({"system"}))
    assert result["scanned"] == 3
    assert result["filtered"] == {"system": 1}
    assert len(result["rows"]) == 2
    assert fake.calls[0][2]["Authorization"] == "SSWS test-key-not-real"
    assert fake.calls[1][1] is None  # the next-link URL carries its own query


@pytest.mark.parametrize(
    "response, expected",
    [
        (FakeResponse(401), "401"),
        (FakeResponse(500, text="boom"), "HTTP 500 boom"),
        (FakeResponse(200, {"not": "a list"}), "unexpected payload"),
    ],
)
def test_fetch_changes_http_errors_are_reported_as_such(monkeypatch, response, expected):
    with pytest.raises(RuntimeError, match=expected):
        fetch(monkeypatch, [response])


def test_fetch_changes_requires_token(monkeypatch):
    since = datetime(2025, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(RuntimeError, match="no API token"):
        auditor._fetch_changes("beta", since, since)


def test_count_logs_failed_request(monkeypatch, caplog):
    monkeypatch.setattr(auditor, "_session", FakeSession([FakeResponse(500, text="boom")]))
    since = datetime(2025, 1, 1, tzinfo=timezone.utc)
    with caplog.at_level("WARNING"):
        n = auditor._count_okta_events_by_prefix("alpha", since, since, ("iam.",))
    assert n == 0
    assert "HTTP 500" in caplog.text
