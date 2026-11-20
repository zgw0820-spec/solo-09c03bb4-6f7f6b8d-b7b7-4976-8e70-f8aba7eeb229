"""End-to-end tests for investigation links (协查链接).

The duty console and the public viewer are two separate FastAPI apps that
share one SQLite file, exactly like the two Compose services.  Separate
``TestClient`` instances play separate browsers, so cookie-based claims are
isolated just like real clients.
"""

from __future__ import annotations

import json
import threading

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.incident_app import create_incident_app
from app.main import create_app


class Clock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start
        self.lock = threading.Lock()

    def __call__(self) -> float:
        with self.lock:
            return self.now

    def advance(self, seconds: float) -> None:
        with self.lock:
            self.now += seconds


@pytest.fixture()
def clock() -> Clock:
    return Clock()


def make_settings(tmp_path, clock, **overrides) -> Settings:
    values = dict(
        db_path=str(tmp_path / "collector.db"),
        window_seconds=5.0,
        max_active_traces=8,
        slow_root_ms=500.0,
        sweep_interval_seconds=0.05,
        incident_ttl_seconds=15 * 60,
        incident_public_base_url="http://viewer.test:8080",
        clock=clock,
    )
    values.update(overrides)
    return Settings(**values)


def tid(n: int) -> str:
    return f"{n:032x}"


def sid(n: int) -> str:
    return f"{n:016x}"


def span(
    trace_id: str,
    span_id: str,
    *,
    parent: str | None = None,
    name: str = "op",
    duration_ms: float = 10.0,
    error: bool = False,
) -> dict:
    start = 1_700_000_000_000_000_000
    end = start + int(duration_ms * 1_000_000)
    raw = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": 2,
        "startTimeUnixNano": str(start),
        "endTimeUnixNano": str(end),
        "status": {"code": 2 if error else 0},
    }
    if parent:
        raw["parentSpanId"] = parent
    return raw


def otlp(*spans: dict, service: str) -> dict:
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": service}}
                    ]
                },
                "scopeSpans": [{"scope": {"name": "test"}, "spans": list(spans)}],
            }
        ]
    }


def post_otlp(client: TestClient, payload: dict) -> None:
    response = client.post(
        "/v1/traces",
        content=json.dumps(payload),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 200, response.text


class Stack:
    """The two apps sharing one DB, plus helpers to act as fresh browsers."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.duty = TestClient(create_app(settings))
        self.viewer = TestClient(create_incident_app(settings))
        self.duty.__enter__()
        self.viewer.__enter__()

    def close(self) -> None:
        self.viewer.__exit__(None, None, None)
        self.duty.__exit__(None, None, None)

    def new_browser(self) -> TestClient:
        """A separate cookie jar, i.e. a separate browser."""
        return TestClient(create_incident_app(self.settings))


@pytest.fixture()
def stack(tmp_path, clock):
    s = Stack(make_settings(tmp_path, clock))
    yield s
    s.close()


def make_kept_trace(client: TestClient, clock: Clock, trace_id: str) -> None:
    """Two services, both retained: checkout-api root + inventory-svc child."""
    post_otlp(client, otlp(span(trace_id, sid(1), name="POST /checkout"), service="checkout-api"))
    post_otlp(
        client,
        otlp(
            span(trace_id, sid(2), parent=sid(1), name="inventory.reserve", error=True),
            service="inventory-svc",
        ),
    )
    clock.advance(5.0)
    assert client.get(f"/api/traces/{trace_id}").json()["state"] == "kept"


def create_link(duty: TestClient, trace_id: str, service: str) -> dict:
    response = duty.post(
        "/api/incidents/links", json={"trace_id": trace_id, "service": service}
    )
    assert response.status_code == 200, response.text
    return response.json()


# --------------------------------------------------------------------------
# issuing links
# --------------------------------------------------------------------------


def test_only_kept_traces_and_real_services_can_be_shared(stack, clock):
    trace_id = tid(1)
    post_otlp(stack.duty, otlp(span(trace_id, sid(1)), service="checkout-api"))
    # still collecting
    response = stack.duty.post(
        "/api/incidents/links", json={"trace_id": trace_id, "service": "checkout-api"}
    )
    assert response.status_code == 409

    clock.advance(5.0)  # clean -> dropped
    response = stack.duty.post(
        "/api/incidents/links", json={"trace_id": trace_id, "service": "checkout-api"}
    )
    assert response.status_code == 409

    unknown = stack.duty.post(
        "/api/incidents/links", json={"trace_id": tid(999), "service": "x"}
    )
    assert unknown.status_code == 404


def test_link_binds_one_existing_service_and_fixed_expiry(stack, clock):
    trace_id = tid(2)
    make_kept_trace(stack.duty, clock, trace_id)
    link = create_link(stack.duty, trace_id, "inventory-svc")
    assert link["service"] == "inventory-svc"
    assert link["expires_at"] == pytest.approx(clock.now + 15 * 60)
    assert link["url"] == f"http://viewer.test:8080/i/{link['link_id']}"

    bad_service = stack.duty.post(
        "/api/incidents/links", json={"trace_id": trace_id, "service": "no-such-svc"}
    )
    assert bad_service.status_code == 404


# --------------------------------------------------------------------------
# claim page + single winner
# --------------------------------------------------------------------------


def test_opening_link_shows_claim_page_without_data(stack, clock):
    trace_id = tid(3)
    make_kept_trace(stack.duty, clock, trace_id)
    link = create_link(stack.duty, trace_id, "inventory-svc")

    browser = stack.new_browser()
    page = browser.get(f"/i/{link['link_id']}")
    assert page.status_code == 200
    assert "确认领取" in page.text

    state = browser.get(f"/i/{link['link_id']}/state")
    assert state.status_code == 200
    body = state.json()
    assert body["status"] == "open"
    assert body["can_claim"] is True
    assert body["claimed_by_this_browser"] is False
    assert "trace_id" not in body  # unclaimed browsers learn nothing
    assert "spans" not in body

    early = browser.get(f"/i/{link['link_id']}/view")
    assert early.status_code == 401


def test_claim_then_view_only_selected_service(stack, clock):
    trace_id = tid(4)
    make_kept_trace(stack.duty, clock, trace_id)
    link = create_link(stack.duty, trace_id, "inventory-svc")

    browser = stack.new_browser()
    claim = browser.post(f"/i/{link['link_id']}/claim", json={"nonce": "n-browser-a"})
    assert claim.status_code == 200, claim.text
    assert claim.json()["already_claimed"] is False

    view = browser.get(f"/i/{link['link_id']}/view")
    assert view.status_code == 200
    data = view.json()
    assert data["service"] == "inventory-svc"
    assert data["spans"] == [
        {"name": "inventory.reserve", "duration_ms": 10.0, "status": "ERROR"}
    ]
    # No span ids, no attributes, no raw body, no other service.
    assert set(data["spans"][0]) == {"name", "duration_ms", "status"}
    assert "checkout" not in json.dumps(data)

    # Claimed browser can view repeatedly.
    for _ in range(3):
        assert browser.get(f"/i/{link['link_id']}/view").status_code == 200


def test_two_browsers_claiming_concurrently_only_one_wins(stack, clock):
    trace_id = tid(5)
    make_kept_trace(stack.duty, clock, trace_id)
    link = create_link(stack.duty, trace_id, "checkout-api")
    link_id = link["link_id"]

    browsers = [stack.new_browser() for _ in range(2)]
    barrier = threading.Barrier(len(browsers))
    results: list[tuple[int, TestClient]] = []
    lock = threading.Lock()

    def attempt(browser: TestClient, nonce: str) -> None:
        barrier.wait()
        response = browser.post(f"/i/{link_id}/claim", json={"nonce": nonce})
        with lock:
            results.append((response.status_code, browser))

    threads = [
        threading.Thread(target=attempt, args=(b, f"nonce-{i}"))
        for i, b in enumerate(browsers)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(code for code, _ in results) == [200, 409]
    winner = next(b for code, b in results if code == 200)
    loser = next(b for code, b in results if code == 409)
    assert winner.get(f"/i/{link_id}/view").status_code == 200
    assert loser.get(f"/i/{link_id}/view").status_code == 401


def test_claim_retry_after_lost_response_returns_same_token(stack, clock):
    trace_id = tid(6)
    make_kept_trace(stack.duty, clock, trace_id)
    link = create_link(stack.duty, trace_id, "checkout-api")

    browser = stack.new_browser()
    first = browser.post(f"/i/{link['link_id']}/claim", json={"nonce": "same-nonce"})
    assert first.status_code == 200

    # Simulate the response being lost: retry the exact same request.
    retry = browser.post(f"/i/{link['link_id']}/claim", json={"nonce": "same-nonce"})
    assert retry.status_code == 200
    assert retry.json()["already_claimed"] is True
    assert browser.get(f"/i/{link['link_id']}/view").status_code == 200

    # Another browser with a different nonce is still refused.
    other = stack.new_browser()
    assert (
        other.post(f"/i/{link['link_id']}/claim", json={"nonce": "other"}).status_code
        == 409
    )


def test_forged_cookie_is_rejected(stack, clock):
    trace_id = tid(7)
    make_kept_trace(stack.duty, clock, trace_id)
    link = create_link(stack.duty, trace_id, "checkout-api")
    browser = stack.new_browser()
    from app.incident_app import _cookie_name

    browser.cookies.set(_cookie_name(link["link_id"]), "forged", path="/i/")
    assert browser.get(f"/i/{link['link_id']}/view").status_code == 403


def test_same_browser_can_hold_claims_on_two_links(stack, clock):
    trace_id = tid(12)
    make_kept_trace(stack.duty, clock, trace_id)
    one = create_link(stack.duty, trace_id, "checkout-api")
    two = create_link(stack.duty, trace_id, "inventory-svc")
    browser = stack.new_browser()
    assert browser.post(f"/i/{one['link_id']}/claim", json={"nonce": "n1"}).status_code == 200
    assert browser.post(f"/i/{two['link_id']}/claim", json={"nonce": "n2"}).status_code == 200
    assert browser.get(f"/i/{one['link_id']}/view").json()["service"] == "checkout-api"
    assert browser.get(f"/i/{two['link_id']}/view").json()["service"] == "inventory-svc"


# --------------------------------------------------------------------------
# revoke / expiry
# --------------------------------------------------------------------------


def test_revoke_blocks_already_claimed_browser(stack, clock):
    trace_id = tid(8)
    make_kept_trace(stack.duty, clock, trace_id)
    link = create_link(stack.duty, trace_id, "inventory-svc")
    browser = stack.new_browser()
    assert browser.post(f"/i/{link['link_id']}/claim", json={"nonce": "n"}).status_code == 200
    assert browser.get(f"/i/{link['link_id']}/view").status_code == 200

    revoked = stack.duty.post(f"/api/incidents/links/{link['link_id']}/revoke")
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    assert browser.get(f"/i/{link['link_id']}/view").status_code == 410
    assert stack.new_browser().get(f"/i/{link['link_id']}/state").json()["status"] == "revoked"


def test_expiry_blocks_claim_and_claimed_view(stack, clock):
    trace_id = tid(9)
    make_kept_trace(stack.duty, clock, trace_id)
    link = create_link(stack.duty, trace_id, "inventory-svc")
    browser = stack.new_browser()
    assert browser.post(f"/i/{link['link_id']}/claim", json={"nonce": "n"}).status_code == 200

    clock.advance(15 * 60 - 1)
    assert browser.get(f"/i/{link['link_id']}/view").status_code == 200  # still valid

    clock.advance(1)  # exactly at expiry
    assert browser.get(f"/i/{link['link_id']}/view").status_code == 410
    late_browser = stack.new_browser()
    late = late_browser.post(f"/i/{link['link_id']}/claim", json={"nonce": "late"})
    assert late.status_code == 410
    assert late_browser.get(f"/i/{link['link_id']}/state").json()["status"] == "expired"


# --------------------------------------------------------------------------
# restart persistence
# --------------------------------------------------------------------------


def test_link_state_survives_restart(tmp_path, clock):
    settings = make_settings(tmp_path, clock)
    first = Stack(settings)
    trace_id = tid(10)
    make_kept_trace(first.duty, clock, trace_id)
    link = create_link(first.duty, trace_id, "inventory-svc")
    browser = first.new_browser()
    assert browser.post(f"/i/{link['link_id']}/claim", json={"nonce": "n"}).status_code == 200
    first.close()

    clock.advance(60)

    # "Restart": brand-new app instances on the same DB file.
    restarted = Stack(make_settings(tmp_path, clock))
    try:
        # Expiry is still the original issued-at + TTL.
        state = restarted.viewer.get(f"/i/{link['link_id']}/state")
        assert state.status_code == 200
        assert state.json()["expires_at"] == pytest.approx(link["expires_at"])
        assert state.json()["status"] == "claimed"

        # A new browser must not be able to claim it...
        assert (
            restarted.new_browser()
            .post(f"/i/{link['link_id']}/claim", json={"nonce": "new"})
            .status_code
            == 409
        )
        # ...while the original browser's cookie still works.
        assert browser.get(f"/i/{link['link_id']}/view").status_code == 200

        # The claim token re-derives identically across restart, so a retry
        # after a lost response still succeeds.
        retry = browser.post(f"/i/{link['link_id']}/claim", json={"nonce": "n"})
        assert retry.status_code == 200
        assert retry.json()["already_claimed"] is True

        # Revocation persists too.
        assert restarted.duty.post(
            f"/api/incidents/links/{link['link_id']}/revoke"
        ).status_code == 200
    finally:
        restarted.close()

    third = Stack(make_settings(tmp_path, clock))
    try:
        assert third.viewer.get(f"/i/{link['link_id']}/state").json()["status"] == "revoked"
        assert browser.get(f"/i/{link['link_id']}/view").status_code == 410
    finally:
        third.close()


# --------------------------------------------------------------------------
# surface separation
# --------------------------------------------------------------------------


def test_viewer_exposes_no_collector_routes(stack):
    for path in ("/v1/traces", "/api/traces", "/api/config", "/api/stats"):
        assert stack.viewer.get(path).status_code == 404, path
    assert stack.viewer.post("/v1/traces", json={}).status_code == 404


def test_operator_link_listing_shows_state(stack, clock):
    trace_id = tid(11)
    make_kept_trace(stack.duty, clock, trace_id)
    link = create_link(stack.duty, trace_id, "checkout-api")
    listing = stack.duty.get(f"/api/incidents/links?trace_id={trace_id}").json()
    assert [item["link_id"] for item in listing["links"]] == [link["link_id"]]
    assert listing["links"][0]["status"] == "open"
