"""Public investigation viewer ("协查页") — runs on its own port.

Deliberately tiny: it shares the collector's database file but exposes **only**

* ``GET  /i/{link_id}``          — claim page (HTML)
* ``GET  /i/{link_id}/state``    — whether this browser has an active claim
* ``POST /i/{link_id}/claim``    — claim the link (exactly one winner)
* ``GET  /i/{link_id}/view``     — the selected service's span name/duration/status
* ``GET  /healthz``              — liveness

No OTLP intake, no trace listing, no raw span body and no other services are
reachable from this app.  It is intended to be published on a separate port
while the collector stays internal.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

from . import __version__
from .config import Settings
from .incidents import IncidentStore, LinkError
from .store import SqliteStore

STATIC_DIR = Path(__file__).parent / "static"

# Cookie name per link (httponly, path=/i/, SameSite=Lax).  Per-link naming
# means claiming one link never clobbers a claim on another in the same
# browser.
COOKIE_PREFIX = "incident_claim_"

_NO_STORE = {"Cache-Control": "no-store, max-age=0"}


def _error(exc: LinkError) -> JSONResponse:
    return JSONResponse({"error": str(exc)}, status_code=exc.status_code, headers=_NO_STORE)


def _cookie_name(link_id: str) -> str:
    digest = hashlib.sha256(link_id.encode("utf-8")).hexdigest()[:16]
    return COOKIE_PREFIX + digest


def _cookie_token(request: Request, link_id: str) -> str | None:
    return request.cookies.get(_cookie_name(link_id)) or None


def _cookie_set(response: Response, link_id: str, token: str, ttl: float) -> None:
    # A small grace period beyond the server-side expiry means the browser
    # cookie is never the limiting factor (client clock skew cannot revoke
    # early); the server still refuses data the moment the link expires.
    response.set_cookie(
        _cookie_name(link_id),
        token,
        max_age=max(1, int(ttl) + 300),
        path="/i/",
        httponly=True,
        samesite="lax",
    )


def create_incident_app(
    settings: Settings | None = None,
    *,
    store: SqliteStore | None = None,
    incidents: IncidentStore | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    store = store or SqliteStore(settings)
    store.init_schema()
    incidents = incidents or IncidentStore(settings)
    incidents.init_schema()

    app = FastAPI(title="Incident Investigation Viewer", version=__version__)
    app.state.settings = settings
    app.state.store = store
    app.state.incidents = incidents

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    def page(name: str) -> HTMLResponse:
        return HTMLResponse(
            (STATIC_DIR / name).read_text(encoding="utf-8"), headers=_NO_STORE
        )

    @app.get("/i/{link_id}", response_class=HTMLResponse)
    async def claim_page(link_id: str) -> HTMLResponse:
        return page("incident.html")

    @app.get("/i/{link_id}/state")
    async def link_state(link_id: str, request: Request) -> Response:
        now = settings.clock()
        described = incidents.describe(link_id, now)
        if described is None:
            return JSONResponse(
                {"error": "link not found"}, status_code=404, headers=_NO_STORE
            )
        token = _cookie_token(request, link_id)
        claimed_by_this_browser = False
        if token is not None:
            try:
                incidents.verify_token(link_id, token, now)
                claimed_by_this_browser = True
            except LinkError:
                claimed_by_this_browser = False
        payload: dict[str, Any] = {
            **described,
            "claimed_by_this_browser": claimed_by_this_browser,
            "server_now": now,
        }
        # A browser that has not claimed this link learns nothing about the
        # trace it points at.
        if not claimed_by_this_browser:
            payload.pop("trace_id")
        return JSONResponse(payload, headers=_NO_STORE)

    @app.post("/i/{link_id}/claim")
    async def claim(link_id: str, request: Request) -> Response:
        try:
            body = await request.json()
        except Exception:
            body = {}
        nonce = str(body.get("nonce", "")).strip() if isinstance(body, dict) else ""
        if not nonce:
            return JSONResponse(
                {"error": "nonce is required"}, status_code=400, headers=_NO_STORE
            )
        now = settings.clock()
        try:
            result = incidents.claim(link_id, nonce, now)
        except LinkError as exc:
            return _error(exc)
        described = incidents.describe(link_id, now)
        assert described is not None
        response = JSONResponse(
            {
                "ok": True,
                "link_id": link_id,
                "already_claimed": result.already_claimed,
                "claimed_at": result.claimed_at,
                "expires_at": described["expires_at"],
            },
            headers=_NO_STORE,
        )
        _cookie_set(response, link_id, result.token, described["expires_at"] - now)
        return response

    @app.get("/i/{link_id}/view")
    async def view(link_id: str, request: Request) -> Response:
        now = settings.clock()
        token = _cookie_token(request, link_id)
        if token is None:
            return JSONResponse(
                {"error": "claim this link first"}, status_code=401, headers=_NO_STORE
            )
        try:
            incidents.verify_token(link_id, token, now)
        except LinkError as exc:
            return _error(exc)
        described = incidents.describe(link_id, now)
        if described is None:
            return JSONResponse(
                {"error": "link not found"}, status_code=404, headers=_NO_STORE
            )
        # Re-check after verification so a revoke/expiry racing with the two
        # reads still refuses the data.
        if described["status"] != "claimed":
            return JSONResponse(
                {"error": f"link is {described['status']}"},
                status_code=410,
                headers=_NO_STORE,
            )
        spans = store.retained_service_spans(
            described["trace_id"], described["service"]
        )
        if spans is None:
            return JSONResponse(
                {"error": "trace is no longer retained"},
                status_code=410,
                headers=_NO_STORE,
            )
        # Re-verify after reading the data: a revoke/expiry that commits while
        # we fetch still means this response must not be handed out.
        try:
            incidents.verify_token(link_id, token, settings.clock())
        except LinkError as exc:
            return _error(exc)
        return JSONResponse(
            {
                "service": described["service"],
                "expires_at": described["expires_at"],
                "spans": spans,
            },
            headers=_NO_STORE,
        )

    @app.get("/", response_class=HTMLResponse)
    async def root() -> HTMLResponse:
        return HTMLResponse(
            "<h1>协查入口</h1><p>请使用值班员发出的协查链接（/i/&lt;id&gt;）。</p>",
            headers=_NO_STORE,
        )

    return app


app = create_incident_app()
