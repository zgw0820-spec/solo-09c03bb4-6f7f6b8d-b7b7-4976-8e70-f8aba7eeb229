"""Internal (duty-operator) endpoints that manage investigation links.

These routes are added to the collector app only — the public incident viewer
never imports this module, so the ingestion and inspection surfaces stay on
the internal port.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .config import Settings
from .incidents import IncidentStore, LinkError
from .store import SqliteStore, STATE_KEPT


def build_duty_router(
    settings: Settings, store: SqliteStore, incidents: IncidentStore
) -> APIRouter:
    router = APIRouter(prefix="/api/incidents")

    @router.get("/config")
    async def incidents_config() -> dict[str, Any]:
        return {
            "ttl_seconds": settings.incident_ttl_seconds,
            "public_base_url": settings.incident_public_base_url,
        }

    @router.post("/links")
    async def create_link(body: dict[str, Any], request: Request) -> Any:
        trace_id = str(body.get("trace_id", "")).strip().lower()
        service = str(body.get("service", "")).strip()
        if not trace_id or not service:
            return JSONResponse(
                {"error": "trace_id and service are required"}, status_code=400
            )
        now = settings.clock()
        trace = store.settle_and_get(trace_id, now)
        if trace is None:
            return JSONResponse({"error": "trace not found"}, status_code=404)
        if trace["state"] != STATE_KEPT:
            return JSONResponse(
                {"error": "investigation links require a retained trace"},
                status_code=409,
            )
        services = store.retained_services(trace_id, now) or []
        if service not in services:
            return JSONResponse(
                {
                    "error": "service has no retained spans in this trace",
                    "services": services,
                },
                status_code=404,
            )
        link = incidents.create_link(trace_id, service, now)
        link["url"] = (
            f"{settings.incident_public_base_url}/i/{link['link_id']}"
        )
        link["status"] = "open"
        return link

    @router.get("/links")
    async def list_links(trace_id: str) -> Any:
        return {
            "links": incidents.list_links(trace_id.strip().lower(), settings.clock())
        }

    @router.get("/links/{link_id}")
    async def get_link(link_id: str) -> Any:
        described = incidents.describe(link_id.strip(), settings.clock())
        if described is None:
            return JSONResponse({"error": "link not found"}, status_code=404)
        described["url"] = f"{settings.incident_public_base_url}/i/{link_id}"
        return described

    @router.post("/links/{link_id}/revoke")
    async def revoke_link(link_id: str) -> Any:
        try:
            described = incidents.revoke(link_id.strip(), settings.clock())
        except LinkError as exc:
            return JSONResponse({"error": str(exc)}, status_code=exc.status_code)
        described["url"] = f"{settings.incident_public_base_url}/i/{link_id}"
        return described

    return router
