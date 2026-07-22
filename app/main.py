from contextlib import asynccontextmanager
from datetime import datetime, timezone
import secrets
import socket

from fastapi import FastAPI, Form, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, text

from app.config import settings
from app.db import Base, SessionLocal, engine
from app.models import SecurityEvent, Source
from app.runtime_config import (
    add_collector,
    delete_collector,
    get_runtime_config,
    rotate_ingest_token,
    update_collector,
    update_runtime_config,
)
from app.schemas import CrowdSecWebhook, EventIn
from app.services import create_event, crowdsec_payload_to_events, dashboard_stats


def sync_configured_sources() -> None:
    config = get_runtime_config()
    if not config["setup_complete"]:
        return
    configured = [(config["firewall_name"], "crowdsec-firewall")]
    if config["server_enabled"]:
        configured.append((config["server_name"], "crowdsec-server"))
    for collector in config.get("collectors", []):
        if collector.get("enabled"):
            configured.append((collector.get("name", "Collector"), f"collector-{collector.get('type', 'generic')}"))
    with SessionLocal() as db:
        for name, kind in configured:
            if db.scalar(select(Source).where(Source.name == name)) is None:
                db.add(Source(name=name, kind=kind))
        db.commit()


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    get_runtime_config()
    sync_configured_sources()
    yield


app = FastAPI(title=settings.app_name, version="0.5.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


def require_token(token: str | None) -> None:
    expected = get_runtime_config()["ingest_token"]
    if not token or not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Invalid ingest token")


@app.get("/health")
def health() -> dict[str, str]:
    with SessionLocal() as db:
        db.execute(text("SELECT 1"))
    return {
        "status": "ok",
        "service": get_runtime_config()["app_name"],
        "version": app.version,
        "time": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request):
    config = get_runtime_config()
    if config["setup_complete"]:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request=request, name="setup.html", context={"config": config})


@app.post("/setup")
def complete_setup(
    app_name: str = Form(default="Homelab Sentinel"),
    firewall_name: str = Form(default="Firewall"),
    server_enabled: str | None = Form(default=None),
    server_name: str = Form(default="Remote Server"),
    crowdsec_enabled: str | None = Form(default=None),
    tailscale_enabled: str | None = Form(default=None),
    notification_provider: str = Form(default="none"),
):
    update_runtime_config({
        "setup_complete": True,
        "app_name": app_name.strip() or "Homelab Sentinel",
        "firewall_name": firewall_name.strip() or "Firewall",
        "server_enabled": server_enabled == "on",
        "server_name": server_name.strip() or "Remote Server",
        "crowdsec_enabled": crowdsec_enabled == "on",
        "tailscale_enabled": tailscale_enabled == "on",
        "notification_provider": notification_provider,
    })
    sync_configured_sources()
    return RedirectResponse(url="/settings?welcome=1", status_code=303)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    config = get_runtime_config()
    if not config["setup_complete"]:
        return RedirectResponse(url="/setup", status_code=303)
    with SessionLocal() as db:
        stats = dashboard_stats(db)
        sources = db.scalars(select(Source).order_by(Source.name)).all()
        events = db.scalars(select(SecurityEvent).order_by(SecurityEvent.seen_at.desc()).limit(settings.recent_event_limit)).all()
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"app_name": config["app_name"], "version": app.version, "sources": sources, "events": events, "collectors": config.get("collectors", []), **stats},
    )


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, welcome: int = Query(default=0), saved: str | None = Query(default=None)):
    config = get_runtime_config()
    if not config["setup_complete"]:
        return RedirectResponse(url="/setup", status_code=303)
    token = config["ingest_token"]
    masked_token = f"{'•' * max(len(token) - 8, 12)}{token[-8:]}"
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={"config": config, "version": app.version, "welcome": bool(welcome), "saved": saved, "masked_token": masked_token},
    )


@app.post("/settings/general")
def save_general_settings(app_name: str = Form(default="Homelab Sentinel"), firewall_name: str = Form(default="Firewall"), server_enabled: str | None = Form(default=None), server_name: str = Form(default="Remote Server"), tailscale_enabled: str | None = Form(default=None)):
    update_runtime_config({"app_name": app_name.strip() or "Homelab Sentinel", "firewall_name": firewall_name.strip() or "Firewall", "server_enabled": server_enabled == "on", "server_name": server_name.strip() or "Remote Server", "tailscale_enabled": tailscale_enabled == "on"})
    sync_configured_sources()
    return RedirectResponse(url="/settings?saved=general", status_code=303)


@app.post("/settings/collectors")
def save_collector_settings(crowdsec_enabled: str | None = Form(default=None), generic_events_enabled: str | None = Form(default=None)):
    update_runtime_config({"crowdsec_enabled": crowdsec_enabled == "on", "generic_events_enabled": generic_events_enabled == "on"})
    return RedirectResponse(url="/settings?saved=collectors#collectors", status_code=303)


@app.post("/settings/collectors/add")
def create_collector(collector_type: str = Form(...), name: str = Form(...), host: str = Form(...), port: int = Form(default=0)):
    if collector_type not in {"opnsense", "linux", "crowdsec", "fail2ban", "syslog"}:
        raise HTTPException(status_code=400, detail="Unsupported collector type")
    add_collector({"type": collector_type, "name": name, "host": host, "port": port})
    sync_configured_sources()
    return RedirectResponse(url="/settings?saved=collector-added#collectors", status_code=303)


@app.post("/settings/collectors/{collector_id}/test")
def test_collector(collector_id: str):
    config = get_runtime_config()
    collector = next((item for item in config.get("collectors", []) if item.get("id") == collector_id), None)
    if collector is None:
        raise HTTPException(status_code=404, detail="Collector not found")
    host = collector.get("host", "")
    port = int(collector.get("port") or (443 if collector.get("type") == "opnsense" else 22))
    try:
        with socket.create_connection((host, port), timeout=4):
            pass
        update_collector(collector_id, {"status": "reachable", "last_error": ""})
    except OSError as exc:
        update_collector(collector_id, {"status": "unreachable", "last_error": str(exc)[:180]})
    return RedirectResponse(url="/settings?saved=collector-tested#collectors", status_code=303)


@app.post("/settings/collectors/{collector_id}/delete")
def remove_collector(collector_id: str):
    if not delete_collector(collector_id):
        raise HTTPException(status_code=404, detail="Collector not found")
    return RedirectResponse(url="/settings?saved=collector-deleted#collectors", status_code=303)


@app.post("/settings/notifications")
def save_notification_settings(notification_provider: str = Form(default="none"), notification_target: str = Form(default="")):
    update_runtime_config({"notification_provider": notification_provider, "notification_target": notification_target.strip()})
    return RedirectResponse(url="/settings?saved=notifications", status_code=303)


@app.post("/settings/token/rotate")
def rotate_token():
    rotate_ingest_token()
    return RedirectResponse(url="/settings?saved=token", status_code=303)


@app.post("/api/v1/events", status_code=201)
def ingest_event(event: EventIn, x_sentinel_token: str | None = Header(default=None)):
    if not get_runtime_config().get("generic_events_enabled", True):
        raise HTTPException(status_code=503, detail="Generic event ingestion is disabled")
    require_token(x_sentinel_token)
    with SessionLocal() as db:
        row = create_event(db, event)
        return {"id": row.id, "status": "created"}


@app.post("/api/v1/crowdsec", status_code=202)
def ingest_crowdsec(webhook: CrowdSecWebhook, x_sentinel_token: str | None = Header(default=None)):
    if not get_runtime_config().get("crowdsec_enabled", True):
        raise HTTPException(status_code=503, detail="CrowdSec ingestion is disabled")
    require_token(x_sentinel_token)
    events = crowdsec_payload_to_events(webhook.source, webhook.payload)
    with SessionLocal() as db:
        ids = [create_event(db, event).id for event in events]
    return {"accepted": len(ids), "ids": ids}


@app.get("/api/v1/events")
def list_events(source: str | None = Query(default=None), severity: str | None = Query(default=None), limit: int = Query(default=50, ge=1, le=500)):
    with SessionLocal() as db:
        stmt = select(SecurityEvent).join(Source).order_by(SecurityEvent.seen_at.desc()).limit(limit)
        if source:
            stmt = stmt.where(Source.name == source)
        if severity:
            stmt = stmt.where(SecurityEvent.severity == severity)
        rows = db.scalars(stmt).all()
        return [{"id": row.id, "source": row.source.name, "event_type": row.event_type, "severity": row.severity, "title": row.title, "source_ip": row.source_ip, "country": row.country, "scenario": row.scenario, "seen_at": row.seen_at.isoformat()} for row in rows]
