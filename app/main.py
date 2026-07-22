from contextlib import asynccontextmanager
from datetime import datetime, timezone
import secrets

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, text

from app.config import settings
from app.db import Base, SessionLocal, engine
from app.models import SecurityEvent, Source
from app.schemas import CrowdSecWebhook, EventIn
from app.services import create_event, crowdsec_payload_to_events, dashboard_stats


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        for name, kind in [
            (settings.opnsense_source_name, "crowdsec-firewall"),
            (settings.vps_source_name, "crowdsec-server"),
        ]:
            if db.scalar(select(Source).where(Source.name == name)) is None:
                db.add(Source(name=name, kind=kind))
        db.commit()
    yield


app = FastAPI(title=settings.app_name, version="0.2.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


def require_token(token: str | None) -> None:
    if not token or not secrets.compare_digest(token, settings.ingest_token):
        raise HTTPException(status_code=401, detail="Invalid ingest token")


@app.get("/health")
def health() -> dict[str, str]:
    with SessionLocal() as db:
        db.execute(text("SELECT 1"))
    return {
        "status": "ok",
        "service": settings.app_name,
        "time": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    with SessionLocal() as db:
        stats = dashboard_stats(db)
        sources = db.scalars(select(Source).order_by(Source.name)).all()
        recent_events = db.scalars(
            select(SecurityEvent).order_by(SecurityEvent.seen_at.desc()).limit(settings.recent_event_limit)
        ).all()
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"app_name": settings.app_name, "sources": sources, "events": recent_events, **stats},
    )


@app.post("/api/v1/events", status_code=201)
def ingest_event(event: EventIn, x_sentinel_token: str | None = Header(default=None)):
    require_token(x_sentinel_token)
    with SessionLocal() as db:
        row = create_event(db, event)
        return {"id": row.id, "status": "created"}


@app.post("/api/v1/crowdsec", status_code=202)
def ingest_crowdsec(webhook: CrowdSecWebhook, x_sentinel_token: str | None = Header(default=None)):
    require_token(x_sentinel_token)
    events = crowdsec_payload_to_events(webhook.source, webhook.payload)
    with SessionLocal() as db:
        ids = [create_event(db, event).id for event in events]
    return {"accepted": len(ids), "ids": ids}


@app.get("/api/v1/events")
def list_events(
    source: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
):
    with SessionLocal() as db:
        stmt = select(SecurityEvent).join(Source).order_by(SecurityEvent.seen_at.desc()).limit(limit)
        if source:
            stmt = stmt.where(Source.name == source)
        if severity:
            stmt = stmt.where(SecurityEvent.severity == severity)
        rows = db.scalars(stmt).all()
        return [
            {
                "id": row.id,
                "source": row.source.name,
                "event_type": row.event_type,
                "severity": row.severity,
                "title": row.title,
                "source_ip": row.source_ip,
                "country": row.country,
                "scenario": row.scenario,
                "seen_at": row.seen_at.isoformat(),
            }
            for row in rows
        ]
