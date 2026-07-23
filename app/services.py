from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import SecurityEvent, Source
from app.schemas import EventIn

SEVERITY_WEIGHTS = {"info": 0, "low": 1, "medium": 3, "high": 7, "critical": 12}


def get_or_create_source(db: Session, name: str, kind: str = "generic") -> Source:
    source = db.scalar(select(Source).where(Source.name == name))
    if source is None:
        source = Source(name=name, kind=kind, status="online")
        db.add(source)
        db.flush()
    return source


def create_event(db: Session, event: EventIn) -> SecurityEvent:
    source = get_or_create_source(db, event.source)
    row = SecurityEvent(
        source_id=source.id,
        event_type=event.event_type,
        severity=event.severity,
        title=event.title,
        source_ip=event.source_ip,
        country=event.country,
        scenario=event.scenario,
        message=event.message,
        raw_data=event.raw_data,
        seen_at=(event.seen_at or datetime.now(timezone.utc)).replace(tzinfo=None),
    )
    db.add(row)
    source.status = "online"
    source.last_seen_at = datetime.utcnow()
    db.commit()
    db.refresh(row)
    return row


def _extract_alerts(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("alerts", "payload", "data"):
        nested = payload.get(key)
        if isinstance(nested, list):
            return [item for item in nested if isinstance(item, dict)]
        if isinstance(nested, dict):
            return [nested]
    return [payload]


def _severity(alert: dict[str, Any], decisions: list[Any]) -> str:
    capacity = alert.get("capacity")
    events_count = alert.get("events_count") or alert.get("eventsCount") or 0
    if decisions and isinstance(capacity, (int, float)) and capacity >= 10:
        return "critical"
    if decisions:
        return "high"
    if isinstance(events_count, int) and events_count >= 5:
        return "medium"
    return "low"


def crowdsec_payload_to_events(source_name: str, payload: Any) -> list[EventIn]:
    events: list[EventIn] = []
    for alert in _extract_alerts(payload):
        source = alert.get("source") or {}
        decisions = alert.get("decisions") or []
        scenario = alert.get("scenario") or alert.get("scenario_hash") or "crowdsec-alert"
        ip = source.get("ip") if isinstance(source, dict) else None
        country = None
        if isinstance(source, dict):
            country = source.get("cn") or source.get("country")
        message = alert.get("message") or alert.get("description")
        started_at = alert.get("start_at") or alert.get("created_at")
        seen_at = None
        if isinstance(started_at, str):
            try:
                seen_at = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            except ValueError:
                seen_at = None
        events.append(
            EventIn(
                source=source_name,
                event_type="crowdsec_alert",
                severity=_severity(alert, decisions),
                title=f"CrowdSec: {scenario}",
                source_ip=ip,
                country=country,
                scenario=str(scenario),
                message=message,
                seen_at=seen_at,
                raw_data=alert,
            )
        )
    return events


def dashboard_stats(db: Session) -> dict[str, Any]:
    total = db.scalar(select(func.count(SecurityEvent.id))) or 0
    active_sources = db.scalar(select(func.count(Source.id)).where(Source.status == "online")) or 0
    unique_ips = db.scalar(
        select(func.count(func.distinct(SecurityEvent.source_ip))).where(SecurityEvent.source_ip.is_not(None))
    ) or 0
    severity_rows = db.execute(
        select(SecurityEvent.severity, func.count(SecurityEvent.id)).group_by(SecurityEvent.severity)
    ).all()
    threat_score = min(100, sum(SEVERITY_WEIGHTS.get(level, 1) * count for level, count in severity_rows))
    threat_level = "CRITICAL" if threat_score >= 70 else "HIGH" if threat_score >= 40 else "MEDIUM" if threat_score >= 15 else "LOW"
    return {
        "total_events": total,
        "active_sources": active_sources,
        "unique_ips": unique_ips,
        "threat_score": threat_score,
        "threat_level": threat_level,
    }
