import json
import os
import secrets
from pathlib import Path
from threading import RLock
from typing import Any

CONFIG_PATH = Path(os.getenv("SENTINEL_CONFIG_PATH", "/data/config.json"))
_LOCK = RLock()
CURRENT_CONFIG_VERSION = 3
_DEFAULTS: dict[str, Any] = {
    "config_version": CURRENT_CONFIG_VERSION,
    "setup_complete": False,
    "app_name": "Homelab Sentinel",
    "firewall_name": "Firewall",
    "server_enabled": False,
    "server_name": "Remote Server",
    "tailscale_enabled": False,
    "notification_provider": "none",
    "notification_target": "",
    "crowdsec_enabled": True,
    "generic_events_enabled": True,
    "collectors": [],
}


def _new_secrets() -> dict[str, str]:
    return {"secret_key": secrets.token_urlsafe(48), "ingest_token": secrets.token_urlsafe(48)}


def _migrate(data: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    changed = False
    version = int(data.get("config_version", 1))
    if version < 2:
        data.setdefault("collectors", [])
        version = 2
        changed = True
    if not isinstance(data.get("collectors"), list):
        data["collectors"] = []
        changed = True
    if version < 3:
        for collector in data["collectors"]:
            collector.setdefault("username", "")
            collector.setdefault("connection_mode", "webhook" if collector.get("type") == "crowdsec" else "network")
        version = 3
        changed = True
    if data.get("config_version") != CURRENT_CONFIG_VERSION:
        data["config_version"] = CURRENT_CONFIG_VERSION
        changed = True
    return data, changed


def ensure_runtime_config() -> dict[str, Any]:
    with _LOCK:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not CONFIG_PATH.exists():
            data = {**_DEFAULTS, **_new_secrets()}
            _write(data)
            return data
        data, changed = _migrate(_read())
        for key, value in _DEFAULTS.items():
            if key not in data:
                data[key] = value
                changed = True
        for key, value in _new_secrets().items():
            if not data.get(key):
                data[key] = value
                changed = True
        if changed:
            _write(data)
        return data


def get_runtime_config() -> dict[str, Any]:
    return ensure_runtime_config()


def update_runtime_config(values: dict[str, Any]) -> dict[str, Any]:
    with _LOCK:
        data = ensure_runtime_config()
        for key, value in values.items():
            if key in _DEFAULTS:
                data[key] = value
        _write(data)
        return data


def add_collector(values: dict[str, Any]) -> dict[str, Any]:
    with _LOCK:
        data = ensure_runtime_config()
        collector = {
            "id": secrets.token_hex(8),
            "type": str(values.get("type") or "generic"),
            "name": str(values.get("name") or "Collector").strip()[:80],
            "host": str(values.get("host") or "").strip()[:255],
            "port": int(values.get("port") or 0),
            "username": str(values.get("username") or "").strip()[:120],
            "connection_mode": str(values.get("connection_mode") or "network").strip()[:40],
            "enabled": True,
            "status": "not_tested",
            "last_error": "",
        }
        data["collectors"].append(collector)
        _write(data)
        return collector


def update_collector(collector_id: str, values: dict[str, Any]) -> dict[str, Any] | None:
    with _LOCK:
        data = ensure_runtime_config()
        for collector in data["collectors"]:
            if collector.get("id") == collector_id:
                collector.update(values)
                _write(data)
                return collector
        return None


def delete_collector(collector_id: str) -> bool:
    with _LOCK:
        data = ensure_runtime_config()
        before = len(data["collectors"])
        data["collectors"] = [item for item in data["collectors"] if item.get("id") != collector_id]
        if len(data["collectors"]) == before:
            return False
        _write(data)
        return True


def rotate_ingest_token() -> str:
    with _LOCK:
        data = ensure_runtime_config()
        data["ingest_token"] = secrets.token_urlsafe(48)
        _write(data)
        return data["ingest_token"]


def _read() -> dict[str, Any]:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = {**_DEFAULTS, **_new_secrets()}
        _write(data)
        return data


def _write(data: dict[str, Any]) -> None:
    tmp = CONFIG_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(CONFIG_PATH)
