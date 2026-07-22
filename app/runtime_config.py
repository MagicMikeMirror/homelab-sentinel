import json
import os
import secrets
from pathlib import Path
from threading import RLock
from typing import Any

CONFIG_PATH = Path(os.getenv("SENTINEL_CONFIG_PATH", "/data/config.json"))
_LOCK = RLock()
_DEFAULTS: dict[str, Any] = {
    "setup_complete": False,
    "app_name": "Homelab Sentinel",
    "firewall_name": "Firewall",
    "server_enabled": False,
    "server_name": "Remote Server",
    "tailscale_enabled": False,
    "notification_provider": "none",
}


def _new_secrets() -> dict[str, str]:
    return {
        "secret_key": secrets.token_urlsafe(48),
        "ingest_token": secrets.token_urlsafe(48),
    }


def ensure_runtime_config() -> dict[str, Any]:
    with _LOCK:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not CONFIG_PATH.exists():
            data = {**_DEFAULTS, **_new_secrets()}
            _write(data)
            return data
        data = _read()
        changed = False
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
        allowed = set(_DEFAULTS)
        for key, value in values.items():
            if key in allowed:
                data[key] = value
        _write(data)
        return data


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
