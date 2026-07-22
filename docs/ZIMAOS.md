# ZimaOS GUI-Installation

Homelab Sentinel läuft als einzelner Container.

## Grunddaten

- Docker-Image: `ghcr.io/magicmikemirror/homelab-sentinel`
- Tag: `latest`
- Titel: `Homelab Sentinel`
- Netzwerk: `bridge`
- Web UI: `http://<ZIMAOS-IP>:8088/`

## Port

| Host | Container | Protokoll |
|---:|---:|---|
| 8088 | 8088 | TCP |

## Speicher

| Host | Container |
|---|---|
| `/DATA/AppData/homelab-sentinel/data` | `/data` |

## Umgebungsvariablen

| Name | Wert |
|---|---|
| `APP_NAME` | `Homelab Sentinel` |
| `APP_ENV` | `production` |
| `SECRET_KEY` | langer zufälliger Wert |
| `INGEST_TOKEN` | anderer langer zufälliger Wert |
| `DATABASE_URL` | `sqlite:////data/sentinel.db` |
| `OPNSENSE_SOURCE_NAME` | `firewall` |
| `VPS_SOURCE_NAME` | `remote-server` |
| `RECENT_EVENT_LIMIT` | `50` |

`SECRET_KEY` und `INGEST_TOKEN` dürfen nicht identisch sein.

## Zugriff

- LAN: `http://<LOKALE-IP>:8088/`
- VPN: `http://<VPN-IP-ODER-HOSTNAME>:8088/`

Keine Portfreigabe ins Internet erstellen.
