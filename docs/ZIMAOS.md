# ZimaOS GUI-Installation

Homelab Sentinel läuft als einzelner Container und richtet sich beim ersten Start selbst ein.

## Grunddaten

- Docker-Image: `ghcr.io/magicmikemirror/homelab-sentinel-app`
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

Keine erforderlich.

Beim ersten Start erzeugt Homelab Sentinel automatisch:

- Secret Key
- Ingest-Token
- SQLite-Datenbank
- lokale Konfigurationsdatei

Anschließend öffnet sich unter `http://<ZIMAOS-IP>:8088/` der Einrichtungsassistent. Dort werden Anzeigename, Quellen, privater VPN-Zugriff und gewünschte Benachrichtigungsart gewählt.

Alle erzeugten Werte werden ausschließlich im eingebundenen Ordner `/data` gespeichert.

## Zugriff

- LAN: `http://<LOKALE-IP>:8088/`
- VPN: `http://<VPN-IP-ODER-HOSTNAME>:8088/`

Keine Portfreigabe ins Internet erstellen.
