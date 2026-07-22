# Homelab Sentinel

Lokales, datenschutzfreundliches Security-Dashboard für mehrere Homelab-Quellen.

## Funktionsumfang

- einzelner, ZimaOS-freundlicher Container
- persistente SQLite-Datenbank unter `/data`
- automatischer Einrichtungsassistent beim ersten Start
- automatische Erzeugung von Secret Key und Ingest-Token
- CrowdSec-Empfang für Firewall- und Server-Quellen
- allgemeine API für weitere Security-Ereignisse
- API-Schutz über `X-Sentinel-Token`
- Threat Score, Live-Ereignisliste und Quellenstatus
- automatischer GHCR-Build

## Container-Image

```text
ghcr.io/magicmikemirror/homelab-sentinel-app:latest
```

## Installation

Für den ersten Start werden nur benötigt:

- Port `8088` → `8088`
- Speicher `/data`

Beim ersten Aufruf öffnet sich automatisch der Einrichtungsassistent. Secrets, Token, Datenbank und Grundeinstellungen werden lokal unter `/data` erzeugt. Es sind keine geheimen Umgebungsvariablen erforderlich.

Die vollständige ZimaOS-Anleitung liegt unter `docs/ZIMAOS.md`.

## Sicherheit

- keine Portfreigabe ins Internet
- Zugriff nur über ein vertrauenswürdiges LAN oder VPN
- automatisch erzeugten Ingest-Token sicher behandeln
- keine echten IP-Adressen, Hostnamen, Domains oder Zugangsdaten committen
