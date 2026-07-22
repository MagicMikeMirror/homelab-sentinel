# Homelab Sentinel

Lokales, datenschutzfreundliches Security-Dashboard für mehrere Homelab-Quellen.

## Funktionsumfang

- einzelner, ZimaOS-freundlicher Container
- persistente SQLite-Datenbank unter `/data`
- CrowdSec-Empfang für Firewall- und Server-Quellen
- allgemeine API für weitere Security-Ereignisse
- API-Schutz über `X-Sentinel-Token`
- Threat Score und Threat Level
- Live-Ereignisliste
- eindeutige Angreifer-IP-Adressen
- Quellenstatus
- automatischer GHCR-Build

## Container-Image

```text
ghcr.io/magicmikemirror/homelab-sentinel:latest
```

## ZimaOS

Die vollständige Anleitung liegt unter `docs/ZIMAOS.md`.

## Sicherheit

- keine Portfreigabe ins Internet
- Zugriff nur über vertrauenswürdiges LAN oder VPN
- `SECRET_KEY` und `INGEST_TOKEN` pro Installation zufällig und unterschiedlich erzeugen
- keine echten IP-Adressen, Hostnamen, Domains oder Zugangsdaten committen
