# Homelab Sentinel

Lokales, datenschutzfreundliches Security-Dashboard für mehrere Homelab-Quellen.

## Version 0.5.0

- einzelner, ZimaOS-freundlicher Container
- persistente SQLite-Datenbank und Konfiguration unter `/data`
- automatischer Einrichtungsassistent
- automatisch erzeugte lokale Secrets
- Collector Framework für OPNsense, Linux-Server, CrowdSec, Fail2ban und Syslog
- Collector über die Weboberfläche hinzufügen, testen und entfernen
- CrowdSec- und allgemeine Ereignis-API
- Threat Score, Live-Ereignisliste und Quellenstatus
- automatische Konfigurationsmigrationen bei Updates
- versionierte GHCR-Images

## Container-Images

Stabile Version:

```text
ghcr.io/magicmikemirror/homelab-sentinel-app:0.5.0
```

Neueste stabile Version:

```text
ghcr.io/magicmikemirror/homelab-sentinel-app:latest
```

## Installation

Benötigt werden nur:

- Port `8088` → `8088`
- dauerhaftes Volume auf `/data`

Beim ersten Aufruf öffnet sich der Einrichtungsassistent. Secrets, Token, Datenbank und Grundeinstellungen werden lokal unter `/data` erzeugt.

## Aktualisierung

Der Container kann aktualisiert werden, ohne die App-Daten zu löschen:

1. vorhandenen Container stoppen
2. neues Image mit demselben `/data`-Volume laden
3. Container neu erstellen oder über die Host-Oberfläche aktualisieren
4. Homelab Sentinel führt notwendige Konfigurationsmigrationen beim Start automatisch aus

Solange dasselbe Host-Verzeichnis wieder auf `/data` eingebunden wird, bleiben Wizard-Konfiguration, Token, Datenbank und Collector erhalten.

Die vollständige ZimaOS-Anleitung liegt unter `docs/ZIMAOS.md`.

## Sicherheit

- keine Portfreigabe ins Internet
- Zugriff nur über ein vertrauenswürdiges LAN oder VPN
- Ingest-Token sicher behandeln
- keine echten IP-Adressen, Hostnamen, Domains oder Zugangsdaten committen
