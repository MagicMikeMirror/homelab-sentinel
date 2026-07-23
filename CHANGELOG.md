# Changelog

## [0.6.0]

- nativer CrowdSec-Endpunkt für echte HTTP-Notifications
- direkte Quellzuordnung über `/api/v1/crowdsec/{source}`
- robuste Verarbeitung einzelner Alerts und Alert-Listen
- Speicherung von Szenario, Quell-IP, Land, Entscheidung und Rohdaten
- verbesserte Einstufung in low, medium, high und critical
- kopierfertige CrowdSec-Endpunkte in der Einstellungsoberfläche
- sichtbare Anschlussinformationen für Firewall und Server
- Release-Workflow mit SemVer-Prüfung, Quellcodeprüfung und kleingeschriebenem GHCR-Pfad
- GitHub Release enthält nur die Release Notes der jeweiligen Version
- bestehende Datenbank, Konfiguration und Tokens bleiben beim Update erhalten

## [0.5.0]

- Collector Framework für OPNsense, Linux-Server, CrowdSec, Fail2ban und Syslog
- Collector über die Weboberfläche hinzufügen, testen und entfernen
- persistente Collector-Konfiguration unter `/data/config.json`
- automatische Konfigurationsmigration von v0.4 auf v0.5
- Versionsanzeige in Healthcheck und Oberfläche
- versionierte GHCR-Images sowie `latest`
- bestehende Installation kann durch Austausch des Container-Images aktualisiert werden

## [0.4.0]

- Einrichtungsassistent
- automatisch erzeugte lokale Secrets
- Einstellungszentrale
- CrowdSec- und allgemeine Ereignis-API
- SQLite-Datenbank unter `/data`
