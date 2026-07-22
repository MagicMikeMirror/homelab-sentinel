# Changelog

## 0.5.0

- Collector Framework für OPNsense, Linux-Server, CrowdSec, Fail2ban und Syslog
- Collector über die Weboberfläche hinzufügen, testen und entfernen
- Erreichbarkeitstest über private Hostnamen oder IP-Adressen
- persistente Collector-Konfiguration unter `/data/config.json`
- automatische Konfigurationsmigration von v0.4 auf v0.5
- Versionsanzeige in Healthcheck und Oberfläche
- versionierte GHCR-Images sowie `latest`
- bestehende Installation kann durch Austausch des Container-Images aktualisiert werden

## 0.4.0

- Einrichtungsassistent
- automatisch erzeugte lokale Secrets
- Einstellungszentrale
- CrowdSec- und allgemeine Ereignis-API
- SQLite-Datenbank unter `/data`
