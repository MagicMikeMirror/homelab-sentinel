# Changelog

## [0.8.0-dev.2]

- Threat Score und Threat Level basieren nur noch auf den letzten 24 Stunden
- Gesamtstatistiken bleiben über den vollständigen Datenbestand erhalten
- technische Quellnamen wie `server` und `firewall` werden auf konfigurierte Anzeigenamen abgebildet
- Dashboard zeigt nur noch die letzten 15 Ereignisse
- neue paginierte Ereignisübersicht mit Quellen- und Schweregradfilter
- Trefferzahlen der häufigsten Szenarien und Länder werden deutlich dargestellt
- Dublettenerkennung berücksichtigt zusätzlich bereits im selben Import enthaltene Duplikate
- Live-Empfang und historische Importe verwenden dieselbe Quellnamensauflösung

## [0.8.0-dev.1]

- historischer CrowdSec-Import über `/api/v1/crowdsec/{source}/import`
- Dublettenerkennung anhand Quelle, Szenario, Angreifer-IP und Zeitpunkt
- wiederholbare Importe mit Ergebniswerten `found`, `imported` und `skipped`
- dynamische Quellenanzeige nur für Quellen mit empfangenen Ereignissen
- Threat-Intelligence-Kennzahlen für Angriffe, eindeutige Angreifer und Länder
- Auswertung der häufigsten Szenarien und Herkunftsländer
- mehrere CrowdSec-Quellen mit getrennten Quellnamen
- Importanleitung direkt in der Einstellungsoberfläche
- bestehende Datenbank, Konfiguration und Tokens bleiben beim Update erhalten

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
- SQLite-Datenbank unter `/data
