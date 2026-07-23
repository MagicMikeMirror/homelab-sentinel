# Homelab Sentinel

Local Security Operations Center (SOC) for homelabs.

Homelab Sentinel collects security events from firewalls and servers, stores them locally, and presents them in a central dashboard. It is designed for private networks and VPN access without cloud accounts, telemetry, or public exposure.

## Current development version

`0.8.0-dev.1` — CrowdSec Historical Import & Threat Intelligence

Stable users should continue using the latest published stable release. Testers can use the `edge` container tag.

## Supported security sources

- CrowdSec on Linux servers and VPS systems
- CrowdSec on OPNsense
- generic authenticated security-event ingestion
- multiple OPNsense and Linux security-source definitions

Homelab Sentinel is not intended for general resource monitoring, media applications, smart-home services, or uptime monitoring.

## v0.8 development highlights

- native CrowdSec live-event ingestion
- historical CrowdSec alert import through `/api/v1/crowdsec/{source}/import`
- duplicate detection for repeated imports
- multiple CrowdSec sources
- dynamic source cards based only on received events
- threat score, unique attackers, source countries, top scenarios, and top countries
- persistent SQLite database and runtime configuration under `/data`
- update-safe container workflow with stable and `edge` images

## Privacy and security

- all application data remains local
- no telemetry or mandatory external service
- no public port forwarding required
- no personal infrastructure values in source code or documentation
- generated secrets and tokens are stored only in the persistent `/data` volume
- incoming events require the `X-Sentinel-Token` header

Use Homelab Sentinel only through a trusted LAN or private VPN such as Tailscale or WireGuard.

## Container images

Stable:

```text
ghcr.io/magicmikemirror/homelab-sentinel-app:latest
```

Development testing:

```text
ghcr.io/magicmikemirror/homelab-sentinel-app:edge
```

## Installation

Required container settings:

- TCP port `8088` mapped to container port `8088`
- persistent host directory mapped to `/data`
- no required environment variables

The setup wizard creates the local configuration, database, secret key, and ingest token automatically. The ZimaOS guide is available in `docs/ZIMAOS.md`.

## CrowdSec live ingestion

```text
POST http://<SENTINEL-HOST>:8088/api/v1/crowdsec/<SOURCE-NAME>
X-Sentinel-Token: <GENERATED-TOKEN>
Content-Type: application/json
```

## CrowdSec historical import

Example for the last 30 days:

```bash
sudo cscli alerts list --since 30d --limit 0 -o json \
  | curl -X POST \
      http://<SENTINEL-HOST>:8088/api/v1/crowdsec/<SOURCE-NAME>/import \
      -H "Content-Type: application/json" \
      -H "X-Sentinel-Token: <GENERATED-TOKEN>" \
      --data-binary @-
```

The response reports `found`, `imported`, and `skipped`. Repeating an import is safe because duplicates are skipped.

## Release policy

Stable releases require matching version metadata, changelog notes, passing tests, successful Python compilation, a successful container build, versioned GHCR tags, a Git tag, and a GitHub Release.

## Roadmap

- `0.6.0` — real CrowdSec ingestion
- `0.7.0` — multi-source setup and usability
- `0.8.0` — historical import and threat intelligence
- `0.9.0` — notifications and incident workflows
- `1.0.0` — stable release
