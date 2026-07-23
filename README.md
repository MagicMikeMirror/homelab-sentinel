# Homelab Sentinel

Local Security Operations Center (SOC) for homelabs.

Homelab Sentinel collects security events from firewalls and servers, stores them locally, and presents them in a central dashboard. It is designed for private networks and VPN access without cloud accounts, telemetry, or public exposure.

## Current release

`0.6.0` — First Real Security Data

## Supported security sources

- CrowdSec on Linux servers and VPS systems
- CrowdSec on OPNsense
- generic authenticated security-event ingestion
- OPNsense and Linux collector definitions for private infrastructure

Homelab Sentinel is not intended for general resource monitoring, media applications, smart-home services, or uptime monitoring.

## v0.6.0 highlights

- native CrowdSec HTTP-notification endpoint
- one endpoint per source: `/api/v1/crowdsec/{source}`
- storage of scenario, attacker IP, country, message, severity, and raw alert data
- local threat score and recent-event feed
- persistent SQLite database and runtime configuration under `/data`
- automatic configuration migration between container updates
- versioned GitHub and GHCR releases

## Privacy and security

- all application data remains local
- no telemetry or mandatory external service
- no public port forwarding required
- no personal infrastructure values in source code or documentation
- generated secrets and tokens are stored only in the persistent `/data` volume
- incoming events require the `X-Sentinel-Token` header

Use Homelab Sentinel only through a trusted LAN or private VPN such as Tailscale or WireGuard.

## Container image

```text
ghcr.io/magicmikemirror/homelab-sentinel-app:0.6.0
```

The `latest` tag follows the newest stable release.

## Installation

Required container settings:

- TCP port `8088` mapped to container port `8088`
- persistent host directory mapped to `/data`
- no required environment variables

The setup wizard creates the local configuration, database, secret key, and ingest token automatically.

The ZimaOS guide is available in `docs/ZIMAOS.md`.

## CrowdSec ingestion

Use the source-specific endpoint shown in **Settings → Collector Framework**:

```text
POST http://<SENTINEL-HOST>:8088/api/v1/crowdsec/<SOURCE-NAME>
X-Sentinel-Token: <GENERATED-TOKEN>
Content-Type: application/json
```

The body may be a native CrowdSec alert object or a list of CrowdSec alerts.

## Release policy

A stable release is published only when:

- `VERSION` matches the requested semantic version
- the changelog contains a matching release section
- the application version matches `VERSION`
- Python compilation and application import succeed
- the Docker image builds and publishes successfully
- versioned and `latest` GHCR tags are written
- a Git tag and GitHub Release are created

## Roadmap

- `0.6.0` — real CrowdSec ingestion
- `0.7.0` — notifications and security insights
- `0.8.0` — incident center
- `0.9.0` — security automation
- `1.0.0` — stable release
