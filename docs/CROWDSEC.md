# CrowdSec anbinden

Homelab Sentinel v0.6 accepts native CrowdSec alerts through a source-specific HTTP endpoint.

## Requirements

- Homelab Sentinel and the CrowdSec host can reach each other through a trusted LAN or private VPN.
- CrowdSec ingestion is enabled in Homelab Sentinel.
- The generated ingest token is available under **Settings → API & Token**.

Do not expose the Sentinel port publicly.

## Endpoint

```text
http://<SENTINEL-HOST>:8088/api/v1/crowdsec/<SOURCE>
```

Use a neutral source key such as `firewall` or `server`. The key becomes the source name in stored events.

## Linux server

Create a notification file in the CrowdSec notification directory used by your installation. Example configuration:

```yaml
type: http
name: homelab_sentinel
log_level: info

format: |
  {{ . | toJson }}

url: http://<SENTINEL-HOST>:8088/api/v1/crowdsec/server
method: POST

headers:
  Content-Type: application/json
  X-Sentinel-Token: <INGEST-TOKEN>

timeout: 10s
max_retry: 3
```

Restrict the file permissions because it contains the ingest token.

Enable the notification in the applicable CrowdSec profile:

```yaml
notifications:
  - homelab_sentinel
```

Test the notification with the CrowdSec notification test command available in your installation, then restart CrowdSec.

## OPNsense

Use the same HTTP notification structure, but point it to a source-specific endpoint such as:

```text
http://<SENTINEL-HOST>:8088/api/v1/crowdsec/firewall
```

Use the CrowdSec configuration directories provided by the installed OPNsense CrowdSec plugin. Plugin-managed files and paths may differ between versions, so confirm them on the target firewall before editing.

## Authentication

Every request must contain:

```text
X-Sentinel-Token: <INGEST-TOKEN>
```

A missing or incorrect token returns HTTP `401`.

## Successful response

A valid alert returns HTTP `202` and a response similar to:

```json
{
  "accepted": 1,
  "ids": [1],
  "source": "server"
}
```

## Supported body formats

Sentinel accepts:

- one CrowdSec alert object
- a list of CrowdSec alert objects
- an object containing an `alerts`, `payload`, or `data` field

For each alert, Sentinel stores the scenario, attacker IP, country, message, severity, timestamp, decisions, and original raw payload.
