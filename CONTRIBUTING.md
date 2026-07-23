# Contributing to Homelab Sentinel

Homelab Sentinel is a privacy-first, local security application. Contributions must remain generic and must never expose a contributor's infrastructure.

## Privacy and security rules

Never commit:

- real public, private, VPN or Tailnet IP addresses
- real hostnames, domains, e-mail addresses or usernames
- API keys, tokens, passwords, cookies or private keys
- screenshots containing identifiable infrastructure data
- provider, account or network details tied to a real installation

For examples and tests, use only reserved documentation values such as:

- `192.0.2.0/24`
- `198.51.100.0/24`
- `203.0.113.0/24`
- `example.com`
- neutral names such as `Firewall`, `Server A` or `CrowdSec Source`

## Product scope

Homelab Sentinel focuses exclusively on security events and security infrastructure. General monitoring, media services, smart-home integrations and unrelated host metrics are outside the project scope.

## User experience

- setup should be possible through the web interface
- multiple firewalls and servers must be supported
- updates must preserve `/data`
- secrets must be generated or stored locally
- no public internet exposure may be required
