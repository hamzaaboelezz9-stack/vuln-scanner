# Docker and local deployment

VulnScanner is an operator-run CLI, not a web service. It requires no database,
public listener, web login or Nginx. Install it on a workstation or VPS from which
you have written authorization to contact the selected targets. Treat assessment
reports and audit logs as private engagement data.

## Docker Compose

Use a currently supported Docker Engine with its Compose plugin. The Dockerfile
pins the Python 3.12 base manifest; the optional lab pins OWASP Juice Shop v20.2.0.
Image digests and dependency versions need deliberate updates. The image build
fetches package wheels; scanning never fetches code, assets or telemetry.

```sh
docker compose config --quiet
docker compose up --build
```

The default command prints help and exits successfully. It does not start an
unrequested assessment. Run the first-use notice once under the same named
state volume, and type exactly `I have permission`:

```sh
docker compose run --rm scanner acknowledge
docker compose run --rm scanner checks
```

Then scan an approved **private address** reachable from the container:

```sh
docker compose run --rm scanner net 192.168.1.10 \
  --ports 22,80,443 --checks discovery,ports,services \
  --output /reports/network-review --format all \
  --result-json /reports/network-result.json
```

These example RFC1918 addresses are documentation, not permission to test a
network you do not own. For named hosts, configure exact entries in the mounted
`allowlist.txt`. Public targets additionally require `--i-have-permission`, a
fresh publisher snapshot and the existing provider/government restrictions.
There is no `--insecure`, root mode or permission environment switch.

### State, reports and the container boundary

- The scanner runs as **UID/GID 10001**, with read-only root, dropped capabilities,
  no-new-privileges, bounded RAM/PIDs and a limited temporary filesystem.
- Named volumes retain owner-only authorization state and reports across runs.
  Source configuration and exact allowlist mounts are read-only.
- Container `127.0.0.1` refers to the scanner container. Use the owned service's
  reachable private address or the isolated `lab.local` alias below.
- Docker isolation is additional protection, not a sandbox for arbitrary Python
  plugins or a guarantee that root on the host cannot read engagement data.
- Removing volumes deletes acknowledgment, audit records and reports. Keep them
  until your engagement retention policy permits deletion.

Copy one report from the named volume using the non-root image; `umask` protects
the host copy. Use an exact report name you just generated:

```sh
umask 077
docker compose run --rm --entrypoint cat scanner /reports/network-review.html > network-review.html
```

A container cache updater is not included as an automatic job. To use an
operator-created policy, CA bundle or NVD cache, add an explicit read-only mount
in a local Compose override and pass its container path. Provider freshness is
checked at runtime, so a packaged policy ages and intentionally fails closed for
public targets. Update it with `python -m scanner.safety.cloud_updates` on the
host, inspect the official-source metadata, and mount the result read-only.

## Isolated Juice Shop lab

The `lab` profile runs an **intentionally vulnerable** application on an internal
Docker network. Its published host port is bound to loopback, never `0.0.0.0`.
It has no public deployment role. No public OWASP demo is used by these commands.

```sh
docker compose --profile lab up -d --wait juice-shop
docker compose run --rm scanner acknowledge
docker compose run --rm scanner web http://lab.local:3000 \
  --output /reports/juice-shop-review --format all \
  --result-json /reports/juice-shop-result.json
```

Default web mode may return **2**: query checks have no eligible parameters at
the root URL, canary traversal is absent, and an HTTP-only endpoint lacks full
TLS coverage. Inspect the recorded outcomes; do not discard a useful report
because coverage is honestly incomplete. A smaller baseline can be requested:

```sh
docker compose run --rm scanner web http://lab.local:3000 \
  --checks headers,cookies,cors,files,disclosure \
  --output /reports/juice-shop-baseline.html
```

After the lab assessment, stop the lab while preserving scanner state/reports:

```sh
docker compose --profile lab stop juice-shop
```

To change only the host lab port, copy `.env.example` to `.env` and edit
`JUICE_SHOP_PORT`. The scanner still uses port 3000 inside the network. A reverse
proxy or Internet tunnel for this lab would defeat its isolation; none is supplied.

## VPS operation and report access

Use a dedicated unprivileged account, keep the OS and Docker current, restrict
SSH with keys and a host firewall, and protect the state/report directories with
local access controls. A VPS account does not grant permission for other tenants
or cloud ranges. This project hard-blocks the major provider address feeds;
Internet scanning is intentionally narrower than many generic port scanners.

Transfer reports through authenticated SSH/SFTP, or open them locally. If an
organization independently serves HTML, it must add authentication, HTTPS,
access logging/retention controls and HTTP `frame-ancestors 'none'`. The standalone
report's meta CSP cannot enforce frame-ancestors. This release does not install
an unauthenticated report server or claim a hosted multi-user security boundary.

## Verification status

See [VALIDATION.md](VALIDATION.md) for checks actually executed for this release.
The CI workflow separately builds the image and smoke-tests its UID/resources
on a Docker-equipped GitHub runner after publication. Shipping that workflow
is not a claim that remote CI has already run or passed.
