# OWASP Juice Shop sample status and reproduction

**A measured Juice Shop report could not be produced in this release environment.**
There is no Docker/Podman engine; the official packaged application download
timed out, and a standalone Compose executable was also unavailable. No public
Juice Shop demo was scanned and no expected findings, PoCs, UUIDs or timestamps
have been fabricated. The included web/network reports are honestly labeled
measured synthetic loopback fixtures.

The optional Compose lab pins **v20.2.0** with publisher image index digest
`sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b`.
The manifest digest was read from Docker's public registry and checked against
the response bytes. A digest identifies those bytes; it is not an independent
security audit of this intentionally vulnerable application.

## Generate the actual report on a Docker-equipped workstation

From the repository root, using a lab you control:

```sh
docker compose --profile lab config --quiet
docker compose build scanner
docker compose --profile lab up -d --wait juice-shop
docker compose run --rm scanner acknowledge
```

Type exactly `I have permission` at the notice. Then run the actual scanner:

```sh
docker compose run --rm scanner web http://lab.local:3000 \
  --output /reports/juice-shop-review --format all \
  --result-json /reports/juice-shop-result.json
```

This produces the real HTML, SARIF, Markdown and native result in the private
report volume. Do not substitute a screenshot or guessed findings for the
result. Exit **2** means selected coverage is partial, not that export failed.
Root-URL input checks can skip, traversal needs a public non-secret canary,
and an HTTP-only lab cannot establish complete TLS security.

Copy the output you just generated:

```sh
umask 077
docker compose run --rm --entrypoint cat scanner /reports/juice-shop-review.html > juice-shop-review.html
docker compose run --rm --entrypoint cat scanner /reports/juice-shop-result.json > juice-shop-result.json
```

Review metadata, observed evidence, confidence and every skipped/inconclusive
check. The tool does not solve challenges, bypass authentication, extract data
or run exploit scripts. A small safe scanner cannot enumerate all Juice Shop
vulnerabilities or establish an overall business-risk rating from configuration
signals alone. Add manually verified findings only with their real evidence.

Stop the intentionally vulnerable lab after use:

```sh
docker compose --profile lab stop juice-shop
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for isolated networking, private volumes and
container verification limits. Official project sources:
[OWASP Juice Shop repository](https://github.com/juice-shop/juice-shop),
[v20.2.0 release](https://github.com/juice-shop/juice-shop/releases/tag/v20.2.0).
