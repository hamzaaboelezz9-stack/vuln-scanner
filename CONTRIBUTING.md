# Contributing

Keep the authorization gate and minimal-evidence boundary intact. New checks
must use the context transports, declare a bounded operation estimate, return
confidence plus explicit coverage, and include remediation. Never add raw target
response logging, implicit external lookups, authentication bypass, destructive
requests, execution payloads or an automatic legal-acceptance option.

## Development

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt 'setuptools>=77.0.3,<81'
python -m pip install --no-deps --no-build-isolation -e .
ruff check scanner tests examples cli.py
ruff format --check scanner tests examples cli.py
python -m pytest -q
python -m build --no-isolation
python -m pip check
```

Tests use owned, ephemeral loopback servers and fictional advisory fixtures.
No public system is an integration-test dependency. Add positive, negative and
refusal tests that establish real behavior; a failed/skipped check must never
turn into a clean pass. Separate actual measurements from authored fixtures.

The CLI constructs an independent registry from explicitly known built-ins.
Add a trusted class to the appropriate `load_*_checks()` list; importing it must
not cause DNS, sockets or file mutations. Existing in-process plugins are trusted
Python, not isolated executables. See [architecture](docs/ARCHITECTURE.md) and
[transport contract](docs/TRANSPORTS.md).

Use typed parameters/returns, public class/method docstrings and authored error
categories. Treat terminal, HTML, Markdown and imported JSON as hostile-data
boundaries. Keep shared configuration keys strict and permissions runtime-only.

## Reviews and disclosure

Explain the trigger, evidence, remediation and verification limits in your pull
request. Keep engagement data, allowlists, private logs and tokens out of commits.
For a potential vulnerability in the scanner, use the private process in
[SECURITY.md](SECURITY.md) rather than a public issue containing an exploit.
Maintain upstream dependency/action/image pins and run the relevant regression
suite when updating them. Do not claim certification or an independent audit.
