# Publishing the source on GitHub

The archive's `vuln-scanner/` directory is the repository root. It contains the
full source, tests, Docker files, measured synthetic examples and documentation.
`SOURCEBOOK.md` reproduces authored text files with paths and two-line explanations;
normal repository files are the runnable implementation.

## Repository description

```text
Authorization-first Python web and TCP security scanner with bounded probes, passive fingerprints, offline CVE candidates, and HTML, SARIF and Markdown reports.
```

Suggested repository name: **vuln-scanner**. Suggested topics: `python`, `appsec`,
`security-scanner`, `ethical-hacking`, `owasp`, `sarif`, `cli`, `docker`.

## Publish

Create an empty repository under your own GitHub account, initialize the unpacked
source, review the staged files, and use the remote URL GitHub gives you:

```sh
git init
git branch -M main
git add .
git diff --cached --stat
git commit -m "Release VulnScanner 0.6.0"
```

Then follow GitHub's displayed commands to add **your real remote** and push
`main`. This package does not create or push a remote repository automatically.
The author identity, disclosure inbox and GitHub ownership must be yours; no
fictional account or fake audit badge is included.

Check the actual CI run after pushing. The workflow tests Python 3.10/3.12,
validates/builds Docker, and smoke-tests the installed wheel outside the checkout.
Full commit action pins, read-only repository permission and disabled checkout
credential persistence limit workflow trust. Remote CI results are not asserted
until those jobs have actually run. Avoid adding target credentials to Actions.

Enable GitHub's **private vulnerability reporting** on the repository Security
page. That gives SECURITY.md a real private disclosure channel without an
invented email address. Dependabot supplies reviewed package/action/image updates;
its presence does not certify that all dependencies are vulnerability-free.

## Release and portfolio

Use the installed commands in [CLI.md](CLI.md) and the isolated lab in
[DEPLOYMENT.md](DEPLOYMENT.md). Explain uncertainty accurately in your portfolio:
reflected markers and SQL error signatures require manual verification; passive
versions and advisory matches do not prove exploitable installed software.

The included reports come from measured local **synthetic fixtures**, as labeled
in each source result and report. They are not fabricated Juice Shop findings.
[JUICE_SHOP.md](JUICE_SHOP.md) explains how to generate a real local lab assessment
and records whether that sample could be measured in the release environment.

Keep real engagement outputs in the ignored `/reports/` directory. The private
state normally lives outside the repository; if relocating it, keep it outside
Git or add its exact path to your ignore rules. The default allowlist is empty.
Remove your engagement entries before publishing a fork.
