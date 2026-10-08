"""Self-contained HTML with autoescaping, fixed templates and a hash-based style CSP."""

import base64
import hashlib
from importlib.resources import files

from jinja2 import Environment, StrictUndefined
from markupsafe import Markup

from scanner import __version__
from scanner.reporting.model import ReportDocument

MAX_TEMPLATE_BYTES = 64 * 1024


def _asset(name: str) -> str:
    if name not in {"report.html", "report.css"}:
        raise ValueError("Unknown report asset.")
    data = files("scanner.reporting").joinpath("templates", name).read_bytes()
    if len(data) > MAX_TEMPLATE_BYTES:
        raise ValueError("Report asset exceeds its size bound.")
    return data.decode("utf-8")


def render_html(document: ReportDocument) -> str:
    """Render inert offline HTML; all source values remain escaped, never template code."""
    css = _asset("report.css")
    digest = base64.b64encode(hashlib.sha256(css.encode("utf-8")).digest()).decode("ascii")
    csp = f"default-src 'none'; script-src 'none'; style-src 'sha256-{digest}'; img-src 'none'; connect-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
    environment = Environment(autoescape=True, undefined=StrictUndefined)
    # Only authored package CSS is marked as markup. No source-result field is ever trusted HTML.
    stylesheet = Markup(css)
    findings = []
    for index, finding in enumerate(document.findings, 1):
        findings.append(
            {
                "id": f"FINDING-{index:03d}",
                "finding": finding,
                "evidence": f"{finding.evidence.method} {finding.evidence.endpoint}\nHTTP status: {finding.evidence.status_code if finding.evidence.status_code else 'Not applicable / unavailable'}\n"
                + "\n".join(finding.evidence.observations),
            }
        )
    return environment.from_string(_asset("report.html")).render(
        document=document, findings=findings, stylesheet=stylesheet, csp=csp, version=__version__
    )
