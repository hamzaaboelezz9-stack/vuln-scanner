"""Discovery metadata, false-positive controls and omitted sensitive response content."""

import pytest

from scanner.checks.web.disclosure import DisclosureCheck
from scanner.checks.web.files import FilesCheck
from scanner.core.result import CheckStatus
from scanner.safety.policy import ScopeError
from scanner.safety.state import AuthorizationStore
from tests.web_lab import Reply, serve_web_lab
from tests.web_support import web_context


def test_sensitive_files_head_only_directory_inventory_no_data_fetch(state: AuthorizationStore) -> None:
    """Report bounded metadata/index signals without fetching files or inventory links."""
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply()
        lab.routes["/.env"] = Reply(
            body=b"SYNTHETIC_SECRET=synthetic-private-config-value", headers=(("Content-Type", "text/plain"),)
        )
        lab.routes["/admin/"] = Reply()
        lab.routes["/uploads/"] = Reply(
            body=b'<h1>Index of /uploads/</h1><a href="synthetic-private-name">one</a><a href="two">two</a>'
        )
        lab.routes["/robots.txt"] = Reply(
            body=b"User-agent: *\nDisallow: /synthetic-private-path\nSitemap: http://169.254.169.254/never\n",
            headers=(("Content-Type", "text/plain"),),
        )
        lab.routes["/sitemap.xml"] = Reply(
            body=(
                f"<urlset><url><loc>{lab.url}/synthetic-private-map-path?token=synthetic-private-token</loc></url></urlset>"
            ).encode(),
            headers=(("Content-Type", "application/xml"),),
        )
        report = FilesCheck().run(web_context(state, lab.url))
        rules = {item.rule_id for item in report.findings}
        assert {
            "files.sensitive_candidate",
            "files.directory_index",
            "files.admin_route",
            "files.public_inventory",
        } <= rules
        assert all(request.method == "HEAD" for request in lab.requests if request.path == "/.env")
        assert not any("synthetic-private-path" in request.path or request.path == "/never" for request in lab.requests)
        assert "synthetic-private" not in str([item.to_dict() for item in report.findings])
        assert report.status is CheckStatus.COMPLETE


def test_soft_404_spa_and_head_unsupported_do_not_fake_exposure(state: AuthorizationStore) -> None:
    """A wildcard 200 is ambiguous and unsupported HEAD never falls back to a secret GET."""
    with serve_web_lab() as lab:
        lab.default = Reply()
        report = FilesCheck().run(web_context(state, lab.url))
        assert not any(item.rule_id == "files.sensitive_candidate" for item in report.findings)
        assert report.status is CheckStatus.INCONCLUSIVE
        lab.default = Reply(404, b"not found")
        lab.routes["/.env"] = Reply(405)
        report = FilesCheck().run(web_context(state, lab.url))
        assert report.status is CheckStatus.INCONCLUSIVE
        assert all(request.method == "HEAD" for request in lab.requests if request.path == "/.env")


@pytest.mark.parametrize(
    "xml",
    [
        b'<!DOCTYPE urlset [<!ENTITY a "synthetic">]><urlset>&a;</urlset>',
        '<!DOCTYPE urlset [<!ENTITY a "synthetic">]><urlset>&a;</urlset>'.encode("utf-16"),
        b"<invalid",
        b"<urlset>" + b"<x/>" * 2049 + b"</urlset>",
    ],
)
def test_sitemap_unsupported_xml_is_incomplete(state: AuthorizationStore, xml: bytes) -> None:
    """DTD/entity and UTF-16 declarations cannot reach an unsafe XML expansion path."""
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply()
        lab.routes["/sitemap.xml"] = Reply(body=xml, headers=(("Content-Type", "application/xml"),))
        assert FilesCheck().run(web_context(state, lab.url)).status is CheckStatus.INCONCLUSIVE


def test_comments_technology_errors_source_maps_omit_values(state: AuthorizationStore) -> None:
    """Source maps are metadata only, and raw comments/errors/headers never enter findings."""
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply(
            body=b'<meta name="generator" content="synthetic-private-generator"><!-- secret=synthetic-private-comment --><script src="/assets/app.js"></script>',
            headers=(("Content-Type", "text/html"), ("Server", "synthetic-private-version")),
        )
        lab.routes["/assets/app.js"] = Reply(
            body=b"const publicValue = 1;\n//# sourceMappingURL=app.js.map",
            headers=(("Content-Type", "application/javascript"),),
        )
        lab.routes["/assets/app.js.map"] = Reply(
            body=b'{"sourcesContent":["synthetic-private-source"]}', headers=(("Content-Type", "application/json"),)
        )
        lab.default = Reply(
            404,
            b'Traceback (most recent call last):\n File "synthetic-private-path", line 3',
            (("Content-Type", "text/plain"),),
        )
        report = DisclosureCheck().run(web_context(state, lab.url))
        assert {
            "disclosure.tech_headers",
            "disclosure.generator",
            "disclosure.comment",
            "disclosure.verbose_error",
            "disclosure.source_map",
        } <= {item.rule_id for item in report.findings}
        assert "synthetic-private" not in str([item.to_dict() for item in report.findings])
        assert all(request.method == "HEAD" for request in lab.requests if request.path.endswith(".map"))


def test_script_scope_and_private_paths_are_never_followed(state: AuthorizationStore) -> None:
    """Untrusted script metadata cannot cause a metadata-service or private-file download."""
    with serve_web_lab() as lab:
        lab.routes["/"] = Reply(
            body=b'<script src="http://169.254.169.254/secret.js"></script><script src="/.env"></script>'
        )
        report = DisclosureCheck().run(web_context(state, lab.url))
        assert report.status is CheckStatus.INCONCLUSIVE
        assert not any(request.path == "/.env" or request.path == "/secret.js" for request in lab.requests)


@pytest.mark.parametrize(
    "path",
    [
        "/.env",
        "/.%65nv",
        "/.git/config",
        "/assets/app.js.map",
        "/backup.zip",
        "/read?file=%2Fetc%2Fpasswd",
        "/read?path=config.yaml",
    ],
)
def test_transport_private_get_refusal_before_io(state: AuthorizationStore, path: str) -> None:
    """The shared transport refuses obvious private-file bodies even if a rule errs."""
    with serve_web_lab() as lab:
        context = web_context(state, lab.url)
        with pytest.raises(ScopeError):
            context.http.request(lab.url + path)
        assert not lab.requests
        context.http.request(lab.url + path, method="HEAD", read_body=False)
        assert lab.requests[0].method == "HEAD"
