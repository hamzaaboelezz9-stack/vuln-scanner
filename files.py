"""Small metadata-only file discovery, directory listing and passive public URL inventory."""

import posixpath
from secrets import token_hex
from xml.etree import ElementTree

from scanner.checks.base import CheckContext, CheckInfo, register_check
from scanner.checks.web.common import (
    WSTG_ROOT,
    PageMetadata,
    WebCheck,
    WebRecord,
    approved_link,
    is_html,
    is_success,
    origin_url,
)
from scanner.core.finding import Confidence, Severity
from scanner.core.session import HTTPResponse
from scanner.core.target import ScanMode
from scanner.utils.wordlists import load_wordlist

MAX_INVENTORY_PATHS = 64
MAX_XML_MARKUP = 2048
MAX_INVENTORY_BYTES = 64 * 1024
FILE_REFERENCE = (
    WSTG_ROOT
    + "02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"
)
INVENTORY_REFERENCE = WSTG_ROOT + "01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage"


def missing_control(path: str) -> str:
    """Probe a same-directory, same-extension nonexistent control for rewrite false positives."""
    directory, basename = posixpath.split(path)
    suffix = posixpath.splitext(basename)[1]
    prefix = "." if basename.startswith(".") else ""
    return posixpath.join(directory, prefix + "vulnscan-not-present-" + token_hex(8) + suffix)


def metadata_candidate(candidate: HTTPResponse, control: HTTPResponse) -> bool:
    """A success differing from a real 404 is a candidate, never proof of secret contents."""
    return candidate.status_code == 200 and control.status_code in {404, 410} and not is_html(candidate)


@register_check(
    CheckInfo(
        "files",
        ScanMode.WEB,
        "Curated HEAD discovery, directory index structure and passive robots/sitemap inventory",
        160,
    )
)
class FilesCheck(WebCheck):
    """Find exposure candidates without downloading .env, repositories or backup contents."""

    def inspect(self, context: CheckContext, record: WebRecord) -> None:
        """Inspect bounded known paths with no recursive or cross-host crawling."""
        for path in load_wordlist("sensitive_files.txt"):
            control = context.http.request(origin_url(context, missing_control(path)), method="HEAD", read_body=False)
            candidate = context.http.request(origin_url(context, path), method="HEAD", read_body=False)
            if candidate.status_code in {405, 501} or control.status_code in {405, 501}:
                record.limit("Some HEAD probes were unsupported; their file exposure is unknown.")
            elif control.status_code == 200:
                record.limit(
                    "A nonexistent-path control returned success; metadata-only discovery cannot distinguish that rewrite."
                )
            elif metadata_candidate(candidate, control):
                record.add(
                    "files.sensitive_candidate",
                    "Sensitive-file URL returned distinct success metadata",
                    Severity.MEDIUM,
                    "A curated sensitive-file path returned HTTP 200 while its randomized same-directory/extension control returned not-found. No file content was downloaded, and private-data exposure is unconfirmed; [Needs manual verification].",
                    candidate,
                    (
                        "HEAD candidate returned 200; corresponding nonexistent control returned "
                        + str(control.status_code)
                        + ".",
                        "Non-HTML metadata observed. File contents, credentials and private data were not retrieved.",
                    ),
                    "Remove config, repository, database and backup files from public document roots. Deny dotfiles/config extensions in Nginx or Apache and store backups outside served directories. Have the owner verify the candidate before rotating any credentials.",
                    (FILE_REFERENCE,),
                    Confidence.POTENTIAL,
                    "HEAD",
                )
        for path in load_wordlist("common_dirs.txt"):
            if path == "/admin/":
                response = context.http.request(origin_url(context, path), method="HEAD", read_body=False)
                if response.status_code == 200:
                    record.add(
                        "files.admin_route",
                        "Administrative route responded",
                        Severity.INFO,
                        "The curated administrative path returned success metadata. An accessible login page is normal; no authentication bypass or unauthorized administrative action was tested.",
                        response,
                        ("HEAD /admin/ returned 200; body and authentication state were not inspected.",),
                        "Review the administrative surface, require strong authentication/MFA and authorization, and limit network access where appropriate. Do not treat URL obscurity as access control.",
                        (FILE_REFERENCE,),
                        method="HEAD",
                    )
                continue
            response = context.http.request(origin_url(context, path))
            if is_success(response) and is_html(response):
                self._directory_index(response, record)
        initial = context.http.request(context.target.url)
        if is_success(initial) and is_html(initial):
            self._directory_index(initial, record)
        self._robots(context, record)
        self._sitemap(context, record)

    def _directory_index(self, response: HTTPResponse, record: WebRecord) -> None:
        if any(
            item.rule_id == "files.directory_index" and item.evidence.endpoint == response.url
            for item in record.findings
        ):
            return
        metadata = PageMetadata()
        metadata.feed(response.text())
        if metadata.anchor_count >= 2 and any(
            heading.strip().lower().startswith(("index of /", "directory listing for /"))
            for heading in metadata.headings
        ):
            record.add(
                "files.directory_index",
                "Directory listing structure observed",
                Severity.LOW,
                "The response contains a conventional directory-index heading and multiple links. This establishes an index-style response; the sensitivity of listed files is unverified. No linked file was downloaded.",
                response,
                (
                    "Conventional directory-index heading and at least two links were observed.",
                    "Listed filenames and response contents were omitted.",
                ),
                "Disable Nginx autoindex or Apache Options Indexes for non-public directories. Keep non-public files outside the web root and authorize deliberate file listings.",
                (FILE_REFERENCE,),
                Confidence.CONFIRMED,
            )

    def _inventory(
        self, context: CheckContext, response: HTTPResponse, paths: tuple[str, ...], record: WebRecord, label: str
    ) -> None:
        accepted = sum(approved_link(context, response.url, path) is not None for path in paths)
        if paths:
            record.add(
                "files.public_inventory",
                f"{label} publishes URL inventory",
                Severity.INFO,
                "The public metadata contains path references. robots.txt and sitemaps are discoverability controls, not access control. Paths were inventoried without visiting them or claiming they are vulnerabilities.",
                response,
                (
                    f"Bounded references observed: {len(paths)}; approved-scope references: {accepted}.",
                    "Referenced paths/query values were not retained or fetched.",
                ),
                "Exclude private URLs from public sitemaps and apply authentication/authorization to private paths. Never rely on robots disallows to protect sensitive content.",
                (INVENTORY_REFERENCE,),
            )

    def _robots(self, context: CheckContext, record: WebRecord) -> None:
        response = context.http.request(origin_url(context, "/robots.txt"))
        if response.status_code != 200:
            return
        if response.body_truncated or response.body_unavailable_reason or len(response.body) > MAX_INVENTORY_BYTES:
            record.limit("robots.txt content was unavailable or exceeded the inventory cap.")
            return
        paths: list[str] = []
        for line in response.text().splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip().lower() in {"disallow", "allow", "sitemap"}:
                value = value.split("#", 1)[0].strip()
                if value and "*" not in value and "$" not in value:
                    paths.append(value)
                    if len(paths) == MAX_INVENTORY_PATHS:
                        record.limit("robots inventory stopped at 64 references.")
                        break
        self._inventory(context, response, tuple(paths), record, "robots.txt")

    def _sitemap(self, context: CheckContext, record: WebRecord) -> None:
        response = context.http.request(origin_url(context, "/sitemap.xml"))
        if response.status_code != 200:
            return
        body = response.body
        if (
            response.body_truncated
            or response.body_unavailable_reason
            or len(body) > MAX_INVENTORY_BYTES
            or body.count(b"<") > MAX_XML_MARKUP
            or b"\x00" in body
            or b"<!doctype" in body.lower()
            or b"<!entity" in body.lower()
        ):
            record.limit("Sitemap XML was unavailable, oversized or included unsupported declarations.")
            return
        try:
            root = ElementTree.fromstring(body.decode("utf-8"))
        except (ElementTree.ParseError, UnicodeError):
            record.limit("Sitemap response was not valid supported XML.")
            return
        paths: list[str] = []
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1] == "loc" and element.text:
                paths.append(element.text.strip())
                if len(paths) == MAX_INVENTORY_PATHS:
                    record.limit("Sitemap inventory stopped at 64 references.")
                    break
        self._inventory(context, response, tuple(paths), record, "sitemap.xml")
