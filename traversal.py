"""Optional public-canary traversal signal; never request OS files or private contents."""

import posixpath
from secrets import token_hex

from scanner.checks.base import CheckContext, CheckInfo, register_check
from scanner.checks.web.common import WSTG_ROOT, WebCheck, WebRecord, input_parameters, mutate_query, origin_url
from scanner.core.errors import CheckSkipped
from scanner.core.finding import Confidence, Severity
from scanner.core.target import ScanMode

FILE_FIELDS = frozenset({"file", "path", "filename", "document", "template", "download"})


@register_check(
    CheckInfo(
        "traversal", ScanMode.WEB, "Differential dot-segment signal against an explicitly configured public canary", 60
    )
)
class TraversalCheck(WebCheck):
    """Requires an owner-created public fixture; a response does not prove a filesystem boundary."""

    def inspect(self, context: CheckContext, record: WebRecord) -> None:
        """Compare public canary, missing filename, basename and parent-relative canary."""
        path, token = context.config.traversal_canary_path, context.config.traversal_canary_token
        if path is None or token is None:
            raise CheckSkipped("Public canary configuration is required.")
        parameters = input_parameters(context, record, FILE_FIELDS)
        canary = context.http.request(origin_url(context, path))
        expected = token.encode("ascii")
        if canary.status_code != 200 or canary.body.strip() != expected or canary.body_truncated:
            record.limit("The operator-created public canary did not return its exact configured token.")
            return
        basename = posixpath.basename(path)
        for index, name in parameters:
            control = context.http.request(
                mutate_query(context.target.url, index, "vulnscan-missing-" + token_hex(8) + ".txt")
            )
            normal = context.http.request(mutate_query(context.target.url, index, basename))
            traversed = context.http.request(mutate_query(context.target.url, index, "../" + basename))
            if (
                traversed.status_code == 200
                and traversed.body.strip() == expected
                and control.body.strip() != expected
                and normal.body.strip() != expected
            ):
                record.add(
                    "input.traversal_canary",
                    "Parent-relative input returned the public canary",
                    Severity.MEDIUM,
                    "A parent-relative filename returned the exact operator-supplied public canary where basename and missing controls did not. Filesystem escape and the application's intended boundary require manual verification. No operating-system or private file was requested.",
                    traversed,
                    (
                        "Existing query field inspected: " + name,
                        "Exact public-canary differential observed; token and file contents were omitted.",
                        "Only a single ../ prefix and the approved public canary filename were used.",
                    ),
                    "Resolve paths against an explicit allowed base directory and reject any canonical result outside that base. Prefer opaque file IDs to filenames, reject absolute/dot-segment paths, and authorize every requested object. Verify the intended boundary using this non-secret canary.",
                    (
                        WSTG_ROOT + "05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include",
                        "https://cwe.mitre.org/data/definitions/22.html",
                    ),
                    Confidence.POTENTIAL,
                )
