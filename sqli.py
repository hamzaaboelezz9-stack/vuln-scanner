"""Single-quote error signatures only: no SQL logic, data queries, timing or bypass."""

import re

from scanner.checks.base import CheckContext, CheckInfo, register_check
from scanner.checks.web.common import WSTG_ROOT, WebCheck, WebRecord, input_parameters, mutate_query
from scanner.core.finding import Confidence, Severity
from scanner.core.target import ScanMode

DB_SIGNATURES = {
    "MySQL syntax error": re.compile(r"You have an error in your SQL syntax|SQL syntax.*MySQL", re.I),
    "PostgreSQL parser error": re.compile(
        r"(?:PostgreSQL|psycopg\w*|PG::SyntaxError)[\s\S]{0,200}(?:syntax error|unterminated quoted string)|ERROR:\s*unterminated quoted string",
        re.I,
    ),
    "SQL Server parser error": re.compile(
        r"Unclosed quotation mark after the character string|Microsoft (?:OLE DB Provider|SQL Native Client|SQL Server).*error",
        re.I,
    ),
    "Oracle syntax error": re.compile(r"\bORA-(?:00907|00917|00933|01756)\b"),
    "SQLite parser error": re.compile(
        r"(?:SQLite(?:Exception|3)?|sqlite3\.OperationalError)[\s\S]{0,200}(?:syntax error|unrecognized token|unterminated)",
        re.I,
    ),
    "SQLSTATE syntax class": re.compile(r"SQLSTATE\[(?:42000|42601)\]", re.I),
}


def database_signatures(text: str) -> frozenset[str]:
    """Return signature labels only, never raw DB errors or queried data."""
    return frozenset(name for name, pattern in DB_SIGNATURES.items() if pattern.search(text))


@register_check(
    CheckInfo(
        "sqli", ScanMode.WEB, "Single-quote differential parser-error signals on non-authentication query fields", 28
    )
)
class SQLiCheck(WebCheck):
    """Detect new parser-error signals; SQL injection remains a manually verified candidate."""

    def inspect(self, context: CheckContext, record: WebRecord) -> None:
        """Append one quote; compare with the original endpoint, without extracting data."""
        parameters = input_parameters(context, record)
        baseline = context.http.request(context.target.url)
        initial = database_signatures(baseline.text())
        for index, name in parameters:
            response = context.http.request(mutate_query(context.target.url, index, "'", append=True))
            matched = database_signatures(response.text()) - initial
            if matched:
                record.add(
                    "input.sql_error",
                    "Single quote introduced a database parser-error signal",
                    Severity.MEDIUM,
                    "A database syntax-error signature appeared after a single-quote mutation and was absent from the baseline. This may reflect unsafe query construction or diagnostic handling; SQL injection and its impact are not confirmed. No query logic, data extraction or authentication bypass was attempted.",
                    response,
                    (
                        "Existing query field inspected: " + name,
                        "New signature families: " + ", ".join(sorted(matched)),
                        "A single quote was appended; raw error text and data were omitted.",
                    ),
                    "Use parameterized queries/prepared statements for all values; validate identifiers with explicit allowlists. Disable database exception details in client responses and review the affected query construction in source or an owned test environment.",
                    (
                        WSTG_ROOT + "07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
                        "https://cwe.mitre.org/data/definitions/89.html",
                    ),
                    Confidence.POTENTIAL,
                )
