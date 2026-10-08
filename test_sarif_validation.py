"""Local schema validation cannot perform remote reference resolution."""

import json

import pytest

from examples.validate_sarif import validate
from scanner.reporting.json_export import render_json
from scanner.reporting.model import ReportError
from tests.report_support import report_document


def test_offline_validation_accepts_contract_and_rejects_wrong_version() -> None:
    """A project-owned minimal contract tests the helper; full official validation is separate."""
    schema = json.dumps(
        {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "required": ["version", "runs"],
            "properties": {"version": {"const": "2.1.0"}, "runs": {"type": "array", "minItems": 1}},
        }
    ).encode()
    assert validate(render_json(report_document()).encode(), schema) == 0
    assert validate(b'{"version":"wrong","runs":[]}', schema) == 2


@pytest.mark.parametrize("keyword", ["$ref", "$dynamicRef", "$recursiveRef"])
def test_external_schema_references_are_refused_before_any_network(keyword: str) -> None:
    """An apparently local schema must not fetch attacker-specified HTTP/file references."""
    for reference in ("https://evil.invalid/schema", "file:///etc/passwd"):
        schema = json.dumps({"nested": {keyword: reference}}).encode()
        with pytest.raises(ReportError):
            validate(b"{}", schema)
