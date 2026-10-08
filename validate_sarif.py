"""Validate a SARIF report using an operator-supplied local official schema, entirely offline."""

import argparse
import sys
from pathlib import Path

from jsonschema.exceptions import SchemaError
from jsonschema.validators import validator_for

from scanner.reporting.io import MAX_INPUT_BYTES, parse_json
from scanner.reporting.model import ReportError


def validate(report: bytes, schema: bytes) -> int:
    """Return violation count after refusing external schema references; no URL is fetched."""
    instance, definition = parse_json(report), parse_json(schema)
    if not isinstance(definition, dict) or len(schema) > 1024 * 1024:
        raise ReportError("Schema must be a bounded JSON object.")
    stack = [definition]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if key in {"$ref", "$dynamicRef", "$recursiveRef"} and (
                    not isinstance(value, str) or not value.startswith("#")
                ):
                    raise ReportError("External schema references are refused.")
                stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)
    validator_type = validator_for(definition, default=None)
    if validator_type is None:
        raise ReportError("Schema must declare a supported local JSON Schema draft.")
    validator_type.check_schema(definition)
    validator = validator_type(definition, format_checker=validator_type.FORMAT_CHECKER)
    return sum(1 for _ in validator.iter_errors(instance))


def main(argv: list[str] | None = None) -> int:
    """Accept trusted local paths; output only validation categories, never raw findings."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--schema", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with args.report.open("rb") as report, args.schema.open("rb") as schema:
            errors = validate(report.read(MAX_INPUT_BYTES + 1), schema.read(1024 * 1024 + 1))
        sys.stdout.write(f"SARIF schema violations: {errors}\n")
        return 0 if errors == 0 else 1
    except (OSError, ReportError, SchemaError):
        sys.stderr.write("SARIF validation failed: invalid local report or schema.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
