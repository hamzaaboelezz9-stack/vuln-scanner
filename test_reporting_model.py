"""Imported reports preserve coverage and reject inconsistent attacker-controlled metadata."""

import copy
import io
import json
from pathlib import Path

import pytest

from scanner.core.result import CheckOutcome, CheckStatus
from scanner.reporting.io import MAX_INPUT_BYTES, load_result, load_stream
from scanner.reporting.model import MAX_FINDINGS, ReportDocument, ReportError
from tests.report_support import report_document, report_result


def test_report_counts_recomputed_and_unknown_metadata_discarded() -> None:
    """A forged zero-count summary or secret-bearing extension never reaches exporters."""
    raw = report_result().to_dict()
    raw["counts"] = {"medium": 0}
    raw["private_extension"] = "never-publish-secret"
    raw["limits"] = {"workers": 2, "private_extension": "never-publish-secret"}
    raw["approved_scope"]["raw_private_banner"] = "never-publish-secret"
    document = ReportDocument.from_mapping(raw)
    assert document.counts["medium"] == 1
    assert "never-publish-secret" not in json.dumps(document.metadata())
    assert document.limits == (("workers", 2),)


@pytest.mark.parametrize("status", [CheckStatus.SKIPPED, CheckStatus.INCONCLUSIVE, CheckStatus.FAILED])
def test_zero_findings_with_incomplete_coverage_never_becomes_clean(status: CheckStatus) -> None:
    """No findings cannot erase an explicit failed or unexecuted check."""
    result = report_result()
    result.findings.clear()
    result.outcomes = [CheckOutcome("headers", status, "Fixture coverage missing.")]
    document = ReportDocument.from_result(result)
    assert not document.complete and document.highest_severity == "None recorded"
    assert document.coverage_counts[status.value] == 1
    assert "secure" not in document.summary.lower()


def test_missing_finish_or_selected_checks_remains_unfinished() -> None:
    """A finish timestamp alone is not sufficient coverage evidence."""
    raw = report_result().to_dict()
    raw["ended_at"] = None
    assert not ReportDocument.from_mapping(raw).complete
    raw = report_result().to_dict()
    raw["coverage"] = []
    assert not ReportDocument.from_mapping(raw).complete


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "other.v1"),
        ("scan_id", "not-a-uuid"),
        ("mode", "unknown"),
        ("started_at", "2026-10-07T12:00:00"),
        ("ended_at", "2000-01-01T00:00:00Z"),
        ("findings", [{}]),
        ("operations", {"HTTP": True}),
        ("limits", {"workers": "10"}),
        ("coverage", [{"check": "headers", "status": "failed", "reason": ""}]),
        ("approved_scope", {"addresses": ["127.0.0.1", "127.0.0.1"], "ports": [3000]}),
    ],
)
def test_invalid_report_fields_fail_closed(field: str, value: object) -> None:
    """Bad imported metadata raises an authored report error, without a partial export."""
    raw = report_result().to_dict()
    raw[field] = value
    with pytest.raises(ReportError):
        ReportDocument.from_mapping(raw)


def test_inconsistent_cvss_is_rejected_and_null_is_preserved() -> None:
    """No score is guessed and independent supplied numbers must match computed vectors."""
    raw = report_result(scored=True).to_dict()
    raw["findings"][0]["cvss"]["score"] = 9.8
    with pytest.raises(ReportError):
        ReportDocument.from_mapping(raw)
    assert report_document().findings[0].cvss is None
    assert report_document(scored=True).findings[0].cvss.score == 6.1


def test_duplicate_coverage_and_oversized_findings_are_rejected() -> None:
    """Bounded imported lists do not silently drop inconvenient coverage/findings."""
    raw = report_result().to_dict()
    raw["coverage"] *= 2
    with pytest.raises(ReportError):
        ReportDocument.from_mapping(raw)
    raw = report_result().to_dict()
    raw["findings"] *= MAX_FINDINGS + 1
    with pytest.raises(ReportError):
        ReportDocument.from_mapping(raw)


def test_actual_previous_phase_samples_are_read_without_changing_measurements() -> None:
    """Source fixtures remain historical measurements, never rebranded as fresh scans."""
    root = Path(__file__).parents[1] / "docs"
    web, net = load_result(root / "WEB_SAMPLE.json"), load_result(root / "NETWORK_SAMPLE.json")
    assert len(web.findings) == 22 and len(net.findings) == 5
    assert dict(web.operations) == {"HTTP": 59, "TCP": 0, "TLS": 5}
    assert dict(net.operations) == {"HTTP": 0, "TCP": 3, "TLS": 0}
    assert not web.complete and not net.complete
    assert "synthetic" in net.purpose and net.surface and len(net.surface.opened) == 2


@pytest.mark.parametrize("mutation", ["pairs", "approved-port", "verified", "omitted", "incomplete", "raw-banner"])
def test_surface_consistency_and_whitelisted_metadata(mutation: str) -> None:
    """Wrong scope/count/authenticity assertions fail; unrecognized raw greetings disappear."""
    raw = json.loads((Path(__file__).parents[1] / "docs/NETWORK_SAMPLE.json").read_text())
    surface = raw["attack_surface"]
    if mutation == "pairs":
        surface["observed_pairs"] = 100
    elif mutation == "approved-port":
        surface["open_ports"][0]["port"] = 1
    elif mutation == "verified":
        surface["open_ports"][0]["service"]["identity_verified"] = True
    elif mutation == "omitted":
        surface["open_ports_omitted"] = 100
    elif mutation == "incomplete":
        surface["observed_pairs"] = 2
    else:
        surface["raw_banner"] = "private-never-publish"
        assert "private-never-publish" not in json.dumps(ReportDocument.from_mapping(raw).metadata())
        return
    with pytest.raises(ReportError):
        ReportDocument.from_mapping(raw)


@pytest.mark.parametrize(
    "payload", [b'{"schema":"a","schema":"b"}', b'{"score":NaN}', b"\xff", b"{} garbage", b"[" * 2000 + b"]" * 2000]
)
def test_invalid_json_is_report_error(payload: bytes) -> None:
    """Duplicate keys, non-finite values, encoding and nesting never become partial reports."""
    with pytest.raises(ReportError):
        load_stream(io.BytesIO(payload))


def test_input_depth_size_and_file_kind_bounds(tmp_path: Path) -> None:
    """Local inputs cannot wait on a FIFO, follow a symlink or allocate unbounded data."""
    with pytest.raises(ReportError):
        load_stream(io.BytesIO(b" " * (MAX_INPUT_BYTES + 1)))
    raw = report_result().to_dict()
    nested: dict[str, object] = {}
    for _ in range(25):
        nested = {"child": nested}
    raw["extension"] = nested
    with pytest.raises(ReportError):
        load_stream(io.BytesIO(json.dumps(raw).encode()))
    source = tmp_path / "source.json"
    source.write_text(json.dumps(report_result().to_dict()))
    link = tmp_path / "linked.json"
    link.symlink_to(source)
    with pytest.raises(ReportError):
        load_result(link)
    with pytest.raises(ReportError):
        load_result(tmp_path)
    assert load_result(source).scan_id == str(report_result().scan_id)


def test_snapshot_does_not_change_with_mutated_original_data() -> None:
    """The immutable copy remains consistent across all subsequently rendered formats."""
    result = report_result()
    original = copy.deepcopy(result)
    document = ReportDocument.from_result(result)
    result.findings.clear()
    result.operation_counts["HTTP"] = 999
    assert len(document.findings) == len(original.findings) == 1
    assert dict(document.operations)["HTTP"] == 1
