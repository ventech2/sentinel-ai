from pathlib import Path

from app.detectors.model_security_rules import scan_repository

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "model_security_repo"


def test_detects_unsafe_model_deserialization_and_accepts_weights_only() -> None:
    findings = scan_repository(FIXTURE_ROOT)

    assert {finding.line_start for finding in findings} == {7, 8, 9, 10}
    assert {finding.category for finding in findings} == {"unsafe_model_deserialization"}
    assert all(finding.detector == "model_security_rules" for finding in findings)
    assert any(finding.title == "Unsafe pickle deserialization" and finding.confidence >= 0.90 for finding in findings)
    assert all(finding.line_start != 11 for finding in findings)
