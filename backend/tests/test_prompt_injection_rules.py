from decimal import Decimal
from pathlib import Path

from app.detectors.prompt_injection_rules import scan_repository

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "prompt_injection_repo"


def test_detects_unsanitized_python_and_javascript_prompt_flows() -> None:
    findings = scan_repository(FIXTURE_ROOT)

    assert len(findings) == 3
    assert {finding.file_path for finding in findings} == {"unsafe_prompt.py", "unsafe_prompt.ts"}
    assert {finding.category for finding in findings} == {"prompt_injection_risk"}
    assert all(finding.detector == "prompt_injection_rules" for finding in findings)
    assert all(finding.severity == "medium" for finding in findings)
    assert all(Decimal("0.50") <= finding.confidence < Decimal("0.70") for finding in findings)
