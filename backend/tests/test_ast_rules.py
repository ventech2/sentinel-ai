from pathlib import Path

from app.detectors.ast_rules import scan_repository

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "ast_repo"


def test_detects_obfuscated_dynamic_execution_and_hardcoded_auth_comparisons() -> None:
    findings = scan_repository(FIXTURE_ROOT)

    dynamic_findings = [finding for finding in findings if finding.category == "obfuscated_dynamic_execution"]
    assert len(dynamic_findings) == 4
    assert any(finding.category == "hardcoded_auth_bypass" for finding in findings)
    assert any(finding.title == "Shell command execution fed by decoded or external data" for finding in findings)
