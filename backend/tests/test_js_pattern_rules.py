from pathlib import Path

from app.detectors.js_pattern_rules import scan_repository

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "js_rules_repo"


def test_detects_dynamic_execution_and_hardcoded_auth_patterns_in_js_and_ts() -> None:
    findings = scan_repository(FIXTURE_ROOT)

    dynamic_findings = [finding for finding in findings if finding.category == "obfuscated_dynamic_execution"]
    auth_findings = [finding for finding in findings if finding.category == "hardcoded_auth_bypass"]

    assert len(dynamic_findings) == 2
    assert len(auth_findings) == 2
    assert {finding.file_path for finding in findings} == {"backdoor.js", "auth.ts"}
