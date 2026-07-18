from pathlib import Path

from app.detectors.config_auditor import scan_repository

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "config_repo"


def test_detects_debug_cors_and_unignored_environment_file() -> None:
    findings = scan_repository(FIXTURE_ROOT)

    titles = {finding.title for finding in findings}
    assert "Debug mode enabled in configuration" in titles
    assert "Wildcard CORS origin configured" in titles
    assert "Environment file is committed without .gitignore coverage" in titles


def test_detects_inline_debug_and_cors_in_application_source() -> None:
    findings = scan_repository(FIXTURE_ROOT)
    application_findings = [finding for finding in findings if finding.file_path == "app.py"]

    assert {finding.title for finding in application_findings} == {
        "Debug mode enabled in configuration",
        "Wildcard CORS origin configured",
    }
