from pathlib import Path

from app.detectors.dependency_auditor import scan_repository

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "dependency_repo"


def test_detects_typosquats_and_obscure_dependencies_across_supported_manifests() -> None:
    findings = scan_repository(FIXTURE_ROOT)

    typosquat_paths = {finding.file_path for finding in findings if finding.category == "typosquatted_dependency"}
    assert {"package.json", "requirements.txt", "go.mod"}.issubset(typosquat_paths)
    assert any(finding.category == "unrecognized_dependency" for finding in findings)
