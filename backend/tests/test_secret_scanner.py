from pathlib import Path

from app.detectors.secret_scanner import scan_repository

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "secret_repo"


def test_detects_entropy_and_signature_secrets_without_scanning_node_modules() -> None:
    findings = scan_repository(FIXTURE_ROOT)

    assert any(finding.title == "High-entropy secret assignment" for finding in findings)
    assert any("AWS access key" in finding.title for finding in findings)
    assert all("node_modules" not in finding.file_path for finding in findings)


def test_skips_binary_files(tmp_path: Path) -> None:
    (tmp_path / "credential.bin").write_bytes(b"\x00AKIA1234567890ABCDEF")

    assert scan_repository(tmp_path) == []
