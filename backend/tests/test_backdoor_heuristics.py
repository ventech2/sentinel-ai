from pathlib import Path
from decimal import Decimal

from app.detectors.backdoor_heuristics import scan_repository

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "backdoor_heuristics_repo"


def test_detects_hardcoded_ip_and_isolated_domain_destinations() -> None:
    findings = scan_repository(FIXTURE_ROOT)
    network_findings = [finding for finding in findings if finding.category == "suspicious_outbound_connection"]

    raw_ip_findings = [
        finding for finding in network_findings if finding.title == "Hardcoded IP address used for outbound connection"
    ]

    assert len(raw_ip_findings) == 2
    assert any(finding.title == "Isolated hardcoded outbound domain" for finding in network_findings)


def test_detects_suspicious_postinstall_script() -> None:
    findings = scan_repository(FIXTURE_ROOT)
    script_findings = [finding for finding in findings if finding.category == "suspicious_install_script"]

    assert len(script_findings) == 1
    assert script_findings[0].file_path == "package.json"
    assert script_findings[0].confidence == Decimal("0.86")
