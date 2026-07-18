"""Manually enrich three actual demo findings with the configured AI provider.

Run from the backend directory after setting GEMINI_API_KEY (or the configured
provider's key) in the environment or backend/.env:
    python scripts/sanity_check_ai_reasoning.py
"""

from dataclasses import asdict
from decimal import Decimal
import json
from pathlib import Path
import sys

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import get_settings
from app.detectors import ast_rules, config_auditor, secret_scanner
from app.reasoning.ai_reasoning import AIReasoningLayer


def _json_default(value: object) -> str:
    if isinstance(value, Decimal):
        return str(value)
    raise TypeError(f"Cannot serialize {type(value)!r}")


def main() -> None:
    settings = get_settings()
    if not settings.gemini_api_key and not settings.openai_api_key:
        raise SystemExit("Set GEMINI_API_KEY or OPENAI_API_KEY in the environment or backend/.env before running this script.")

    demo_root = BACKEND_ROOT / "sample-data" / "vulnerable-demo-app"
    static_findings = [
        secret_scanner.scan_repository(demo_root)[0],
        next(finding for finding in config_auditor.scan_repository(demo_root) if finding.file_path == "app/main.py"),
        next(finding for finding in ast_rules.scan_repository(demo_root) if finding.category == "hardcoded_auth_bypass"),
    ]
    layer = AIReasoningLayer.from_settings()
    print(f"AI provider: {layer.provider_name}; model: {layer.model}", file=sys.stderr)
    enriched = layer.enrich_findings(static_findings, demo_root)

    print(json.dumps([asdict(finding) for finding in enriched], indent=2, default=_json_default))


if __name__ == "__main__":
    main()
