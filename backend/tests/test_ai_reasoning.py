import json
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

from app.detectors.models import DetectorFinding
from app.reasoning.ai_reasoning import AIReasoningLayer


@dataclass
class FakeResponses:
    output_text: str
    request: dict | None = None

    def create(self, **kwargs):
        self.request = kwargs
        return SimpleNamespace(output_text=self.output_text)


@dataclass
class FakeOpenAIClient:
    responses: FakeResponses


@dataclass
class FakeGeminiModels:
    output_text: str
    request: dict | None = None

    def generate_content(self, **kwargs):
        self.request = kwargs
        return SimpleNamespace(text=self.output_text)


@dataclass
class FakeGeminiClient:
    models: FakeGeminiModels


class DeadlineExceededError(Exception):
    code = 504
    status = "DEADLINE_EXCEEDED"


class ResourceExhaustedError(Exception):
    code = 429
    status = "RESOURCE_EXHAUSTED"


class TimeoutThenFailingGeminiModels:
    def __init__(self) -> None:
        self.call_count = 0

    def generate_content(self, **kwargs):
        self.call_count += 1
        if self.call_count == 1:
            raise DeadlineExceededError("deadline exceeded")
        raise RuntimeError("second request failed")


class RateLimitedThenSuccessfulGeminiModels:
    def __init__(self, output_text: str) -> None:
        self.output_text = output_text
        self.call_count = 0

    def generate_content(self, **kwargs):
        self.call_count += 1
        if self.call_count == 1:
            raise ResourceExhaustedError("quota temporarily exhausted")
        return SimpleNamespace(text=self.output_text)


def _finding() -> DetectorFinding:
    return DetectorFinding(
        detector="secret_scan",
        category="hardcoded_secret",
        severity="high",
        confidence=Decimal("0.50"),
        file_path="app.py",
        line_start=3,
        line_end=3,
        code_snippet='API_KEY = "example"',
        title="Hardcoded API key",
        description="An API key is stored in source code.",
    )


def test_enriches_existing_finding_from_mocked_structured_response(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("one\ntwo\nAPI_KEY = 'example'\nfour\nfive\n", encoding="utf-8")
    response = {
        "severity": "critical",
        "confidence": 0.91,
        "explanation": "The credential is committed in application source and can be copied by repository readers.",
        "fix_suggestion": "Move it to a secret manager, load it through configuration, and rotate it.",
        "exploitability_notes": "Risk is highest when the repository is public or shared with untrusted collaborators.",
    }
    fake_responses = FakeResponses(json.dumps(response))
    layer = AIReasoningLayer(provider="openai", model="gpt-5.6", client=FakeOpenAIClient(fake_responses))

    enriched = layer.enrich_finding(_finding(), tmp_path)

    assert enriched.detector == "secret_scan"
    assert enriched.category == "hardcoded_secret"
    assert enriched.file_path == "app.py"
    assert enriched.severity == "critical"
    assert enriched.confidence == Decimal("0.91")
    assert enriched.ai_explanation == (
        "The credential is committed in application source and can be copied by repository readers.\n\n"
        "Exploitability notes: Risk is highest when the repository is public or shared with untrusted collaborators."
    )
    assert enriched.fix_suggestion.startswith("Move it to a secret manager")
    assert fake_responses.request["model"] == "gpt-5.6"
    assert fake_responses.request["text"]["format"]["type"] == "json_schema"
    assert "    3: API_KEY = 'example'" in fake_responses.request["input"][1]["content"]


def test_invalid_or_failed_ai_response_keeps_static_finding_unchanged(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text("one\ntwo\nAPI_KEY = 'example'\n", encoding="utf-8")
    finding = _finding()
    layer = AIReasoningLayer(
        provider="openai",
        model="gpt-5.6",
        client=FakeOpenAIClient(FakeResponses("not JSON")),
    )

    unchanged = layer.enrich_finding(finding, tmp_path)

    assert unchanged is finding
    assert "response validation failed" in capsys.readouterr().err


def test_enriches_finding_from_mocked_gemini_response(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("one\ntwo\nAPI_KEY = 'example'\n", encoding="utf-8")
    response = {
        "severity": "medium",
        "confidence": 0.60,
        "explanation": "The static credential is a risk when the source is exposed.",
        "fix_suggestion": "Load a rotated credential from a secret manager.",
        "exploitability_notes": "An attacker needs access to the repository or deployed artifact.",
    }
    fake_models = FakeGeminiModels(json.dumps(response))
    layer = AIReasoningLayer(
        provider="gemini",
        client=FakeGeminiClient(fake_models),
        gemini_min_request_interval_seconds=0,
    )

    enriched = layer.enrich_finding(_finding(), tmp_path)

    assert enriched.ai_explanation is not None
    assert enriched.severity == "medium"
    assert enriched.confidence == Decimal("0.50")
    assert fake_models.request["model"] == "gemini-3-flash-preview"
    assert fake_models.request["config"].response_mime_type == "application/json"
    assert fake_models.request["config"].response_json_schema["required"] == [
        "severity",
        "confidence",
        "explanation",
        "fix_suggestion",
        "exploitability_notes",
    ]


def test_gemini_transient_timeout_retries_once_then_falls_back(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text("one\ntwo\nAPI_KEY = 'example'\n", encoding="utf-8")
    models = TimeoutThenFailingGeminiModels()
    layer = AIReasoningLayer(
        provider="gemini",
        client=FakeGeminiClient(models),
        gemini_min_request_interval_seconds=0,
        gemini_max_retries=1,
        gemini_retry_initial_delay_seconds=0,
    )
    finding = _finding()

    unchanged = layer.enrich_finding(finding, tmp_path)

    assert unchanged is finding
    assert models.call_count == 2
    output = capsys.readouterr().err
    assert "DEADLINE_EXCEEDED" in output
    assert "retry 1 of 1" in output
    assert "second request failed" in output


def test_gemini_rate_limit_retries_then_enriches_finding(tmp_path: Path, capsys) -> None:
    (tmp_path / "app.py").write_text("one\ntwo\nAPI_KEY = 'example'\n", encoding="utf-8")
    response = {
        "severity": "high",
        "confidence": 0.80,
        "explanation": "The hardcoded credential can be copied from source control.",
        "fix_suggestion": "Rotate the key and load it from a secret manager.",
        "exploitability_notes": "Repository access is enough to expose the credential.",
    }
    models = RateLimitedThenSuccessfulGeminiModels(json.dumps(response))
    layer = AIReasoningLayer(
        provider="gemini",
        client=FakeGeminiClient(models),
        gemini_min_request_interval_seconds=0,
        gemini_max_retries=1,
        gemini_retry_initial_delay_seconds=0,
    )

    enriched = layer.enrich_finding(_finding(), tmp_path)

    assert models.call_count == 2
    assert enriched.ai_explanation is not None
    assert enriched.fix_suggestion == "Rotate the key and load it from a secret manager."
    assert "RESOURCE_EXHAUSTED" in capsys.readouterr().err
