from __future__ import annotations

import json
from pathlib import Path

import pytest

from knowledge_index.config import AppConfig, PipelineConfig
from knowledge_index.pipeline import converters


class _Response:
    """The narrow slice of httpx.Response that _convert_docling reads."""

    status_code = 200
    text = ""

    @staticmethod
    def json() -> dict:
        return {
            "status": "success",
            "document": {"text_content": "Pozew o zapłatę."},
        }

    def raise_for_status(self) -> None:
        return None


@pytest.fixture
def posted(monkeypatch) -> dict:
    """Capture the form Docling Serve is called with, without calling it."""
    captured: dict = {}

    def fake_post(url, *, files, data, timeout):
        captured["url"] = url
        captured["data"] = data
        return _Response()

    monkeypatch.setattr(converters.httpx, "post", fake_post)
    return captured


def _convert(config: AppConfig, tmp_path: Path) -> None:
    scan = tmp_path / "pozew.pdf"
    scan.write_bytes(b"%PDF-1.4 scanned filing")
    converters.convert_document(
        scan, name=scan.name, mime_type="application/pdf", config=config
    )


def test_the_deployments_ocr_languages_reach_docling(posted, tmp_path) -> None:
    """A jurisdiction outside de/en has to be able to say so. Before this was a
    setting the pair was compiled in, and a Polish scan was OCR'd with the German
    and English models — which does not fail, it returns confident nonsense that
    the rest of the pipeline then classifies, types and embeds."""
    config = AppConfig(pipeline=PipelineConfig(ocr_languages=["pl", "en"]))

    _convert(config, tmp_path)

    assert posted["data"]["ocr_lang"] == ["pl", "en"]


def test_the_default_stays_the_pair_the_appliance_shipped_with(posted, tmp_path) -> None:
    """Existing deployments must not silently change model set on upgrade."""
    _convert(AppConfig(), tmp_path)

    assert posted["data"]["ocr_lang"] == ["de", "en"]
    assert posted["data"]["ocr_engine"] == "easyocr"


def test_languages_are_normalized_and_deduplicated() -> None:
    """Casing and stray whitespace come from hand-edited config and environment
    variables; easyocr matches its model names exactly."""
    config = PipelineConfig(ocr_languages=[" PL ", "en", "pl"])

    assert config.ocr_languages == ["pl", "en"]


@pytest.mark.parametrize("value", [[], [""], ["  "]])
def test_an_empty_language_set_is_refused(value: list[str]) -> None:
    """Silently falling back to a default here would OCR the estate in the wrong
    language and report success."""
    with pytest.raises(ValueError):
        PipelineConfig(ocr_languages=value)


def test_the_environment_can_pin_the_language_set(monkeypatch) -> None:
    """`KI_PIPELINE__OCR_LANGUAGES`, like every other scalar under pipeline.*."""
    monkeypatch.setenv("KI_PIPELINE__OCR_LANGUAGES", json.dumps(["pl", "de", "en"]))

    assert AppConfig().pipeline.ocr_languages == ["pl", "de", "en"]
