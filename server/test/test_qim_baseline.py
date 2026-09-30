"""Tests for the QIM baseline watermarking method."""
from __future__ import annotations

from pathlib import Path
import pytest
import pymupdf

from qim_baseline import QIMBaseline
from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
)

SECRET = "Group 20 -> G07"
KEY = "unit-test-key"


def _make_pdf(pages: int = 3, lines: int = 45) -> bytes:
    """Build a text-heavy PDF with enough lines to carry a payload."""
    doc = pymupdf.open()
    for page_index in range(pages):
        page = doc.new_page()
        text = "\n".join(
            f"Page {page_index} line {i}: the quick brown fox jumps over the lazy dog."
            for i in range(lines)
        )
        page.insert_textbox(pymupdf.Rect(50, 50, 550, 780), text, fontsize=10)
    data = doc.tobytes(no_new_id=True)
    doc.close()
    return data


@pytest.fixture(scope="module")
def method() -> QIMBaseline:
    return QIMBaseline()


@pytest.fixture(scope="module")
def pdf() -> bytes:
    return _make_pdf()


@pytest.fixture(scope="module")
def watermarked(method: QIMBaseline, pdf: bytes) -> bytes:
    return method.add_watermark(pdf, secret=SECRET, key=KEY)


class TestApplicability:
    def test_applicable_to_text_heavy_pdf(self, method: QIMBaseline, pdf: bytes):
        assert method.is_watermark_applicable(pdf) is True

    def test_not_applicable_to_tiny_pdf(self, method: QIMBaseline):
        assert method.is_watermark_applicable(_make_pdf(pages=1, lines=3)) is False

    def test_not_applicable_to_garbage(self, method: QIMBaseline):
        assert method.is_watermark_applicable(b"%PDF-1.4\nnot really a pdf") is False


class TestRoundTrip:
    def test_secret_survives(self, method: QIMBaseline, watermarked: bytes):
        assert method.read_secret(watermarked, key=KEY) == SECRET

    def test_output_is_a_pdf(self, method: QIMBaseline, watermarked: bytes):
        assert watermarked.startswith(b"%PDF-")

    def test_accepts_a_path(self, method: QIMBaseline, watermarked: bytes, tmp_path: Path):
        path = tmp_path / "wm.pdf"
        path.write_bytes(watermarked)
        assert method.read_secret(path, key=KEY) == SECRET

    def test_unicode_secret(self, method: QIMBaseline, pdf: bytes):
        secret = "Grüße-Group-20"
        out = method.add_watermark(pdf, secret=secret, key=KEY)
        assert method.read_secret(out, key=KEY) == secret

    def test_deterministic(self, method: QIMBaseline, pdf: bytes):
        first = method.add_watermark(pdf, secret=SECRET, key=KEY)
        second = method.add_watermark(pdf, secret=SECRET, key=KEY)
        assert first == second


class TestSecurity:
    def test_wrong_key_rejected(self, method: QIMBaseline, watermarked: bytes):
        with pytest.raises(InvalidKeyError):
            method.read_secret(watermarked, key="not-the-key")

    def test_unwatermarked_pdf_raises(self, method: QIMBaseline, pdf: bytes):
        with pytest.raises((SecretNotFoundError, InvalidKeyError)):
            method.read_secret(pdf, key=KEY)

    def test_different_keys_give_different_output(self, method: QIMBaseline, pdf: bytes):
        a = method.add_watermark(pdf, secret=SECRET, key="key-a")
        b = method.add_watermark(pdf, secret=SECRET, key="key-b")
        assert a != b

    def test_empty_secret_rejected(self, method: QIMBaseline, pdf: bytes):
        with pytest.raises(ValueError):
            method.add_watermark(pdf, secret="", key=KEY)

    def test_empty_key_rejected(self, method: QIMBaseline, pdf: bytes):
        with pytest.raises(ValueError):
            method.add_watermark(pdf, secret=SECRET, key="")


class TestRobustness:
    def test_survives_a_resave(self, method: QIMBaseline, watermarked: bytes):
        """Re-saving the file in a PDF library must not destroy the mark."""
        doc = pymupdf.open(stream=watermarked, filetype="pdf")
        resaved = doc.tobytes(deflate=True)
        doc.close()
        assert method.read_secret(resaved, key=KEY) == SECRET

    def test_survives_appended_bytes(self, method: QIMBaseline, watermarked: bytes):
        assert method.read_secret(watermarked + b"\n% junk\n", key=KEY) == SECRET

    def test_survives_metadata_stripping(self, method: QIMBaseline, watermarked: bytes):
        doc = pymupdf.open(stream=watermarked, filetype="pdf")
        doc.set_metadata({})
        stripped = doc.tobytes(deflate=True)
        doc.close()
        assert method.read_secret(stripped, key=KEY) == SECRET

    def test_survives_losing_a_trailing_page(self, method: QIMBaseline):
        """Redundancy: with two or more copies embedded, truncation is survivable."""
        pdf = _make_pdf(pages=6)
        watermarked = method.add_watermark(pdf, secret=SECRET, key=KEY)
        doc = pymupdf.open(stream=watermarked, filetype="pdf")
        doc.delete_page(doc.page_count - 1)
        shortened = doc.tobytes(deflate=True)
        doc.close()
        assert method.read_secret(shortened, key=KEY) == SECRET

    def test_losing_a_leading_page_breaks_extraction(self, method: QIMBaseline):
        """Known limitation, asserted so a future change to it is deliberate.

        Repetitions are read at fixed offsets from the first carrier, so
        removing content from the *front* shifts every copy out of phase
        and the payload can no longer be located.
        """
        pdf = _make_pdf(pages=6)
        watermarked = method.add_watermark(pdf, secret=SECRET, key=KEY)
        doc = pymupdf.open(stream=watermarked, filetype="pdf")
        doc.delete_page(0)
        shifted = doc.tobytes(deflate=True)
        doc.close()
        with pytest.raises((SecretNotFoundError, InvalidKeyError)):
            method.read_secret(shifted, key=KEY)


class TestVisualIntegrity:
    def test_text_content_unchanged(self, method: QIMBaseline, pdf: bytes, watermarked: bytes):
        before = pymupdf.open(stream=pdf, filetype="pdf")
        after = pymupdf.open(stream=watermarked, filetype="pdf")
        try:
            assert before.page_count == after.page_count
            for i in range(before.page_count):
                assert before[i].get_text() == after[i].get_text()
        finally:
            before.close()
            after.close()

    def test_displacement_stays_below_one_point(
        self, method: QIMBaseline, pdf: bytes, watermarked: bytes
    ):
        before = pymupdf.open(stream=pdf, filetype="pdf")
        after = pymupdf.open(stream=watermarked, filetype="pdf")
        try:
            worst = 0.0
            for i in range(before.page_count):
                words_before = before[i].get_text("words")
                words_after = after[i].get_text("words")
                assert len(words_before) == len(words_after)
                for wb, wa in zip(words_before, words_after):
                    worst = max(worst, abs(wb[0] - wa[0]), abs(wb[1] - wa[1]))
            assert worst < 1.0
        finally:
            before.close()
            after.close()
