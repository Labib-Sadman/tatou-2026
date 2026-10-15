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
            # The method guarantees at most one quantisation step (0.25pt).
            # A 1.0 tolerance is looser than the documented behaviour and lets
            # several _quantize mutations through; pin it to the real bound.
            assert worst <= method._STEP + 1e-9
        finally:
            before.close()
            after.close()


class TestCapacityBoundary:
    """Pin the applicability threshold.

    `is_watermark_applicable` returns True when the document offers at
    least `_LEN_BITS + 8 * 16 + _MAC_BITS` = 200 carriers (a 16-character
    secret is assumed, since the real secret is not passed in). The
    existing applicability tests use 6 and ~270 carriers, so they sit far
    either side of the boundary and pass under almost any threshold.
    These pin it exactly.
    """

    def test_exactly_at_the_threshold_is_applicable(self, method: QIMBaseline):
        pdf = _make_pdf(pages=2, lines=50)          # 200 carriers
        assert len(method._collect_carriers(pdf)) == 200
        assert method.is_watermark_applicable(pdf) is True

    def test_just_below_the_threshold_is_not_applicable(self, method: QIMBaseline):
        pdf = _make_pdf(pages=2, lines=49)          # 196 carriers
        assert len(method._collect_carriers(pdf)) == 196
        assert method.is_watermark_applicable(pdf) is False


class TestPayloadIntegrity:
    """The MAC must authenticate the ciphertext, not merely the key.

    Round-trip tests cannot see this: they encrypt and decrypt with the
    same code, so a MAC that ignores its message still agrees with
    itself. Only a test that compares MACs over *different* ciphertexts
    detects it.
    """

    def test_mac_depends_on_the_ciphertext(self, method: QIMBaseline):
        assert method._mac(b"ciphertext-AAAA", KEY) != method._mac(b"ciphertext-BBBB", KEY)

    def test_mac_depends_on_the_key(self, method: QIMBaseline):
        assert method._mac(b"ciphertext", "key-a") != method._mac(b"ciphertext", "key-b")

    def test_mac_is_truncated_to_the_declared_length(self, method: QIMBaseline):
        assert len(method._mac(b"ciphertext", KEY)) == method._MAC_BITS // 8


class TestKeystream:
    """A secret longer than one SHA-256 block must still round-trip.

    Every other test uses a secret under 32 bytes, which fits in the
    first keystream block, so the loop that appends further blocks is
    never exercised.
    """

    def test_secret_longer_than_one_keystream_block(self, method: QIMBaseline):
        secret = "L" * 60                            # > 32-byte block
        pdf = _make_pdf(pages=7, lines=40)   # 560 carriers; payload needs 552
        out = method.add_watermark(pdf, secret=secret, key=KEY)
        assert method.read_secret(out, key=KEY) == secret

    def test_keystream_is_as_long_as_the_data(self, method: QIMBaseline):
        data = b"x" * 100
        assert len(method._xor_keystream(data, KEY)) == len(data)

    def test_keystream_is_its_own_inverse(self, method: QIMBaseline):
        data = b"round-trip me" * 5
        assert method._xor_keystream(method._xor_keystream(data, KEY), KEY) == data


class TestPayloadLimits:
    def test_secret_at_the_byte_limit_is_accepted(self, method: QIMBaseline):
        method._build_payload_bits("x" * 255, KEY)   # must not raise

    def test_secret_over_the_byte_limit_is_rejected(self, method: QIMBaseline):
        with pytest.raises(ValueError):
            method._build_payload_bits("x" * 256, KEY)

    def test_payload_bit_length_matches_the_format(self, method: QIMBaseline):
        secret = "sixteen-char-sec"
        bits = method._build_payload_bits(secret, KEY)
        expected = method._LEN_BITS + 8 * len(secret.encode()) + method._MAC_BITS
        assert len(bits) == expected


class TestMajorityVote:
    """The per-bit majority vote is never exercised with disagreeing copies."""

    def test_majority_of_three_wins(self, method: QIMBaseline):
        # three repetitions of a 2-bit payload; bit 0 is 1,1,0 -> 1
        bits = [1, 0,  1, 0,  0, 0]
        assert method._majority_vote(bits, 2) == [1, 0]

    def test_minority_loses(self, method: QIMBaseline):
        bits = [1, 0,  0, 0,  0, 0]
        assert method._majority_vote(bits, 2) == [0, 0]

    def test_an_exact_tie_resolves_to_zero(self, method: QIMBaseline):
        """Two repetitions disagreeing: strict majority means 0 wins.

        Pins the comparison as `ones * 2 > repetitions`, not `>=`.
        """
        assert method._majority_vote([1, 0], 1) == [0]

    def test_a_tie_over_four_repetitions_resolves_to_zero(self, method: QIMBaseline):
        """Pins the multiplier: `ones * 3 > repetitions` would return 1 here."""
        assert method._majority_vote([1, 1, 0, 0], 1) == [0]


class TestKnownAnswers:
    """Fixed vectors for the key-derived keystream and the MAC.

    Round-trip tests cannot detect a change that alters encryption and
    decryption identically - a different counter start, a different
    counter width, a different block boundary - because the mutated code
    still agrees with itself. These vectors pin the actual bytes, so the
    scheme stays interoperable with any independent implementation of
    the documented format.

    Regenerate deliberately, never by pasting whatever the code now
    emits: a changed vector means the on-the-wire format changed and
    every watermark already issued becomes unreadable.
    """

    KEY = "known-answer-key"

    def test_keystream_vector(self, method: QIMBaseline):
        expected = bytes.fromhex(
            "24ea275839de8550e04eec29a440565d"
            "22f86ca2daaa95e7cb06f7bdb8cde376"
            "9e22a817785366da501835ed8d2d67eb"
        )
        assert method._xor_keystream(b"\x00" * 48, self.KEY) == expected

    def test_mac_vector(self, method: QIMBaseline):
        assert method._mac(b"fixed-ciphertext", self.KEY) == bytes.fromhex("9a31cdd05099f387")
