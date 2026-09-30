"""qim_baseline.py

Watermarking method that hides a payload in the vertical baseline
positions of text lines, using Quantization Index Modulation (QIM).

Idea
----
Every line of text in a PDF is placed by a text-matrix operator in the
page's content stream::

    a b c d e f Tm

where ``f`` is the vertical position (the baseline) of that line. The
exact value carries no meaning to a reader: moving a line by a fraction
of a point is invisible, but it is a number we fully control.

This method *quantizes* each of those numbers onto a grid of step
``_STEP`` points and uses the parity of the grid index to carry one bit:

- bit 0  ->  the coordinate is snapped to an **even** multiple of the step
- bit 1  ->  the coordinate is snapped to an **odd** multiple of the step

Both the horizontal start position (``e``) and the baseline (``f``) of
every line are used, so each line of text carries two bits.

Reading the watermark back therefore needs no access to the original
document: divide each baseline by the step, round to the nearest
integer, and look at whether that integer is even or odd. This is the
standard QIM trick, and it is the reason the method works at all -- a
scheme based on *relative* shifts would require the original file for
comparison, which the owner of a leaked document does not have.

Because the largest correction is one full step (``0.25 pt``, i.e. about
0.09 mm), the visual result is indistinguishable from the original.

Payload format
--------------
The embedded bit string is::

    [ 8 bits: length of ciphertext in bytes ]
    [ 8 * L bits: ciphertext                ]
    [ 64 bits: truncated HMAC-SHA256        ]

The secret is encrypted with a keystream derived from ``key`` (so a
recipient cannot read who else the document was issued to), and the
ciphertext is authenticated with an HMAC truncated to 64 bits (so
nobody can forge or alter a watermark without the key).

The payload is repeated over as many lines as the document offers, and
extraction takes a per-bit majority vote over the repetitions. A
document that loses or gains a few lines can therefore still be
attributed.

Limitations
-----------
The watermark lives in the content stream, so any tool that *rewrites*
content streams from scratch (Ghostscript, "optimise PDF" functions,
print-to-PDF, rasterisation) destroys it. It survives copying, renaming,
appending, incremental updates, metadata stripping and -- given at least
two embedded repetitions -- truncation at the end of the document.

Repetitions are read at fixed offsets from the first carrier, so removing
or inserting content at the *front* of the document shifts every copy out
of phase and defeats extraction. A self-synchronising framing (a marker
pattern before each repetition) would close that gap.
"""
from __future__ import annotations

from typing import Final, List, Tuple
import hashlib
import hmac
import re

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)

import pymupdf


# Matches "a b c d e f Tm"; group 6 is the vertical baseline position.
_TM_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+"
    rb"(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+(-?\d+(?:\.\d+)?)\s+Tm"
)


class QIMBaseline(WatermarkingMethod):
    """Embed a secret in the parity of quantized text-line baselines."""

    name: Final[str] = "qim-baseline"

    #: Quantization step in PDF points. Must divide exactly in binary so
    #: that the written decimal representation round-trips without error.
    _STEP: Final[float] = 0.25

    #: Domain separation for the two key derivations.
    _MAC_CONTEXT: Final[bytes] = b"wm:qim-baseline:v1:mac"
    _ENC_CONTEXT: Final[bytes] = b"wm:qim-baseline:v1:enc"

    _MAC_BITS: Final[int] = 64
    _LEN_BITS: Final[int] = 8

    # ------------------------------------------------------------------
    # Interface
    # ------------------------------------------------------------------

    @staticmethod
    def get_usage() -> str:
        return (
            "Hides the secret in the parity of quantized text-line baseline "
            "positions (QIM, step 0.25pt). Invisible to the reader and "
            "readable without the original document. Requires a PDF with "
            "enough text lines: roughly (8 * len(secret) + 72) / 2 lines for "
            "a single copy of the payload, repeated as often as it fits. "
            "The 'position' parameter is ignored."
        )

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        """True when the document has enough text lines for one payload.

        A secret of up to 16 characters is assumed here, since the actual
        secret is not passed to this method.
        """
        try:
            data = load_pdf_bytes(pdf)
            carriers = self._collect_carriers(data)
        except Exception:
            return False
        return len(carriers) >= self._LEN_BITS + 8 * 16 + self._MAC_BITS

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        bits = self._build_payload_bits(secret, key)

        try:
            doc = pymupdf.open(stream=data, filetype="pdf")
        except Exception as exc:
            raise WatermarkingError("Could not open the PDF") from exc

        try:
            written = 0
            for page in doc:
                for xref in page.get_contents():
                    stream = doc.xref_stream(xref)
                    if not stream:
                        continue
                    new_stream, used = self._rewrite_stream(stream, bits, written)
                    if used:
                        doc.update_stream(xref, new_stream)
                        written += used

            if written < len(bits):
                raise WatermarkingError(
                    f"Document offers only {written} carriers, but the "
                    f"payload needs {len(bits)}"
                )

            out = doc.tobytes(deflate=True, garbage=0, no_new_id=True)
        finally:
            doc.close()

        return out

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        bits = self._collect_carriers(data)
        min_len = self._LEN_BITS + self._MAC_BITS
        if len(bits) < min_len:
            raise SecretNotFoundError("Too few carriers to hold a watermark")

        length = self._bits_to_int(bits[: self._LEN_BITS])
        payload_len = self._LEN_BITS + 8 * length + self._MAC_BITS
        if length == 0 or payload_len > len(bits):
            raise SecretNotFoundError("No plausible watermark payload found")

        voted = self._majority_vote(bits, payload_len)

        body = self._bits_to_bytes(voted[self._LEN_BITS:])
        ciphertext = body[:length]
        mac = body[length: length + self._MAC_BITS // 8]

        expected = self._mac(ciphertext, key)
        if not hmac.compare_digest(mac, expected):
            raise InvalidKeyError(
                "Watermark did not authenticate: wrong key, or no watermark present"
            )

        plaintext = self._xor_keystream(ciphertext, key)
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WatermarkingError("Recovered secret is not valid UTF-8") from exc

    # ------------------------------------------------------------------
    # Payload construction
    # ------------------------------------------------------------------

    def _build_payload_bits(self, secret: str, key: str) -> List[int]:
        plaintext = secret.encode("utf-8")
        if len(plaintext) > 255:
            raise ValueError("Secret must encode to at most 255 bytes")

        ciphertext = self._xor_keystream(plaintext, key)
        mac = self._mac(ciphertext, key)

        bits: List[int] = []
        bits += self._int_to_bits(len(ciphertext), self._LEN_BITS)
        bits += self._bytes_to_bits(ciphertext)
        bits += self._bytes_to_bits(mac)
        return bits

    def _mac(self, ciphertext: bytes, key: str) -> bytes:
        """Truncated HMAC-SHA256 over the ciphertext."""
        full = hmac.new(
            key.encode("utf-8"), self._MAC_CONTEXT + ciphertext, hashlib.sha256
        ).digest()
        return full[: self._MAC_BITS // 8]

    def _xor_keystream(self, data: bytes, key: str) -> bytes:
        """Encrypt/decrypt with a deterministic key-derived keystream.

        The keystream is SHA256(key || context || counter) for counter =
        0, 1, 2, ... XORed onto the data. Deterministic by design: the
        interface requires identical output for identical inputs, which
        rules out a random nonce.
        """
        key_bytes = key.encode("utf-8")
        stream = bytearray()
        counter = 0
        while len(stream) < len(data):
            block = hashlib.sha256(
                key_bytes + self._ENC_CONTEXT + counter.to_bytes(4, "big")
            ).digest()
            stream += block
            counter += 1
        return bytes(b ^ s for b, s in zip(data, stream))

    # ------------------------------------------------------------------
    # Carrier handling
    # ------------------------------------------------------------------

    def _collect_carriers(self, data: bytes) -> List[int]:
        """Return the bits carried by every text line, in document order.

        Each line contributes two bits: one from its horizontal start
        position and one from its baseline, in that order.
        """
        doc = pymupdf.open(stream=data, filetype="pdf")
        try:
            bits: List[int] = []
            for page in doc:
                for xref in page.get_contents():
                    stream = doc.xref_stream(xref)
                    if not stream:
                        continue
                    for match in _TM_RE.finditer(stream):
                        for group in (5, 6):
                            value = float(match.group(group))
                            bits.append(int(round(value / self._STEP)) & 1)
            return bits
        finally:
            doc.close()

    def _rewrite_stream(
        self, stream: bytes, bits: List[int], offset: int
    ) -> Tuple[bytes, int]:
        """Quantize every baseline in ``stream`` to carry the next bits.

        Returns the new stream and the number of carriers consumed.
        ``offset`` is how many carriers earlier streams already used, so
        that the payload continues seamlessly across pages.
        """
        used = 0
        out = bytearray()
        last = 0

        for match in _TM_RE.finditer(stream):
            for group in (5, 6):
                bit = bits[(offset + used) % len(bits)]
                value = float(match.group(group))

                out += stream[last: match.start(group)]
                out += self._format_number(self._quantize(value, bit))
                last = match.end(group)
                used += 1

        out += stream[last:]
        return bytes(out), used

    def _quantize(self, y: float, bit: int) -> float:
        """Snap ``y`` to the nearest grid multiple whose parity is ``bit``."""
        k = int(round(y / self._STEP))
        if (k & 1) != bit:
            # Move to whichever neighbouring index is closer to the original.
            k = k + 1 if y / self._STEP > k else k - 1
        return k * self._STEP

    @staticmethod
    def _format_number(value: float) -> bytes:
        """Render a quantized value exactly, without scientific notation."""
        text = f"{value:.2f}".rstrip("0").rstrip(".")
        return (text or "0").encode("ascii")

    # ------------------------------------------------------------------
    # Bit helpers
    # ------------------------------------------------------------------

    def _majority_vote(self, bits: List[int], payload_len: int) -> List[int]:
        """Combine every full repetition of the payload by majority vote."""
        repetitions = len(bits) // payload_len
        voted: List[int] = []
        for i in range(payload_len):
            ones = sum(bits[i + r * payload_len] for r in range(repetitions))
            voted.append(1 if ones * 2 > repetitions else 0)
        return voted

    @staticmethod
    def _int_to_bits(value: int, width: int) -> List[int]:
        return [(value >> (width - 1 - i)) & 1 for i in range(width)]

    @staticmethod
    def _bits_to_int(bits: List[int]) -> int:
        value = 0
        for bit in bits:
            value = (value << 1) | bit
        return value

    @staticmethod
    def _bytes_to_bits(data: bytes) -> List[int]:
        return [(byte >> (7 - i)) & 1 for byte in data for i in range(8)]

    @staticmethod
    def _bits_to_bytes(bits: List[int]) -> bytes:
        usable = len(bits) - (len(bits) % 8)
        return bytes(
            sum(bits[i + j] << (7 - j) for j in range(8))
            for i in range(0, usable, 8)
        )


__all__ = ["QIMBaseline"]
