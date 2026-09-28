"""encrypted_metadata.py

Watermarking method that embeds an AES-256-GCM encrypted, authenticated
secret into a custom key of the PDF's /Info dictionary, using PyMuPDF to
make a structurally valid edit to the actual PDF object graph.

Unlike the toy methods in this codebase (which append raw bytes after the
final %%EOF marker), this method embeds the watermark inside real PDF
structure. Unlike ``add_after_eof`` (which only base64-encodes the secret,
providing no confidentiality), this method actually encrypts the secret:
AES-256-GCM gives authenticated encryption, so both confidentiality and
integrity/authenticity are provided by a single, well-vetted primitive
(no separate HMAC needed).

Key derivation: the caller-supplied ``key`` string is stretched into a
256-bit AES key via PBKDF2-HMAC-SHA256 with a random per-watermark salt,
so the same key string never produces the same key material twice.

Author: Labib Sadman (individual Phase I watermarking method)
"""
from __future__ import annotations

from typing import Final
import base64
import hashlib
import os

import fitz  # PyMuPDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from watermarking_method import (
    InvalidKeyError,
    PdfSource,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class EncryptedMetadataWatermark(WatermarkingMethod):
    """Embeds an AES-256-GCM encrypted secret in the PDF's /Info dictionary."""

    name: Final[str] = "encrypted-metadata"

    _INFO_KEY: Final[str] = "TatouWM"
    _PBKDF2_ITERATIONS: Final[int] = 200_000
    _SALT_LEN: Final[int] = 16
    _NONCE_LEN: Final[int] = 12

    @staticmethod
    def get_usage() -> str:
        return (
            "Embeds an AES-256-GCM encrypted, authenticated secret into a "
            "custom key ('TatouWM') of the PDF's /Info dictionary. "
            "Position is ignored."
        )

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

        salt = os.urandom(self._SALT_LEN)
        nonce = os.urandom(self._NONCE_LEN)
        aes_key = self._derive_key(key, salt)

        ciphertext = AESGCM(aes_key).encrypt(nonce, secret.encode("utf-8"), None)
        payload = base64.urlsafe_b64encode(salt + nonce + ciphertext).decode("ascii")

        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception as exc:
            raise WatermarkingError(f"Failed to open PDF: {exc}") from exc

        try:
            info_xref = self._ensure_info_xref(doc)
            doc.xref_set_key(info_xref, self._INFO_KEY, f"({payload})")
            out = doc.tobytes()
        except Exception as exc:
            raise WatermarkingError(f"Failed to embed watermark: {exc}") from exc
        finally:
            doc.close()

        return out

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        try:
            data = load_pdf_bytes(pdf)
            doc = fitz.open(stream=data, filetype="pdf")
            doc.close()
            return True
        except Exception:
            return False

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception as exc:
            raise WatermarkingError(f"Failed to open PDF: {exc}") from exc

        try:
            info_xref = self._get_info_xref(doc)
            raw = doc.xref_get_key(info_xref, self._INFO_KEY) if info_xref else None
        finally:
            doc.close()

        if not raw or raw[0] == "null" or not raw[1]:
            raise SecretNotFoundError("No watermark found in PDF metadata")

        value = raw[1]
        if value.startswith("(") and value.endswith(")"):
            value = value[1:-1]

        try:
            blob = base64.urlsafe_b64decode(value.encode("ascii"))
        except Exception as exc:
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if len(blob) < self._SALT_LEN + self._NONCE_LEN:
            raise SecretNotFoundError("Malformed watermark payload")

        salt = blob[: self._SALT_LEN]
        nonce = blob[self._SALT_LEN : self._SALT_LEN + self._NONCE_LEN]
        ciphertext = blob[self._SALT_LEN + self._NONCE_LEN :]

        aes_key = self._derive_key(key, salt)

        try:
            plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise InvalidKeyError(
                "Provided key failed to decrypt/authenticate the watermark"
            ) from exc

        return plaintext.decode("utf-8")

    # ---------------------
    # Internal helpers
    # ---------------------

    @staticmethod
    def _derive_key(key: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            key.encode("utf-8"),
            salt,
            EncryptedMetadataWatermark._PBKDF2_ITERATIONS,
            dklen=32,
        )

    @staticmethod
    def _get_info_xref(doc: "fitz.Document") -> int | None:
        raw = doc.xref_get_key(-1, "Info")
        if not raw or raw[0] != "xref":
            return None
        xref_str = raw[1].split()[0]
        return int(xref_str)

    @classmethod
    def _ensure_info_xref(cls, doc: "fitz.Document") -> int:
        xref = cls._get_info_xref(doc)
        if xref is not None:
            return xref
        # No /Info dict exists yet; force PyMuPDF to create one.
        doc.set_metadata(doc.metadata or {})
        xref = cls._get_info_xref(doc)
        if xref is None:
            raise WatermarkingError("Could not create /Info dictionary on PDF")
        return xref


__all__ = ["EncryptedMetadataWatermark"]
