"""rmap_routes.py

RMAP (Roger Michael Authentication Protocol) endpoints for Tatou.

Two routes are registered:

``POST /api/rmap-initiate``
    Accepts RMAP Message 1 and returns Response 1.

``POST /api/rmap-get-link``
    Accepts RMAP Message 2. On success it creates a watermarked copy of
    the group's assigned confidential document, individually marked for
    the authenticated identity, records it in the Versions table, and
    only then returns Response 2 containing the link.

The watermarked version is registered under the RMAP session link, so a
successful handshake hands the client a link that the existing
``GET /api/get-version/<link>`` route can serve.

Configuration (environment variables)
-------------------------------------
``RMAP_SERVER_PRIV``     path to the server's OpenPGP private key (.asc)
``RMAP_SERVER_PUB``      path to the server's OpenPGP public key (.asc)
``RMAP_CLIENT_KEYS_DIR`` directory of client public keys, one per
                         identity, named ``<Identity>.asc``
``RMAP_PASSPHRASE``      passphrase for the private key, if protected
``RMAP_LINK_PREFIX``     prefix prepended to the link sent to the client
``RMAP_DOCUMENT_ID``     id of the document to distribute, or
``RMAP_DOCUMENT_NAME``   its name, if no id is given
``RMAP_METHOD``          watermarking method name
``RMAP_KEY``             watermarking key used for those versions
``RMAP_POSITION``        optional position hint for the method

If the keys are missing the routes still exist but answer 503, so the
rest of the platform keeps working on a machine without RMAP keys.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path

from flask import jsonify, request
from sqlalchemy import text
from werkzeug.utils import secure_filename

import watermarking_utils as WMUtils

from rmap import (
    RMAPServer,
    RMAPError,
    MalformedMessageException,
    UnknownIdentityException,
    DecryptionException,
    ProtocolStateException,
)


# Map library exceptions onto HTTP status codes. Anything not listed
# falls back to 400.
_ERROR_STATUS = {
    MalformedMessageException: 400,
    DecryptionException: 400,
    UnknownIdentityException: 403,
    ProtocolStateException: 409,
}


def register_rmap_routes(app, get_engine) -> None:
    """Attach the two RMAP routes to ``app``.

    ``get_engine`` is the callable used by the rest of the server to get
    the SQLAlchemy engine, passed in so this module does not have to
    know how the app builds its database connection.
    """

    app.config.setdefault("RMAP_SERVER_PRIV", os.environ.get("RMAP_SERVER_PRIV", "./keys/server_priv.asc"))
    app.config.setdefault("RMAP_SERVER_PUB", os.environ.get("RMAP_SERVER_PUB", "./keys/server_pub.asc"))
    app.config.setdefault("RMAP_CLIENT_KEYS_DIR", os.environ.get("RMAP_CLIENT_KEYS_DIR", "./keys/clients"))
    app.config.setdefault("RMAP_PASSPHRASE", os.environ.get("RMAP_PASSPHRASE") or None)
    app.config.setdefault("RMAP_LINK_PREFIX", os.environ.get("RMAP_LINK_PREFIX", ""))
    app.config.setdefault("RMAP_DOCUMENT_ID", os.environ.get("RMAP_DOCUMENT_ID") or None)
    app.config.setdefault("RMAP_DOCUMENT_NAME", os.environ.get("RMAP_DOCUMENT_NAME") or None)
    app.config.setdefault("RMAP_METHOD", os.environ.get("RMAP_METHOD", "encrypted-metadata"))
    app.config.setdefault("RMAP_KEY", os.environ.get("RMAP_KEY") or None)
    app.config.setdefault("RMAP_POSITION", os.environ.get("RMAP_POSITION") or None)

    _lock = threading.Lock()

    def _rmap_server():
        """Build the RMAPServer once, on first use.

        Done lazily so that a deployment without keys still boots; the
        routes report 503 instead of the whole app failing to import.
        """
        srv = app.config.get("_RMAP_SERVER")
        if srv is not None:
            return srv
        with _lock:
            srv = app.config.get("_RMAP_SERVER")
            if srv is not None:
                return srv
            priv = Path(app.config["RMAP_SERVER_PRIV"])
            pub = Path(app.config["RMAP_SERVER_PUB"])
            clients = Path(app.config["RMAP_CLIENT_KEYS_DIR"])
            if not priv.is_file() or not pub.is_file() or not clients.is_dir():
                raise FileNotFoundError(
                    "RMAP keys not configured: expected private key at "
                    f"{priv}, public key at {pub}, client keys in {clients}"
                )
            srv = RMAPServer(
                server_public_key_path=str(pub),
                server_private_key_path=str(priv),
                passphrase=app.config["RMAP_PASSPHRASE"],
                linkPrefix=app.config["RMAP_LINK_PREFIX"],
                verbose=False,
            )
            srv.loadIdentities(str(clients))
            app.config["_RMAP_SERVER"] = srv
            return srv

    def _rmap_error(exc: RMAPError):
        status = 400
        for cls, code in _ERROR_STATUS.items():
            if isinstance(exc, cls):
                status = code
                break
        # The message is deliberately generic: telling a caller *why*
        # their handshake failed helps an attacker map the protocol
        # state machine.
        return jsonify({"error": "rmap handshake failed"}), status

    def _assigned_document(conn):
        """Return the Documents row this server distributes over RMAP."""
        doc_id = app.config["RMAP_DOCUMENT_ID"]
        if doc_id:
            return conn.execute(
                text("SELECT id, name, path FROM Documents WHERE id = :id LIMIT 1"),
                {"id": int(doc_id)},
            ).first()
        name = app.config["RMAP_DOCUMENT_NAME"]
        if name:
            return conn.execute(
                text("SELECT id, name, path FROM Documents WHERE name = :name ORDER BY id LIMIT 1"),
                {"name": name},
            ).first()
        return None

    def _resolve_under_storage(raw_path: str) -> Path | None:
        """Resolve a stored path, refusing anything outside STORAGE_DIR."""
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        path = Path(raw_path)
        if not path.is_absolute():
            path = storage_root / path
        path = path.resolve()
        try:
            path.relative_to(storage_root)
        except ValueError:
            return None
        return path if path.exists() else None

    def _create_version_for(identity: str, link: str) -> None:
        """Watermark the assigned document for ``identity`` under ``link``.

        Raises RuntimeError with a short reason on failure. The caller
        must not return a link to the client unless this succeeded.
        """
        method = app.config["RMAP_METHOD"]
        key = app.config["RMAP_KEY"]
        position = app.config["RMAP_POSITION"]
        if not key:
            raise RuntimeError("RMAP_KEY is not configured")

        with get_engine().connect() as conn:
            existing = conn.execute(
                text("SELECT id FROM Versions WHERE link = :link LIMIT 1"),
                {"link": link},
            ).first()
            if existing:
                # Same handshake completed twice: the version is already
                # recorded, nothing more to do.
                return
            row = _assigned_document(conn)

        if not row:
            raise RuntimeError("assigned RMAP document not found")

        source = _resolve_under_storage(row.path)
        if source is None:
            raise RuntimeError("assigned RMAP document missing on disk")

        # The secret is what identifies the recipient if the document
        # leaks, so it must be the authenticated identity, never
        # anything the client supplied.
        secret = identity

        if WMUtils.is_watermarking_applicable(method=method, pdf=str(source), position=position) is False:
            raise RuntimeError(f"method {method!r} not applicable to the assigned document")

        wm_bytes = WMUtils.apply_watermark(
            pdf=str(source), secret=secret, key=key, method=method, position=position
        )
        if not isinstance(wm_bytes, (bytes, bytearray)) or not wm_bytes:
            raise RuntimeError("watermarking produced no output")

        dest_dir = source.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{Path(row.name or source.name).stem}__rmap__{secure_filename(identity)}__{link[:8]}.pdf"
        dest_path = dest_dir / filename
        dest_path.write_bytes(wm_bytes)

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text(
                        """
                        INSERT INTO Versions
                            (documentid, link, intended_for, secret, method, position, path)
                        VALUES
                            (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                        """
                    ),
                    {
                        "documentid": row.id,
                        "link": link,
                        "intended_for": identity,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": str(dest_path),
                    },
                )
        except Exception as exc:
            dest_path.unlink(missing_ok=True)
            raise RuntimeError(f"could not record version: {exc}") from exc

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    @app.post("/api/rmap-initiate")
    def rmap_initiate():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"error": "json body required"}), 400
        try:
            server = _rmap_server()
        except FileNotFoundError:
            return jsonify({"error": "rmap not configured on this server"}), 503
        try:
            _identity, resp1 = server.receiveMsg1(body)
        except RMAPError as exc:
            return _rmap_error(exc)
        return jsonify(resp1), 200

    @app.post("/api/rmap-get-link")
    def rmap_get_link():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"error": "json body required"}), 400
        try:
            server = _rmap_server()
        except FileNotFoundError:
            return jsonify({"error": "rmap not configured on this server"}), 503
        try:
            identity, expected_link, resp2 = server.receiveMsg2(body)
        except RMAPError as exc:
            return _rmap_error(exc)

        # The specification is explicit: no link may be returned unless
        # the watermarked version exists and is recorded. A failure here
        # is ours, not the client's, hence 500.
        try:
            _create_version_for(identity, expected_link)
        except Exception as exc:
            app.logger.error("rmap: failed to create version for %s: %s", identity, exc)
            return jsonify({"error": "could not prepare the document"}), 500

        return jsonify(resp2), 200
