"""Tests for the RMAP handshake endpoints.

These drive a real four-message handshake with freshly generated PGP
keypairs against an app that has only the RMAP routes registered, with a
SQLite stand-in for MariaDB. That keeps the tests runnable without a
database container while still exercising the real library, the real
route code, real watermarking and the real Versions insert.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest
from flask import Flask
from sqlalchemy import create_engine, text

pytest.importorskip("rmap", reason="rmap library not installed")

import pymupdf
from rmap import RMAPClient

from rmap_routes import register_rmap_routes

WM_KEY = "rmap-test-watermark-key"
IDENTITY = "Group_20"


def _keygen(name: str, priv: Path, pub: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "rmap.keygen", "--name", name,
         "--email", f"{name.lower()}@test.invalid",
         "--out-private", str(priv), "--out-public", str(pub)],
        capture_output=True,
    )
    if result.returncode != 0 or not priv.exists():
        pytest.skip(f"rmap-keygen unavailable: {result.stderr.decode()[:200]}")


def _make_source_pdf(path: Path) -> None:
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_textbox(pymupdf.Rect(50, 50, 550, 700),
                        "Confidential document assigned to this group.\n" * 20,
                        fontsize=11)
    doc.save(str(path))
    doc.close()


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    """Keys, a source document, a SQLite database and a configured app."""
    base = tmp_path_factory.mktemp("rmap")
    keys = base / "keys"
    (keys / "clients").mkdir(parents=True)
    storage = base / "storage" / "owner"
    storage.mkdir(parents=True)

    _keygen("Server", keys / "server_priv.asc", keys / "server_pub.asc")
    _keygen(IDENTITY, keys / "client_priv.asc", keys / "clients" / f"{IDENTITY}.asc")

    source = storage / "assigned.pdf"
    _make_source_pdf(source)

    engine = create_engine(f"sqlite:///{base / 'test.db'}", future=True)
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE Documents (id INTEGER PRIMARY KEY, name TEXT, path TEXT)"))
        conn.execute(text(
            "CREATE TABLE Versions (id INTEGER PRIMARY KEY, documentid INT, link TEXT UNIQUE, "
            "intended_for TEXT, secret TEXT, method TEXT, position TEXT, path TEXT)"
        ))
        conn.execute(text("INSERT INTO Documents (id, name, path) VALUES (1, 'assigned', :p)"),
                     {"p": str(source)})

    app = Flask(__name__)
    app.config["STORAGE_DIR"] = base / "storage"
    app.config.update(
        RMAP_SERVER_PRIV=str(keys / "server_priv.asc"),
        RMAP_SERVER_PUB=str(keys / "server_pub.asc"),
        RMAP_CLIENT_KEYS_DIR=str(keys / "clients"),
        RMAP_PASSPHRASE=None,
        RMAP_LINK_PREFIX="https://example.invalid/api/get-version/",
        RMAP_DOCUMENT_ID="1",
        RMAP_DOCUMENT_NAME=None,
        RMAP_METHOD="encrypted-metadata",
        RMAP_KEY=WM_KEY,
        RMAP_POSITION=None,
    )
    register_rmap_routes(app, lambda: engine)
    return {"base": base, "keys": keys, "app": app, "engine": engine}


def _client(env, identity=IDENTITY, priv="client_priv.asc") -> RMAPClient:
    return RMAPClient(
        identity=identity,
        client_private_key_path=str(env["keys"] / priv),
        server_public_key_path=str(env["keys"] / "server_pub.asc"),
    )


def _handshake(env, identity=IDENTITY, priv="client_priv.asc"):
    """Run a full handshake, returning (client, resp2 payload)."""
    tc = env["app"].test_client()
    client = _client(env, identity, priv)
    r1 = tc.post("/api/rmap-initiate", json=client.build_msg1())
    assert r1.status_code == 200, r1.get_json()
    client.process_resp1(r1.get_json())
    r2 = tc.post("/api/rmap-get-link", json=client.build_msg2())
    assert r2.status_code == 200, r2.get_json()
    return client, client.process_resp2(r2.get_json())


class TestHandshake:
    def test_full_handshake_returns_the_expected_link(self, env):
        client, result = _handshake(env)
        assert client.expected_link in result
        assert len(client.expected_link) == 32

    def test_version_is_recorded_before_the_link_is_returned(self, env):
        client, _ = _handshake(env)
        with env["engine"].connect() as conn:
            row = conn.execute(
                text("SELECT intended_for, secret, method, path FROM Versions WHERE link = :l"),
                {"l": client.expected_link},
            ).first()
        assert row is not None, "no Versions row for the issued link"
        assert row.intended_for == IDENTITY
        assert Path(row.path).exists()

    def test_watermark_identifies_the_requesting_identity(self, env):
        """A leaked copy must be traceable back to who fetched it."""
        import watermarking_utils as WMUtils
        client, _ = _handshake(env)
        with env["engine"].connect() as conn:
            path = conn.execute(text("SELECT path FROM Versions WHERE link = :l"),
                                {"l": client.expected_link}).scalar()
        assert WMUtils.read_watermark(method="encrypted-metadata", pdf=path, key=WM_KEY) == IDENTITY

    def test_each_handshake_yields_a_distinct_link_and_version(self, env):
        first, _ = _handshake(env)
        second, _ = _handshake(env)
        assert first.expected_link != second.expected_link
        with env["engine"].connect() as conn:
            count = conn.execute(
                text("SELECT COUNT(*) FROM Versions WHERE link IN (:a, :b)"),
                {"a": first.expected_link, "b": second.expected_link},
            ).scalar()
        assert count == 2


class TestRejections:
    def test_unregistered_identity_is_refused(self, env):
        _keygen("Group_99", env["keys"] / "g99_priv.asc", env["keys"] / "g99_pub.asc")
        tc = env["app"].test_client()
        client = _client(env, "Group_99", "g99_priv.asc")
        resp = tc.post("/api/rmap-initiate", json=client.build_msg1())
        assert resp.status_code == 403

    def test_malformed_payload_is_refused(self, env):
        tc = env["app"].test_client()
        assert tc.post("/api/rmap-initiate", json={"payload": "bm90LXBncA=="}).status_code == 400

    def test_missing_body_is_refused(self, env):
        tc = env["app"].test_client()
        assert tc.post("/api/rmap-initiate", json={}).status_code == 400

    def test_errors_do_not_leak_the_reason(self, env):
        """Distinguishable failure messages would map the state machine."""
        tc = env["app"].test_client()
        body = tc.post("/api/rmap-initiate", json={"payload": "bm90LXBncA=="}).get_json()
        assert "rmap" in body.get("error", "").lower()
        assert "identity" not in body.get("error", "").lower()

    def test_no_version_is_created_for_a_rejected_handshake(self, env):
        with env["engine"].connect() as conn:
            before = conn.execute(text("SELECT COUNT(*) FROM Versions")).scalar()
        tc = env["app"].test_client()
        tc.post("/api/rmap-get-link", json={"payload": "bm90LXBncA=="})
        with env["engine"].connect() as conn:
            after = conn.execute(text("SELECT COUNT(*) FROM Versions")).scalar()
        assert before == after


class TestUnconfigured:
    def test_routes_report_unavailable_without_keys(self, tmp_path):
        """A deployment without keys must still boot and answer cleanly."""
        app = Flask(__name__)
        app.config["STORAGE_DIR"] = tmp_path
        app.config.update(
            RMAP_SERVER_PRIV=str(tmp_path / "missing_priv.asc"),
            RMAP_SERVER_PUB=str(tmp_path / "missing_pub.asc"),
            RMAP_CLIENT_KEYS_DIR=str(tmp_path / "missing_clients"),
            RMAP_PASSPHRASE=None, RMAP_LINK_PREFIX="", RMAP_DOCUMENT_ID="1",
            RMAP_DOCUMENT_NAME=None, RMAP_METHOD="encrypted-metadata",
            RMAP_KEY="x", RMAP_POSITION=None,
        )
        register_rmap_routes(app, lambda: None)
        tc = app.test_client()
        assert tc.post("/api/rmap-initiate", json={"payload": "x"}).status_code == 503
        assert tc.post("/api/rmap-get-link", json={"payload": "x"}).status_code == 503
