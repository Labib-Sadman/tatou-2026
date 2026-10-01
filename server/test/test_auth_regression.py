"""Security regression tests for Tatou's token authentication.

SAMM Security Testing improvement: before this file, no automated test
checked that protected API endpoints reject unauthenticated or forged
requests. These checks had only ever been done by hand.

None of these tests need the database: the auth check runs before any
route touches the DB, so they work with plain `python -m pytest`.
"""
import pytest
from itsdangerous import URLSafeTimedSerializer

from server import app

# A secret only the "server" knows during the tests.
SERVER_KEY = "test-only-server-secret"
# Must match the salt used by the server's _serializer().
SALT = "tatou-auth"
# A protected endpoint (decorated with @require_auth).
PROTECTED = "/api/list-documents"


@pytest.fixture
def client(monkeypatch):
    # Give the app a known secret for this test only.
    monkeypatch.setitem(app.config, "SECRET_KEY", SERVER_KEY)
    return app.test_client()


def make_token(secret, uid=1, login="alice"):
    """Create a token the same way the server does after a login."""
    s = URLSafeTimedSerializer(secret, salt=SALT)
    return s.dumps({"uid": uid, "login": login, "email": f"{login}@example.com"})


def test_missing_token_rejected(client):
    """No Authorization header at all -> 401."""
    resp = client.get(PROTECTED)
    assert resp.status_code == 401


def test_forged_token_rejected(client):
    """Token signed with a key the attacker guessed, not the server's key -> 401."""
    forged = make_token("attacker-guessed-key")
    resp = client.get(PROTECTED, headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_tampered_token_rejected(client):
    """A real token whose content was edited (e.g. to become another user) -> 401."""
    real = make_token(SERVER_KEY, uid=1)
    payload, rest = real.split(".", 1)
    other = make_token(SERVER_KEY, uid=2).split(".", 1)[0]
    tampered = f"{other}.{rest}"  # uid=2's payload with uid=1's signature
    assert tampered != real
    resp = client.get(PROTECTED, headers={"Authorization": f"Bearer {tampered}"})
    assert resp.status_code == 401


def test_valid_token_passes_auth_and_plugin_endpoint_stays_disabled(client):
    """Control case: a genuinely valid token gets past the auth check.

    Without this, the tests above could pass for the wrong reason
    (e.g. if every request were rejected). Uses /api/load-plugin, which
    was disabled because it allowed remote code execution: it must
    answer 410 Gone, never load anything.
    """
    valid = make_token(SERVER_KEY)
    resp = client.post(
        "/api/load-plugin",
        json={"filename": "evil.pkl"},
        headers={"Authorization": f"Bearer {valid}"},
    )
    assert resp.status_code == 410
