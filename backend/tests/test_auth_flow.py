"""Exercises the full auth/vault-unlock crypto pipeline end to end against a real
Postgres database: seed superadmin -> prelogin -> login -> invite -> accept -> me.

Crypto operations here simulate what the browser's lib/crypto.ts does, using the same
underlying libsodium primitives via PyNaCl (app.core.crypto) - this validates the wire
contract and server-side logic; true browser/Python interop is exercised separately
once the frontend crypto module exists.
"""

import nacl.utils
import pytest

from app.core.crypto import (
    PWHASH_MEMLIMIT_DEFAULT,
    PWHASH_OPSLIMIT_DEFAULT,
    PWHASH_SALT_BYTES,
    generate_keypair,
    keyed_blake2b,
    pwhash_argon2id,
    secretbox_encrypt,
)
from app.core.encoding import b64encode
from app.models.user import UserRole
from app.scripts.seed_admin import create_admin


def _derive_signup_payload(password: str) -> dict:
    """Simulates the browser's invite-accept / seed flow: derive stretch_key, generate
    a keypair, wrap the private key, compute auth_hash."""
    salt = nacl.utils.random(PWHASH_SALT_BYTES)
    stretch_key = pwhash_argon2id(password.encode(), salt, PWHASH_OPSLIMIT_DEFAULT, PWHASH_MEMLIMIT_DEFAULT)
    private_key, public_key = generate_keypair()
    wrapped_private_key, nonce = secretbox_encrypt(private_key, stretch_key)
    auth_hash = keyed_blake2b(password.encode(), key=stretch_key).hex()
    return {
        "public_key": b64encode(public_key),
        "wrapped_private_key": b64encode(wrapped_private_key),
        "wrapped_private_key_nonce": b64encode(nonce),
        "kdf_salt": b64encode(salt),
        "kdf_ops_limit": PWHASH_OPSLIMIT_DEFAULT,
        "kdf_mem_limit": PWHASH_MEMLIMIT_DEFAULT,
        "auth_hash": auth_hash,
    }


def _derive_login_auth_hash(password: str, salt: bytes, ops_limit: int, mem_limit: int) -> str:
    stretch_key = pwhash_argon2id(password.encode(), salt, ops_limit, mem_limit)
    return keyed_blake2b(password.encode(), key=stretch_key).hex()


ADMIN_EMAIL = "admin@infrawarden-test.example.com"
ADMIN_PASSWORD = "correct horse battery staple 12"


@pytest.fixture(autouse=True)
async def _seed_admin():
    await create_admin(ADMIN_EMAIL, ADMIN_PASSWORD)


async def test_prelogin_unknown_email_does_not_404(client):
    r = await client.post("/api/v1/auth/prelogin", json={"email": "nobody@nowhere-example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["kdf_ops_limit"] == PWHASH_OPSLIMIT_DEFAULT

    # same unknown email always gets the same fake salt back (not fresh randomness)
    r2 = await client.post("/api/v1/auth/prelogin", json={"email": "nobody@nowhere-example.com"})
    assert r2.json()["kdf_salt"] == body["kdf_salt"]


async def test_admin_login_and_me(client):
    pre = await client.post("/api/v1/auth/prelogin", json={"email": ADMIN_EMAIL})
    assert pre.status_code == 200
    kdf = pre.json()

    import base64

    auth_hash = _derive_login_auth_hash(
        ADMIN_PASSWORD, base64.b64decode(kdf["kdf_salt"]), kdf["kdf_ops_limit"], kdf["kdf_mem_limit"]
    )

    login = await client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "auth_hash": auth_hash})
    assert login.status_code == 200, login.text
    tokens = login.json()
    assert "access_token" in tokens and "refresh_token" in tokens

    me = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 200, me.text
    assert me.json()["email"] == ADMIN_EMAIL
    assert me.json()["role"] == UserRole.admin.value

    refreshed = await client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 200
    assert "access_token" in refreshed.json()


async def test_login_wrong_password_rejected(client):
    pre = await client.post("/api/v1/auth/prelogin", json={"email": ADMIN_EMAIL})
    kdf = pre.json()
    import base64

    wrong_hash = _derive_login_auth_hash(
        "totally wrong password", base64.b64decode(kdf["kdf_salt"]), kdf["kdf_ops_limit"], kdf["kdf_mem_limit"]
    )
    r = await client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "auth_hash": wrong_hash})
    assert r.status_code == 401


async def _admin_access_token(client) -> str:
    import base64

    pre = await client.post("/api/v1/auth/prelogin", json={"email": ADMIN_EMAIL})
    kdf = pre.json()
    auth_hash = _derive_login_auth_hash(
        ADMIN_PASSWORD, base64.b64decode(kdf["kdf_salt"]), kdf["kdf_ops_limit"], kdf["kdf_mem_limit"]
    )
    login = await client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "auth_hash": auth_hash})
    return login.json()["access_token"]


async def test_invite_accept_flow(client):
    admin_token = await _admin_access_token(client)

    invite_resp = await client.post(
        "/api/v1/invites",
        json={"email": "colleague@infrawarden-test.example.com", "role": "user"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert invite_resp.status_code == 200, invite_resp.text
    invite = invite_resp.json()
    raw_token = invite["token"]

    fetched = await client.get(f"/api/v1/invites/{raw_token}")
    assert fetched.status_code == 200
    assert fetched.json()["email"] == "colleague@infrawarden-test.example.com"

    signup_payload = _derive_signup_payload("colleague master password 2026")
    accept = await client.post(f"/api/v1/invites/{raw_token}/accept", json=signup_payload)
    assert accept.status_code == 200, accept.text
    tokens = accept.json()

    me = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 200
    assert me.json()["email"] == "colleague@infrawarden-test.example.com"
    assert me.json()["role"] == UserRole.user.value

    # invite is single-use
    reuse = await client.post(f"/api/v1/invites/{raw_token}/accept", json=signup_payload)
    assert reuse.status_code == 404


async def test_non_admin_cannot_create_invite(client):
    admin_token = await _admin_access_token(client)
    invite_resp = await client.post(
        "/api/v1/invites",
        json={"email": "someone@infrawarden-test.example.com", "role": "user"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    signup_payload = _derive_signup_payload("someone password 2026")
    accepted = await client.post(f"/api/v1/invites/{invite_resp.json()['token']}/accept", json=signup_payload)
    user_token = accepted.json()["access_token"]

    r = await client.post(
        "/api/v1/invites",
        json={"email": "another@infrawarden-test.example.com", "role": "user"},
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert r.status_code == 403
