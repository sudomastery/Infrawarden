"""Exercises scoped API token creation and the agent-facing endpoint - the core
mechanism an MCP server uses to fetch a client's infra doc on an agent's behalf.

Unlike the other test modules, this one uses REAL crypto throughout (not opaque
placeholder bytes), because the whole point is proving the token-derived-key
reconciliation mechanism actually decrypts correctly end to end.
"""

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone

import nacl.utils
import pytest

from app.core.crypto import aead_encrypt, derive_token_wrap_key, seal_for_public_key
from app.core.security import hash_token_secret
from app.scripts.seed_admin import create_admin

ADMIN_EMAIL = "admin@infrawarden-test.example.com"
ADMIN_PASSWORD = "admin master password 2026"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


@pytest.fixture(autouse=True)
async def _seed_admin():
    await create_admin(ADMIN_EMAIL, ADMIN_PASSWORD)


async def _login(client, email: str, password: str) -> str:
    from app.core.crypto import keyed_blake2b, pwhash_argon2id

    pre = await client.post("/api/v1/auth/prelogin", json={"email": email})
    kdf = pre.json()
    salt = base64.b64decode(kdf["kdf_salt"])
    stretch = pwhash_argon2id(password.encode(), salt, kdf["kdf_ops_limit"], kdf["kdf_mem_limit"])
    auth_hash = keyed_blake2b(password.encode(), key=stretch).hex()
    login = await client.post("/api/v1/auth/login", json={"email": email, "auth_hash": auth_hash})
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _signup_with_real_keys(client, email: str) -> dict:
    """Unlike other test modules, this generates a REAL X25519 keypair for the
    user, since token tests need to actually seal/unseal a real data key."""
    import nacl.public

    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    invite = await client.post(
        "/api/v1/invites", json={"email": email, "role": "user"}, headers=_auth(admin_token)
    )
    raw_token = invite.json()["token"]

    keypair = nacl.public.PrivateKey.generate()
    accept = await client.post(
        f"/api/v1/invites/{raw_token}/accept",
        json={
            "public_key": _b64(bytes(keypair.public_key)),
            "wrapped_private_key": _b64(b"irrelevant"),
            "wrapped_private_key_nonce": _b64(b"0" * 24),
            "kdf_salt": _b64(b"0" * 16),
            "kdf_ops_limit": 3,
            "kdf_mem_limit": 268435456,
            "auth_hash": "irrelevant-for-these-tests",
        },
    )
    tokens = accept.json()
    me = await client.get("/api/v1/users/me", headers=_auth(tokens["access_token"]))
    return {
        "access_token": tokens["access_token"],
        "user_id": me.json()["id"],
        "private_key": bytes(keypair),
        "public_key": bytes(keypair.public_key),
    }


async def _create_client_and_resource(client, owner: dict, admin_id: str, fields: dict) -> dict:
    data_key = nacl.utils.random(32)
    owner_wrapped = seal_for_public_key(data_key, owner["public_key"])

    client_resp = await client.post(
        "/api/v1/clients",
        json={
            "name": "Agent Test Co",
            "grants": [
                {"user_id": owner["user_id"], "wrapped_data_key": _b64(owner_wrapped)},
                {"user_id": admin_id, "wrapped_data_key": _b64(b"admin-key-doesnt-need-to-be-real")},
            ],
        },
        headers=_auth(owner["access_token"]),
    )
    client_id = client_resp.json()["id"]

    ciphertext, nonce = aead_encrypt(json.dumps(fields).encode(), data_key)
    resource_resp = await client.post(
        f"/api/v1/clients/{client_id}/resources",
        json={"resource_type": "host", "ciphertext": _b64(ciphertext), "nonce": _b64(nonce)},
        headers=_auth(owner["access_token"]),
    )
    return {"client_id": client_id, "resource_id": resource_resp.json()["id"], "data_key": data_key}


def _mint_token(client_id: str, scope_type: str, resource_ids: list[str] | None, ttl_seconds: int, data_key: bytes):
    """Simulates the browser's token-creation crypto: generate token_id/secret,
    derive the wrap key, encrypt the data key with it. Returns (token_id,
    token_secret, request_body)."""
    token_id = str(uuid.uuid4())
    token_secret = nacl.utils.random(32)
    wrap_key = derive_token_wrap_key(token_id, token_secret)
    wrapped_data_key, nonce = aead_encrypt(data_key, wrap_key)
    body = {
        "token_id": token_id,
        "scope_type": scope_type,
        "resource_ids": resource_ids,
        "ttl_seconds": ttl_seconds,
        "token_hash": hash_token_secret(token_secret),
        "wrapped_data_key": _b64(wrapped_data_key),
        "wrapped_data_key_nonce": _b64(nonce),
    }
    return token_id, token_secret, body


async def test_agent_endpoint_returns_correct_rendered_doc(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup_with_real_keys(client, "owner@infrawarden-test.example.com")

    setup = await _create_client_and_resource(
        client, owner, admin_id, {"name": "web-01", "ip": "10.0.1.5", "username": "deploy"}
    )

    note_ciphertext, note_nonce = aead_encrypt(json.dumps("behind the LB").encode(), setup["data_key"])
    await client.post(
        f"/api/v1/resources/{setup['resource_id']}/notes",
        json={"ciphertext": _b64(note_ciphertext), "nonce": _b64(note_nonce)},
        headers=_auth(owner["access_token"]),
    )

    token_id, token_secret, body = _mint_token(setup["client_id"], "all_resources", None, 3600, setup["data_key"])
    create_resp = await client.post(
        f"/api/v1/clients/{setup['client_id']}/tokens", json=body, headers=_auth(owner["access_token"])
    )
    assert create_resp.status_code == 200, create_resp.text
    assert create_resp.json()["id"] == token_id

    bearer = f"{token_id}.{token_secret.hex()}"
    doc = await client.get("/api/v1/agent/doc", headers={"Authorization": f"Bearer {bearer}"})
    assert doc.status_code == 200, doc.text
    body = doc.json()
    assert body["client_name"] == "Agent Test Co"
    assert "web-01" in body["rendered_markdown"]
    assert "10.0.1.5" in body["rendered_markdown"]
    assert "deploy" in body["rendered_markdown"]


async def test_resource_scoped_token_excludes_out_of_scope_resources(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup_with_real_keys(client, "owner2@infrawarden-test.example.com")

    setup = await _create_client_and_resource(client, owner, admin_id, {"name": "in-scope-host"})

    ciphertext, nonce = aead_encrypt(json.dumps({"name": "out-of-scope-host"}).encode(), setup["data_key"])
    other_resource = await client.post(
        f"/api/v1/clients/{setup['client_id']}/resources",
        json={"resource_type": "host", "ciphertext": _b64(ciphertext), "nonce": _b64(nonce)},
        headers=_auth(owner["access_token"]),
    )
    assert other_resource.status_code == 200

    token_id, token_secret, body = _mint_token(
        setup["client_id"], "selected_resources", [setup["resource_id"]], 3600, setup["data_key"]
    )
    create_resp = await client.post(
        f"/api/v1/clients/{setup['client_id']}/tokens", json=body, headers=_auth(owner["access_token"])
    )
    assert create_resp.status_code == 200, create_resp.text

    bearer = f"{token_id}.{token_secret.hex()}"
    doc = await client.get("/api/v1/agent/doc", headers={"Authorization": f"Bearer {bearer}"})
    assert "in-scope-host" in doc.json()["rendered_markdown"]
    assert "out-of-scope-host" not in doc.json()["rendered_markdown"]


async def test_agent_sees_token_creators_own_version_not_latest(client):
    """If the token creator has a pending (un-accepted) change on a resource, the
    agent doc must reflect what the creator is actually looking at - not
    whatever the latest edit happens to be."""
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup_with_real_keys(client, "owner3@infrawarden-test.example.com")
    colleague = await _signup_with_real_keys(client, "colleague3@infrawarden-test.example.com")

    setup = await _create_client_and_resource(client, owner, admin_id, {"name": "host", "ip": "10.0.0.1"})

    share = await client.post(
        f"/api/v1/clients/{setup['client_id']}/access",
        json={"user_id": colleague["user_id"], "wrapped_data_key": _b64(seal_for_public_key(setup["data_key"], colleague["public_key"]))},
        headers=_auth(owner["access_token"]),
    )
    assert share.status_code == 200

    # Owner edits the IP - colleague hasn't accepted this change.
    new_ciphertext, new_nonce = aead_encrypt(json.dumps({"name": "host", "ip": "10.0.0.99"}).encode(), setup["data_key"])
    edit = await client.post(
        f"/api/v1/resources/{setup['resource_id']}/versions",
        json={"ciphertext": _b64(new_ciphertext), "nonce": _b64(new_nonce)},
        headers=_auth(owner["access_token"]),
    )
    assert edit.status_code == 200
    assert edit.json()["has_pending_change"] is False  # owner's own view auto-advanced

    # Colleague mints a token - they're still on the OLD ip.
    token_id, token_secret, body = _mint_token(setup["client_id"], "all_resources", None, 3600, setup["data_key"])
    create_resp = await client.post(
        f"/api/v1/clients/{setup['client_id']}/tokens", json=body, headers=_auth(colleague["access_token"])
    )
    assert create_resp.status_code == 200

    bearer = f"{token_id}.{token_secret.hex()}"
    doc = await client.get("/api/v1/agent/doc", headers={"Authorization": f"Bearer {bearer}"})
    assert "10.0.0.1" in doc.json()["rendered_markdown"]
    assert "10.0.0.99" not in doc.json()["rendered_markdown"]


async def test_expired_token_returns_401_and_envelope_is_nulled(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup_with_real_keys(client, "owner4@infrawarden-test.example.com")
    setup = await _create_client_and_resource(client, owner, admin_id, {"name": "host"})

    token_id, token_secret, body = _mint_token(setup["client_id"], "all_resources", None, 1800, setup["data_key"])
    create_resp = await client.post(
        f"/api/v1/clients/{setup['client_id']}/tokens", json=body, headers=_auth(owner["access_token"])
    )
    assert create_resp.status_code == 200

    # Force it into the past directly (simulating TTL elapsing).
    from app.db.session import async_session_factory
    from app.models.api_token import ApiToken

    async with async_session_factory() as db:
        token = await db.get(ApiToken, uuid.UUID(token_id))
        token.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()

    bearer = f"{token_id}.{token_secret.hex()}"
    doc = await client.get("/api/v1/agent/doc", headers={"Authorization": f"Bearer {bearer}"})
    assert doc.status_code == 401

    # Physical expiry: envelope is nulled, not just flagged - even the correct
    # secret can't recover anything anymore.
    async with async_session_factory() as db:
        token = await db.get(ApiToken, uuid.UUID(token_id))
        assert token.wrapped_data_key is None
        assert token.wrapped_data_key_nonce is None

    doc2 = await client.get("/api/v1/agent/doc", headers={"Authorization": f"Bearer {bearer}"})
    assert doc2.status_code == 401


async def test_revoked_token_returns_401(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup_with_real_keys(client, "owner5@infrawarden-test.example.com")
    setup = await _create_client_and_resource(client, owner, admin_id, {"name": "host"})

    token_id, token_secret, body = _mint_token(setup["client_id"], "all_resources", None, 3600, setup["data_key"])
    await client.post(f"/api/v1/clients/{setup['client_id']}/tokens", json=body, headers=_auth(owner["access_token"]))

    revoke = await client.delete(
        f"/api/v1/clients/{setup['client_id']}/tokens/{token_id}", headers=_auth(owner["access_token"])
    )
    assert revoke.status_code == 204

    bearer = f"{token_id}.{token_secret.hex()}"
    doc = await client.get("/api/v1/agent/doc", headers={"Authorization": f"Bearer {bearer}"})
    assert doc.status_code == 401


async def test_wrong_token_secret_rejected(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup_with_real_keys(client, "owner6@infrawarden-test.example.com")
    setup = await _create_client_and_resource(client, owner, admin_id, {"name": "host"})

    token_id, _real_secret, body = _mint_token(setup["client_id"], "all_resources", None, 3600, setup["data_key"])
    await client.post(f"/api/v1/clients/{setup['client_id']}/tokens", json=body, headers=_auth(owner["access_token"]))

    wrong_secret = nacl.utils.random(32)
    bearer = f"{token_id}.{wrong_secret.hex()}"
    doc = await client.get("/api/v1/agent/doc", headers={"Authorization": f"Bearer {bearer}"})
    assert doc.status_code == 401


async def test_invalid_ttl_rejected(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup_with_real_keys(client, "owner7@infrawarden-test.example.com")
    setup = await _create_client_and_resource(client, owner, admin_id, {"name": "host"})

    token_id, _secret, body = _mint_token(setup["client_id"], "all_resources", None, 12345, setup["data_key"])
    resp = await client.post(f"/api/v1/clients/{setup['client_id']}/tokens", json=body, headers=_auth(owner["access_token"]))
    assert resp.status_code == 422
