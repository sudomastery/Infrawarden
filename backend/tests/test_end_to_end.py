"""The golden-path end-to-end test: the full journey from an admin sending an
invite through to an agent (via a scoped API token, exactly as the MCP server
would use it) successfully reading back a client's infra doc - and then losing
that access once the token is revoked.

Every step uses real crypto (the same libsodium primitives the browser's
lib/crypto.ts uses), simulating exactly what happens client-side at each step,
so this proves the full pipeline is correct end to end, not just that each
endpoint independently accepts well-formed requests.

This mirrors, as one continuous narrative, what was manually verified with the
actual built MCP server binary talking real MCP JSON-RPC over stdio to a live
backend (see the commit history) - this test is the permanent, repeatable
version of that same journey.
"""

import base64
import json
import uuid

import nacl.public
import nacl.utils
import pytest

from app.core.crypto import (
    aead_decrypt,
    aead_encrypt,
    derive_token_wrap_key,
    keyed_blake2b,
    pwhash_argon2id,
    secretbox_encrypt,
    seal_for_public_key,
    unseal_with_private_key,
)
from app.core.security import hash_token_secret
from app.scripts.seed_admin import create_admin

ADMIN_EMAIL = "admin@infrawarden-test.example.com"
ADMIN_PASSWORD = "superadmin master password 2026"

PWHASH_OPS = 3
PWHASH_MEM = 268435456


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


@pytest.fixture(autouse=True)
async def _seed_admin():
    await create_admin(ADMIN_EMAIL, ADMIN_PASSWORD)


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _login(client, email: str, password: str) -> str:
    pre = await client.post("/api/v1/auth/prelogin", json={"email": email})
    kdf = pre.json()
    salt = base64.b64decode(kdf["kdf_salt"])
    stretch = pwhash_argon2id(password.encode(), salt, kdf["kdf_ops_limit"], kdf["kdf_mem_limit"])
    auth_hash = keyed_blake2b(password.encode(), key=stretch).hex()
    resp = await client.post("/api/v1/auth/login", json={"email": email, "auth_hash": auth_hash})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


async def test_full_credential_to_agent_journey(client):
    # --- 1. Admin invites a colleague, who sets up their vault client-side ---
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]

    owner_password = "owner master password for this test 2026"
    invite = await client.post(
        "/api/v1/invites",
        json={"email": "owner@infrawarden-test.example.com", "role": "user"},
        headers=_auth(admin_token),
    )
    assert invite.status_code == 200, invite.text
    raw_invite_token = invite.json()["token"]

    invite_lookup = await client.get(f"/api/v1/invites/{raw_invite_token}")
    assert invite_lookup.status_code == 200
    assert invite_lookup.json()["email"] == "owner@infrawarden-test.example.com"

    owner_salt = nacl.utils.random(16)
    owner_stretch_key = pwhash_argon2id(owner_password.encode(), owner_salt, PWHASH_OPS, PWHASH_MEM)
    owner_keypair = nacl.public.PrivateKey.generate()
    owner_wrapped_private_key, owner_pk_nonce = secretbox_encrypt(bytes(owner_keypair), owner_stretch_key)
    owner_auth_hash = keyed_blake2b(owner_password.encode(), key=owner_stretch_key).hex()

    accept = await client.post(
        f"/api/v1/invites/{raw_invite_token}/accept",
        json={
            "public_key": _b64(bytes(owner_keypair.public_key)),
            "wrapped_private_key": _b64(owner_wrapped_private_key),
            "wrapped_private_key_nonce": _b64(owner_pk_nonce),
            "kdf_salt": _b64(owner_salt),
            "kdf_ops_limit": PWHASH_OPS,
            "kdf_mem_limit": PWHASH_MEM,
            "auth_hash": owner_auth_hash,
        },
    )
    assert accept.status_code == 200, accept.text
    owner_token = accept.json()["access_token"]
    owner_id = (await client.get("/api/v1/users/me", headers=_auth(owner_token))).json()["id"]

    # --- 2. Owner logs in fresh (simulating a new session) and unlocks their vault ---
    fresh_login_token = await _login(client, "owner@infrawarden-test.example.com", owner_password)
    me = (await client.get("/api/v1/users/me", headers=_auth(fresh_login_token))).json()
    relogin_salt = base64.b64decode(me["kdf_salt"])
    relogin_stretch_key = pwhash_argon2id(owner_password.encode(), relogin_salt, PWHASH_OPS, PWHASH_MEM)
    from app.core.crypto import secretbox_decrypt

    unwrapped_private_key = secretbox_decrypt(
        base64.b64decode(me["wrapped_private_key"]), base64.b64decode(me["wrapped_private_key_nonce"]), relogin_stretch_key
    )
    assert unwrapped_private_key == bytes(owner_keypair)  # vault unlock recovers the exact same key
    owner_token = fresh_login_token

    # --- 3. Owner creates a client, auto-granting the superadmin ---
    data_key = nacl.utils.random(32)
    owner_wrapped_data_key = seal_for_public_key(data_key, bytes(owner_keypair.public_key))
    admin_wrapped_data_key = b"admin-does-not-need-a-real-unseal-in-this-test"

    client_resp = await client.post(
        "/api/v1/clients",
        json={
            "name": "E2E Test Co",
            "description": "created during the golden-path e2e test",
            "grants": [
                {"user_id": owner_id, "wrapped_data_key": _b64(owner_wrapped_data_key)},
                {"user_id": admin_id, "wrapped_data_key": _b64(admin_wrapped_data_key)},
            ],
        },
        headers=_auth(owner_token),
    )
    assert client_resp.status_code == 200, client_resp.text
    client_id = client_resp.json()["id"]

    # --- 4. Owner adds a resource with real encrypted fields, plus a note ---
    fields = {
        "name": "prod-web-01",
        "ip": "10.20.30.40",
        "hostname": "web01.e2e.internal",
        "username": "deploy",
        "secret": "s3cret-deploy-key",
        "tags": "production,web",
    }
    ciphertext, nonce = aead_encrypt(json.dumps(fields).encode(), data_key)
    resource_resp = await client.post(
        f"/api/v1/clients/{client_id}/resources",
        json={"resource_type": "host", "ciphertext": _b64(ciphertext), "nonce": _b64(nonce)},
        headers=_auth(owner_token),
    )
    assert resource_resp.status_code == 200, resource_resp.text
    resource_id = resource_resp.json()["id"]

    note_text = "2026-07-15: this host had a brief outage, root-caused to a bad deploy and rolled back same day."
    note_ciphertext, note_nonce = aead_encrypt(json.dumps(note_text).encode(), data_key)
    note_resp = await client.post(
        f"/api/v1/resources/{resource_id}/notes",
        json={"ciphertext": _b64(note_ciphertext), "nonce": _b64(note_nonce)},
        headers=_auth(owner_token),
    )
    assert note_resp.status_code == 200

    # --- 5. Owner shares the client with a second colleague ---
    colleague_password = "colleague master password 2026"
    colleague_invite = await client.post(
        "/api/v1/invites",
        json={"email": "colleague@infrawarden-test.example.com", "role": "user"},
        headers=_auth(admin_token),
    )
    colleague_salt = nacl.utils.random(16)
    colleague_stretch_key = pwhash_argon2id(colleague_password.encode(), colleague_salt, PWHASH_OPS, PWHASH_MEM)
    colleague_keypair = nacl.public.PrivateKey.generate()
    colleague_wrapped_pk, colleague_pk_nonce = secretbox_encrypt(bytes(colleague_keypair), colleague_stretch_key)
    colleague_accept = await client.post(
        f"/api/v1/invites/{colleague_invite.json()['token']}/accept",
        json={
            "public_key": _b64(bytes(colleague_keypair.public_key)),
            "wrapped_private_key": _b64(colleague_wrapped_pk),
            "wrapped_private_key_nonce": _b64(colleague_pk_nonce),
            "kdf_salt": _b64(colleague_salt),
            "kdf_ops_limit": PWHASH_OPS,
            "kdf_mem_limit": PWHASH_MEM,
            "auth_hash": keyed_blake2b(colleague_password.encode(), key=colleague_stretch_key).hex(),
        },
    )
    colleague_token = colleague_accept.json()["access_token"]
    colleague_id = (await client.get("/api/v1/users/me", headers=_auth(colleague_token))).json()["id"]

    colleague_wrapped_data_key = seal_for_public_key(data_key, bytes(colleague_keypair.public_key))
    share_resp = await client.post(
        f"/api/v1/clients/{client_id}/access",
        json={"user_id": colleague_id, "wrapped_data_key": _b64(colleague_wrapped_data_key)},
        headers=_auth(owner_token),
    )
    assert share_resp.status_code == 200, share_resp.text

    # Colleague can now see the client and decrypt the resource themselves.
    colleague_client_view = await client.get(f"/api/v1/clients/{client_id}", headers=_auth(colleague_token))
    assert colleague_client_view.status_code == 200
    colleague_data_key = unseal_with_private_key(
        base64.b64decode(colleague_client_view.json()["wrapped_data_key"]), bytes(colleague_keypair)
    )
    assert colleague_data_key == data_key

    colleague_resource_view = await client.get(f"/api/v1/resources/{resource_id}", headers=_auth(colleague_token))
    decrypted_by_colleague = json.loads(
        aead_decrypt(
            base64.b64decode(colleague_resource_view.json()["current_version"]["ciphertext"]),
            base64.b64decode(colleague_resource_view.json()["current_version"]["nonce"]),
            colleague_data_key,
        )
    )
    assert decrypted_by_colleague == fields

    # --- 6. Colleague mints a scoped API token, exactly as the web UI would ---
    token_id = str(uuid.uuid4())
    token_secret = nacl.utils.random(32)
    token_wrap_key = derive_token_wrap_key(token_id, token_secret)
    token_wrapped_data_key, token_nonce = aead_encrypt(data_key, token_wrap_key)

    token_create = await client.post(
        f"/api/v1/clients/{client_id}/tokens",
        json={
            "token_id": token_id,
            "scope_type": "all_resources",
            "resource_ids": None,
            "ttl_seconds": 1800,
            "token_hash": hash_token_secret(token_secret),
            "wrapped_data_key": _b64(token_wrapped_data_key),
            "wrapped_data_key_nonce": _b64(token_nonce),
        },
        headers=_auth(colleague_token),
    )
    assert token_create.status_code == 200, token_create.text
    assert token_create.json()["expires_at"] is not None

    # --- 7. The agent (MCP server, in reality) fetches the doc with just the token ---
    bearer = f"{token_id}.{token_secret.hex()}"
    doc = await client.get("/api/v1/agent/doc", headers={"Authorization": f"Bearer {bearer}"})
    assert doc.status_code == 200, doc.text
    markdown = doc.json()["rendered_markdown"]

    assert "E2E Test Co" == doc.json()["client_name"]
    for expected in ("prod-web-01", "10.20.30.40", "web01.e2e.internal", "deploy", "s3cret-deploy-key"):
        assert expected in markdown
    assert "brief outage" in markdown
    assert "owner@infrawarden-test.example.com" in markdown  # note author attribution (owner wrote the note)

    # --- 8. Revoke the token - the agent immediately loses access ---
    revoke = await client.delete(f"/api/v1/clients/{client_id}/tokens/{token_id}", headers=_auth(colleague_token))
    assert revoke.status_code == 204

    doc_after_revoke = await client.get("/api/v1/agent/doc", headers={"Authorization": f"Bearer {bearer}"})
    assert doc_after_revoke.status_code == 401

    # And a stranger with no grant at all was never able to see any of this.
    stranger_password = "stranger master password 2026"
    stranger_invite = await client.post(
        "/api/v1/invites",
        json={"email": "stranger@infrawarden-test.example.com", "role": "user"},
        headers=_auth(admin_token),
    )
    stranger_salt = nacl.utils.random(16)
    stranger_stretch_key = pwhash_argon2id(stranger_password.encode(), stranger_salt, PWHASH_OPS, PWHASH_MEM)
    stranger_keypair = nacl.public.PrivateKey.generate()
    stranger_wrapped_pk, stranger_pk_nonce = secretbox_encrypt(bytes(stranger_keypair), stranger_stretch_key)
    stranger_accept = await client.post(
        f"/api/v1/invites/{stranger_invite.json()['token']}/accept",
        json={
            "public_key": _b64(bytes(stranger_keypair.public_key)),
            "wrapped_private_key": _b64(stranger_wrapped_pk),
            "wrapped_private_key_nonce": _b64(stranger_pk_nonce),
            "kdf_salt": _b64(stranger_salt),
            "kdf_ops_limit": PWHASH_OPS,
            "kdf_mem_limit": PWHASH_MEM,
            "auth_hash": keyed_blake2b(stranger_password.encode(), key=stranger_stretch_key).hex(),
        },
    )
    stranger_token = stranger_accept.json()["access_token"]
    stranger_client_view = await client.get(f"/api/v1/clients/{client_id}", headers=_auth(stranger_token))
    assert stranger_client_view.status_code == 404
