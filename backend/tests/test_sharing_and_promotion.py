"""Exercises sharing a client with a colleague (and the new grant holder starting
in sync with existing resources), revocation (including the superadmin-revocation
guard), and the promote-to-superadmin + per-client reconciliation flow."""

import base64

import pytest

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


async def _signup(client, email: str) -> dict:
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    invite = await client.post(
        "/api/v1/invites", json={"email": email, "role": "user"}, headers=_auth(admin_token)
    )
    raw_token = invite.json()["token"]
    accept = await client.post(
        f"/api/v1/invites/{raw_token}/accept",
        json={
            "public_key": _b64(email.encode().ljust(32, b"0")[:32]),
            "wrapped_private_key": _b64(b"wrapped-private-key"),
            "wrapped_private_key_nonce": _b64(b"0" * 24),
            "kdf_salt": _b64(b"0" * 16),
            "kdf_ops_limit": 3,
            "kdf_mem_limit": 268435456,
            "auth_hash": "irrelevant-for-these-tests",
        },
    )
    tokens = accept.json()
    me = await client.get("/api/v1/users/me", headers=_auth(tokens["access_token"]))
    return {"access_token": tokens["access_token"], "user_id": me.json()["id"]}


async def test_share_grants_access_and_syncs_existing_resources(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup(client, "owner@infrawarden-test.example.com")
    colleague = await _signup(client, "colleague@infrawarden-test.example.com")

    client_resp = await client.post(
        "/api/v1/clients",
        json={
            "name": "Shared Co",
            "grants": [
                {"user_id": owner["user_id"], "wrapped_data_key": _b64(b"owner-key")},
                {"user_id": admin_id, "wrapped_data_key": _b64(b"admin-key")},
            ],
        },
        headers=_auth(owner["access_token"]),
    )
    client_id = client_resp.json()["id"]

    resource_resp = await client.post(
        f"/api/v1/clients/{client_id}/resources",
        json={"resource_type": "host", "ciphertext": _b64(b"v1"), "nonce": _b64(b"n" * 24)},
        headers=_auth(owner["access_token"]),
    )
    resource_id = resource_resp.json()["id"]

    # Colleague can't see the client yet.
    denied = await client.get(f"/api/v1/clients/{client_id}", headers=_auth(colleague["access_token"]))
    assert denied.status_code == 404

    share = await client.post(
        f"/api/v1/clients/{client_id}/access",
        json={"user_id": colleague["user_id"], "wrapped_data_key": _b64(b"colleague-key")},
        headers=_auth(owner["access_token"]),
    )
    assert share.status_code == 200, share.text
    assert share.json()["email"] == "colleague@infrawarden-test.example.com"

    # Now they can, and their own wrapped copy of the data key comes back.
    now_visible = await client.get(f"/api/v1/clients/{client_id}", headers=_auth(colleague["access_token"]))
    assert now_visible.status_code == 200
    assert now_visible.json()["wrapped_data_key"] == _b64(b"colleague-key")

    # And they start in sync with the existing resource - no pending-change banner.
    colleague_resource = await client.get(f"/api/v1/resources/{resource_id}", headers=_auth(colleague["access_token"]))
    assert colleague_resource.status_code == 200
    assert colleague_resource.json()["has_pending_change"] is False

    access_list = await client.get(f"/api/v1/clients/{client_id}/access", headers=_auth(owner["access_token"]))
    emails = {row["email"] for row in access_list.json()}
    assert emails == {"owner@infrawarden-test.example.com", ADMIN_EMAIL, "colleague@infrawarden-test.example.com"}

    revoke = await client.delete(
        f"/api/v1/clients/{client_id}/access/{colleague['user_id']}", headers=_auth(owner["access_token"])
    )
    assert revoke.status_code == 204
    denied_again = await client.get(f"/api/v1/clients/{client_id}", headers=_auth(colleague["access_token"]))
    assert denied_again.status_code == 404


async def test_cannot_revoke_superadmin_access(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup(client, "owner2@infrawarden-test.example.com")

    client_resp = await client.post(
        "/api/v1/clients",
        json={
            "name": "Protected Co",
            "grants": [
                {"user_id": owner["user_id"], "wrapped_data_key": _b64(b"owner-key")},
                {"user_id": admin_id, "wrapped_data_key": _b64(b"admin-key")},
            ],
        },
        headers=_auth(owner["access_token"]),
    )
    client_id = client_resp.json()["id"]

    revoke = await client.delete(f"/api/v1/clients/{client_id}/access/{admin_id}", headers=_auth(owner["access_token"]))
    assert revoke.status_code == 400


async def test_promote_and_reconcile(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup(client, "owner3@infrawarden-test.example.com")
    future_admin = await _signup(client, "future-admin@infrawarden-test.example.com")

    # A client created before the promotion - future_admin has no grant on it.
    client_resp = await client.post(
        "/api/v1/clients",
        json={
            "name": "Pre-existing Co",
            "grants": [
                {"user_id": owner["user_id"], "wrapped_data_key": _b64(b"owner-key")},
                {"user_id": admin_id, "wrapped_data_key": _b64(b"admin-key")},
            ],
        },
        headers=_auth(owner["access_token"]),
    )
    client_id = client_resp.json()["id"]

    promote = await client.post(f"/api/v1/admin/users/{future_admin['user_id']}/promote", headers=_auth(admin_token))
    assert promote.status_code == 200, promote.text
    assert promote.json()["clients_needing_reconciliation"] == [client_id]

    # Not yet reconciled - still 404 even though they're a superadmin now.
    still_denied = await client.get(f"/api/v1/clients/{client_id}", headers=_auth(future_admin["access_token"]))
    assert still_denied.status_code == 404

    # The existing superadmin (who already has this client's data key) reconciles it.
    reconcile = await client.post(
        f"/api/v1/clients/{client_id}/access",
        json={"user_id": future_admin["user_id"], "wrapped_data_key": _b64(b"newly-promoted-key")},
        headers=_auth(admin_token),
    )
    assert reconcile.status_code == 200

    now_visible = await client.get(f"/api/v1/clients/{client_id}", headers=_auth(future_admin["access_token"]))
    assert now_visible.status_code == 200
    assert now_visible.json()["wrapped_data_key"] == _b64(b"newly-promoted-key")

    # A client created AFTER promotion auto-grants them - no reconciliation needed.
    new_client = await client.post(
        "/api/v1/clients",
        json={
            "name": "Post-promotion Co",
            "grants": [
                {"user_id": owner["user_id"], "wrapped_data_key": _b64(b"owner-key-2")},
                {"user_id": admin_id, "wrapped_data_key": _b64(b"admin-key-2")},
                {"user_id": future_admin["user_id"], "wrapped_data_key": _b64(b"future-admin-key-2")},
            ],
        },
        headers=_auth(owner["access_token"]),
    )
    assert new_client.status_code == 200
    immediate_access = await client.get(
        f"/api/v1/clients/{new_client.json()['id']}", headers=_auth(future_admin["access_token"])
    )
    assert immediate_access.status_code == 200


async def test_revoke_then_regrant_same_user_does_not_crash(client):
    """share_client_access unconditionally inserts a ResourceUserState row per
    active resource for the new grantee; if revoke doesn't clean those up, a
    later re-grant to the same (now-returning) user collides on the
    (resource_id, user_id) primary key."""
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup(client, "owner4@infrawarden-test.example.com")
    colleague = await _signup(client, "colleague4@infrawarden-test.example.com")

    client_resp = await client.post(
        "/api/v1/clients",
        json={
            "name": "Revoke Regrant Co",
            "grants": [
                {"user_id": owner["user_id"], "wrapped_data_key": _b64(b"owner-key")},
                {"user_id": admin_id, "wrapped_data_key": _b64(b"admin-key")},
            ],
        },
        headers=_auth(owner["access_token"]),
    )
    client_id = client_resp.json()["id"]

    await client.post(
        f"/api/v1/clients/{client_id}/resources",
        json={"resource_type": "host", "ciphertext": _b64(b"c"), "nonce": _b64(b"n" * 24)},
        headers=_auth(owner["access_token"]),
    )

    share1 = await client.post(
        f"/api/v1/clients/{client_id}/access",
        json={"user_id": colleague["user_id"], "wrapped_data_key": _b64(b"colleague-key-1")},
        headers=_auth(owner["access_token"]),
    )
    assert share1.status_code == 200

    revoke = await client.delete(
        f"/api/v1/clients/{client_id}/access/{colleague['user_id']}", headers=_auth(owner["access_token"])
    )
    assert revoke.status_code == 204

    share2 = await client.post(
        f"/api/v1/clients/{client_id}/access",
        json={"user_id": colleague["user_id"], "wrapped_data_key": _b64(b"colleague-key-2")},
        headers=_auth(owner["access_token"]),
    )
    assert share2.status_code == 200, share2.text

    regained = await client.get(f"/api/v1/clients/{client_id}", headers=_auth(colleague["access_token"]))
    assert regained.status_code == 200
    assert regained.json()["wrapped_data_key"] == _b64(b"colleague-key-2")


async def test_only_owner_or_admin_can_revoke_someone_elses_access(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup(client, "owner5@infrawarden-test.example.com")
    colleague = await _signup(client, "colleague5@infrawarden-test.example.com")

    client_resp = await client.post(
        "/api/v1/clients",
        json={
            "name": "Ownership Co",
            "grants": [
                {"user_id": owner["user_id"], "wrapped_data_key": _b64(b"owner-key")},
                {"user_id": admin_id, "wrapped_data_key": _b64(b"admin-key")},
            ],
        },
        headers=_auth(owner["access_token"]),
    )
    client_id = client_resp.json()["id"]

    share = await client.post(
        f"/api/v1/clients/{client_id}/access",
        json={"user_id": colleague["user_id"], "wrapped_data_key": _b64(b"colleague-key")},
        headers=_auth(owner["access_token"]),
    )
    assert share.status_code == 200

    # The colleague (not the owner, not a superadmin) cannot revoke the owner's
    # own access - only self-revocation and owner/superadmin-initiated revokes
    # of OTHERS are allowed.
    denied = await client.delete(
        f"/api/v1/clients/{client_id}/access/{owner['user_id']}", headers=_auth(colleague["access_token"])
    )
    assert denied.status_code == 403

    # But the colleague CAN revoke their own access ("leave").
    self_revoke = await client.delete(
        f"/api/v1/clients/{client_id}/access/{colleague['user_id']}", headers=_auth(colleague["access_token"])
    )
    assert self_revoke.status_code == 204
