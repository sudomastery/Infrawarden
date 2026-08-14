"""Exercises client CRUD, resource creation/editing/versioning, notes, personal
hide vs owner delete, and the superadmin auto-grant + deleted-items recovery flow -
against a real Postgres database.

No actual encryption happens here: ciphertext/nonce fields are opaque blobs from
the server's perspective, so tests just use arbitrary bytes and check they round
trip - the crypto layer itself is covered in test_auth_flow.py's interop checks.
"""

import base64
import uuid

import pytest

from app.models.client_access_grant import ClientAccessGrant
from app.scripts.seed_admin import create_admin

ADMIN_EMAIL = "admin@infrawarden-test.example.com"
ADMIN_PASSWORD = "admin master password 2026"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


@pytest.fixture(autouse=True)
async def _seed_admin():
    await create_admin(ADMIN_EMAIL, ADMIN_PASSWORD)


async def _signup(client, email: str, role: str | None = None) -> dict:
    """Creates a user directly via the admin-invite flow (role defaults to 'user')
    and returns {access_token, user_id, public_key_b64}. Fake keys - no real crypto
    needed for these access-control-focused tests."""
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)

    invite = await client.post(
        "/api/v1/invites",
        json={"email": email, "role": role or "user"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert invite.status_code == 200, invite.text
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
    assert accept.status_code == 200, accept.text
    tokens = accept.json()

    me = await client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    return {
        "access_token": tokens["access_token"],
        "user_id": me.json()["id"],
        "public_key_b64": me.json()["public_key"],
    }


async def _login(client, email: str, password: str) -> str:
    # These tests only ever log in as the admin (whose real auth_hash we can compute
    # since create_admin used a real password); other users are only ever accessed
    # via the token minted at signup, matching what a real session would look like.
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


async def test_client_creation_auto_grants_superadmin(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()

    owner = await _signup(client, "owner@infrawarden-test.example.com")

    # Owner creates a client, wrapping the data key for themself AND for every
    # current superadmin (just the seeded admin here) - simulating what the
    # browser's client-creation flow does after fetching GET /users.
    resp = await client.post(
        "/api/v1/clients",
        json={
            "name": "Acme Corp",
            "description": "test client",
            "grants": [
                {"user_id": owner["user_id"], "wrapped_data_key": _b64(b"data-key-for-owner-000")},
                {"user_id": admin["id"], "wrapped_data_key": _b64(b"data-key-for-admin-000")},
            ],
        },
        headers=_auth(owner["access_token"]),
    )
    assert resp.status_code == 200, resp.text
    client_id = resp.json()["id"]
    assert resp.json()["wrapped_data_key"] == _b64(b"data-key-for-owner-000")

    # The superadmin never got an explicit "share" action, but can already see it.
    admin_get = await client.get(f"/api/v1/clients/{client_id}", headers=_auth(admin_token))
    assert admin_get.status_code == 200
    assert admin_get.json()["wrapped_data_key"] == _b64(b"data-key-for-admin-000")

    # A random third user with no grant gets a 404, not a 403 (existence isn't leaked).
    stranger = await _signup(client, "stranger@infrawarden-test.example.com")
    stranger_get = await client.get(f"/api/v1/clients/{client_id}", headers=_auth(stranger["access_token"]))
    assert stranger_get.status_code == 404


async def test_client_creation_rejects_grants_to_non_admin_strangers(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    owner = await _signup(client, "owner2@infrawarden-test.example.com")
    other_user = await _signup(client, "other2@infrawarden-test.example.com")

    resp = await client.post(
        "/api/v1/clients",
        json={
            "name": "Sneaky Corp",
            "grants": [
                {"user_id": owner["user_id"], "wrapped_data_key": _b64(b"k1")},
                {"user_id": other_user["user_id"], "wrapped_data_key": _b64(b"k2")},  # not an admin!
            ],
        },
        headers=_auth(owner["access_token"]),
    )
    assert resp.status_code == 400


async def _create_client(client, owner_token: str, owner_id: str, admin_id: str) -> str:
    resp = await client.post(
        "/api/v1/clients",
        json={
            "name": "Test Client",
            "grants": [
                {"user_id": owner_id, "wrapped_data_key": _b64(b"owner-data-key-0000")},
                {"user_id": admin_id, "wrapped_data_key": _b64(b"admin-data-key-0000")},
            ],
        },
        headers=_auth(owner_token),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


async def test_resource_lifecycle_versions_and_pending_change_banner(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]

    owner = await _signup(client, "owner3@infrawarden-test.example.com")
    client_id = await _create_client(client, owner["access_token"], owner["user_id"], admin_id)

    create_resp = await client.post(
        f"/api/v1/clients/{client_id}/resources",
        json={"resource_type": "host", "ciphertext": _b64(b"v1-ciphertext"), "nonce": _b64(b"n" * 24)},
        headers=_auth(owner["access_token"]),
    )
    assert create_resp.status_code == 200, create_resp.text
    resource = create_resp.json()
    resource_id = resource["id"]
    assert resource["has_pending_change"] is False
    assert resource["current_version"]["ciphertext"] == _b64(b"v1-ciphertext")

    # Superadmin already sees it too, in sync at v1, no explicit share needed.
    admin_view = await client.get(f"/api/v1/resources/{resource_id}", headers=_auth(admin_token))
    assert admin_view.status_code == 200
    assert admin_view.json()["has_pending_change"] is False

    # Owner edits it (e.g. IP changed) -> new version.
    edit_resp = await client.post(
        f"/api/v1/resources/{resource_id}/versions",
        json={"ciphertext": _b64(b"v2-ciphertext"), "nonce": _b64(b"n" * 24)},
        headers=_auth(owner["access_token"]),
    )
    assert edit_resp.status_code == 200, edit_resp.text
    assert edit_resp.json()["has_pending_change"] is False  # editor's own view auto-advances
    assert edit_resp.json()["current_version"]["ciphertext"] == _b64(b"v2-ciphertext")

    # Admin's view is now stale - a pending-change banner should show, old value still returned.
    admin_view2 = await client.get(f"/api/v1/resources/{resource_id}", headers=_auth(admin_token))
    assert admin_view2.json()["has_pending_change"] is True
    assert admin_view2.json()["current_version"]["ciphertext"] == _b64(b"v1-ciphertext")

    # Admin ignores it - banner-equivalent state updates but value is still old.
    ignore_resp = await client.post(f"/api/v1/resources/{resource_id}/ignore", headers=_auth(admin_token))
    assert ignore_resp.status_code == 200
    assert ignore_resp.json()["last_seen_version_id"] == ignore_resp.json()["latest_version_id"]
    assert ignore_resp.json()["current_version_id"] != ignore_resp.json()["latest_version_id"]

    admin_view3 = await client.get(f"/api/v1/resources/{resource_id}", headers=_auth(admin_token))
    assert admin_view3.json()["current_version"]["ciphertext"] == _b64(b"v1-ciphertext")  # still old

    # Admin accepts - now they're on v2.
    accept_resp = await client.post(f"/api/v1/resources/{resource_id}/accept", headers=_auth(admin_token))
    assert accept_resp.json()["current_version_id"] == accept_resp.json()["latest_version_id"]

    admin_view4 = await client.get(f"/api/v1/resources/{resource_id}", headers=_auth(admin_token))
    assert admin_view4.json()["current_version"]["ciphertext"] == _b64(b"v2-ciphertext")
    assert admin_view4.json()["has_pending_change"] is False

    # Full version history is intact and was never overwritten.
    versions = await client.get(f"/api/v1/resources/{resource_id}/versions", headers=_auth(owner["access_token"]))
    assert [v["ciphertext"] for v in versions.json()] == [_b64(b"v1-ciphertext"), _b64(b"v2-ciphertext")]


async def test_notes_are_append_only(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup(client, "owner4@infrawarden-test.example.com")
    client_id = await _create_client(client, owner["access_token"], owner["user_id"], admin_id)

    resource = (
        await client.post(
            f"/api/v1/clients/{client_id}/resources",
            json={"resource_type": "storage", "ciphertext": _b64(b"c"), "nonce": _b64(b"n" * 24)},
            headers=_auth(owner["access_token"]),
        )
    ).json()

    for note in (b"first note", b"second note"):
        r = await client.post(
            f"/api/v1/resources/{resource['id']}/notes",
            json={"ciphertext": _b64(note), "nonce": _b64(b"n" * 24)},
            headers=_auth(owner["access_token"]),
        )
        assert r.status_code == 200

    notes = await client.get(f"/api/v1/resources/{resource['id']}/notes", headers=_auth(owner["access_token"]))
    assert [n["ciphertext"] for n in notes.json()] == [_b64(b"first note"), _b64(b"second note")]


async def test_personal_hide_vs_owner_delete_and_superadmin_recovery(client, db_session):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup(client, "owner5@infrawarden-test.example.com")
    colleague = await _signup(client, "colleague5@infrawarden-test.example.com")

    create_resp = await client.post(
        "/api/v1/clients",
        json={
            "name": "Test Client",
            "grants": [
                {"user_id": owner["user_id"], "wrapped_data_key": _b64(b"owner-data-key-0000")},
                {"user_id": admin_id, "wrapped_data_key": _b64(b"admin-data-key-0000")},
            ],
        },
        headers=_auth(owner["access_token"]),
    )
    client_id = create_resp.json()["id"]

    # Colleague access simulates a completed share (task #4's sharing flow isn't
    # built yet - inserting the grant row directly is equivalent to what it will
    # produce: one more ClientAccessGrant row, nothing more).
    db_session.add(
        ClientAccessGrant(
            client_id=uuid.UUID(client_id),
            user_id=uuid.UUID(colleague["user_id"]),
            wrapped_data_key=b"colleague-data-key-000",
            granted_by_user_id=uuid.UUID(owner["user_id"]),
        )
    )
    await db_session.commit()

    resource = (
        await client.post(
            f"/api/v1/clients/{client_id}/resources",
            json={"resource_type": "network_device", "ciphertext": _b64(b"c"), "nonce": _b64(b"n" * 24)},
            headers=_auth(owner["access_token"]),
        )
    ).json()
    resource_id = resource["id"]

    # A grant holder who is neither the resource's owner nor a superadmin cannot
    # hard-delete - only hide it from their own view.
    forbidden = await client.delete(f"/api/v1/resources/{resource_id}", headers=_auth(colleague["access_token"]))
    assert forbidden.status_code == 403

    # The superadmin CAN hard-delete/archive even though they didn't create it -
    # same authority as the owner, since they already have universal access.
    hide_resp = await client.post(f"/api/v1/resources/{resource_id}/hide", headers=_auth(admin_token))
    assert hide_resp.status_code == 204
    admin_list = await client.get(f"/api/v1/clients/{client_id}/resources", headers=_auth(admin_token))
    assert admin_list.json()[0]["hidden"] is True
    # Owner still sees it completely normally - hide is per-viewer only.
    owner_list = await client.get(f"/api/v1/clients/{client_id}/resources", headers=_auth(owner["access_token"]))
    assert owner_list.json()[0]["hidden"] is False

    # Owner performs the real delete.
    delete_resp = await client.delete(f"/api/v1/resources/{resource_id}", headers=_auth(owner["access_token"]))
    assert delete_resp.status_code == 204

    # It's gone from the client's resource list for everyone, including the owner.
    owner_list2 = await client.get(f"/api/v1/clients/{client_id}/resources", headers=_auth(owner["access_token"]))
    assert owner_list2.json() == []
    owner_get = await client.get(f"/api/v1/resources/{resource_id}", headers=_auth(owner["access_token"]))
    assert owner_get.status_code == 404

    # But it shows up, fully intact, in the superadmin's deleted-items archive.
    deleted = await client.get("/api/v1/admin/deleted-resources", headers=_auth(admin_token))
    assert deleted.status_code == 200
    assert len(deleted.json()) == 1
    assert deleted.json()[0]["id"] == resource_id
    assert deleted.json()[0]["latest_version"]["ciphertext"] == _b64(b"c")

    # A non-admin cannot reach the archive at all.
    forbidden_archive = await client.get("/api/v1/admin/deleted-resources", headers=_auth(owner["access_token"]))
    assert forbidden_archive.status_code == 403

    # Superadmin restores it - nothing was ever actually lost.
    restore = await client.post(
        f"/api/v1/admin/deleted-resources/{resource_id}/restore", headers=_auth(admin_token)
    )
    assert restore.status_code == 204
    owner_list3 = await client.get(f"/api/v1/clients/{client_id}/resources", headers=_auth(owner["access_token"]))
    assert len(owner_list3.json()) == 1
    assert owner_list3.json()[0]["id"] == resource_id


async def test_update_client_name_and_description(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup(client, "owner6@infrawarden-test.example.com")
    client_id = await _create_client(client, owner["access_token"], owner["user_id"], admin_id)

    patch_resp = await client.patch(
        f"/api/v1/clients/{client_id}",
        json={"name": "Renamed Co", "description": "updated description"},
        headers=_auth(owner["access_token"]),
    )
    assert patch_resp.status_code == 200, patch_resp.text
    assert patch_resp.json()["name"] == "Renamed Co"
    assert patch_resp.json()["description"] == "updated description"

    fetched = await client.get(f"/api/v1/clients/{client_id}", headers=_auth(owner["access_token"]))
    assert fetched.json()["name"] == "Renamed Co"

    # A stranger with no grant can't rename it.
    stranger = await _signup(client, "stranger6@infrawarden-test.example.com")
    denied = await client.patch(
        f"/api/v1/clients/{client_id}", json={"name": "Hijacked"}, headers=_auth(stranger["access_token"])
    )
    assert denied.status_code == 404


async def test_create_client_rejects_grants_missing_a_current_superadmin(client):
    """A grant set that silently omits a superadmin would leave that superadmin
    permanently unable to decrypt the client, with no later mechanism to detect
    or repair it - must be rejected outright, not just checked for extra
    non-admin recipients."""
    owner = await _signup(client, "owner7@infrawarden-test.example.com")
    resp = await client.post(
        "/api/v1/clients",
        json={"name": "Missing Admin Co", "grants": [{"user_id": owner["user_id"], "wrapped_data_key": _b64(b"k")}]},
        headers=_auth(owner["access_token"]),
    )
    assert resp.status_code == 400


async def test_create_client_rejects_duplicate_grant_user_ids(client):
    owner = await _signup(client, "owner8@infrawarden-test.example.com")
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    resp = await client.post(
        "/api/v1/clients",
        json={
            "name": "Dup Co",
            "grants": [
                {"user_id": owner["user_id"], "wrapped_data_key": _b64(b"k1")},
                {"user_id": admin_id, "wrapped_data_key": _b64(b"k2")},
                {"user_id": admin_id, "wrapped_data_key": _b64(b"k3")},
            ],
        },
        headers=_auth(owner["access_token"]),
    )
    assert resp.status_code == 400


async def test_delete_client_blocked_while_resources_exist(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup(client, "owner9@infrawarden-test.example.com")
    client_id = await _create_client(client, owner["access_token"], owner["user_id"], admin_id)

    await client.post(
        f"/api/v1/clients/{client_id}/resources",
        json={"resource_type": "host", "ciphertext": _b64(b"c"), "nonce": _b64(b"n" * 24)},
        headers=_auth(owner["access_token"]),
    )

    blocked = await client.delete(f"/api/v1/clients/{client_id}", headers=_auth(owner["access_token"]))
    assert blocked.status_code == 409

    # An empty client (never had a resource) can still be deleted.
    empty_client_id = await _create_client(client, owner["access_token"], owner["user_id"], admin_id)
    allowed = await client.delete(f"/api/v1/clients/{empty_client_id}", headers=_auth(owner["access_token"]))
    assert allowed.status_code == 204
