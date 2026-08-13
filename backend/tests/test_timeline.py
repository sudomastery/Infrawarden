"""Exercises the client-level timeline: append-only manual entries now, reserved
schema (source='email') for the not-yet-built ingestion pipeline later."""

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
    invite = await client.post("/api/v1/invites", json={"email": email, "role": "user"}, headers=_auth(admin_token))
    raw_token = invite.json()["token"]
    accept = await client.post(
        f"/api/v1/invites/{raw_token}/accept",
        json={
            "public_key": _b64(email.encode().ljust(32, b"0")[:32]),
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
    return {"access_token": tokens["access_token"], "user_id": me.json()["id"]}


async def test_timeline_entries_are_manual_and_append_only(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup(client, "owner@infrawarden-test.example.com")

    client_resp = await client.post(
        "/api/v1/clients",
        json={
            "name": "Timeline Test Co",
            "grants": [
                {"user_id": owner["user_id"], "wrapped_data_key": _b64(b"owner-key")},
                {"user_id": admin_id, "wrapped_data_key": _b64(b"admin-key")},
            ],
        },
        headers=_auth(owner["access_token"]),
    )
    client_id = client_resp.json()["id"]

    for text in (b"server rebooted for patching", b"confirmed healthy after reboot"):
        r = await client.post(
            f"/api/v1/clients/{client_id}/timeline",
            json={"ciphertext": _b64(text), "nonce": _b64(b"n" * 24)},
            headers=_auth(owner["access_token"]),
        )
        assert r.status_code == 200, r.text
        assert r.json()["source"] == "manual"
        assert r.json()["created_by_user_id"] == owner["user_id"]

    entries = await client.get(f"/api/v1/clients/{client_id}/timeline", headers=_auth(owner["access_token"]))
    assert entries.status_code == 200
    assert [e["ciphertext"] for e in entries.json()] == [
        _b64(b"server rebooted for patching"),
        _b64(b"confirmed healthy after reboot"),
    ]

    # Superadmin already sees it too, without an explicit share.
    admin_view = await client.get(f"/api/v1/clients/{client_id}/timeline", headers=_auth(admin_token))
    assert admin_view.status_code == 200
    assert len(admin_view.json()) == 2


async def test_timeline_requires_client_access(client):
    admin_token = await _login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_id = (await client.get("/api/v1/users/me", headers=_auth(admin_token))).json()["id"]
    owner = await _signup(client, "owner2@infrawarden-test.example.com")
    stranger = await _signup(client, "stranger2@infrawarden-test.example.com")

    client_resp = await client.post(
        "/api/v1/clients",
        json={
            "name": "Private Co",
            "grants": [
                {"user_id": owner["user_id"], "wrapped_data_key": _b64(b"owner-key")},
                {"user_id": admin_id, "wrapped_data_key": _b64(b"admin-key")},
            ],
        },
        headers=_auth(owner["access_token"]),
    )
    client_id = client_resp.json()["id"]

    denied = await client.post(
        f"/api/v1/clients/{client_id}/timeline",
        json={"ciphertext": _b64(b"snooping"), "nonce": _b64(b"n" * 24)},
        headers=_auth(stranger["access_token"]),
    )
    assert denied.status_code == 404
