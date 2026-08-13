"""One-off local bootstrap: creates the first superadmin account.

Every other account is created through the normal invite flow, where the browser
does all key generation and master-password stretching client-side and the server
never sees a plaintext private key or master password. There is no browser involved
in bootstrapping the very first account, so THIS SCRIPT is the one deliberate,
clearly-marked exception: it performs the client-side crypto steps itself, locally,
using the operator's own machine. Run it once, over a trusted local connection to
the database - never expose this as an HTTP endpoint.

Usage:
    python -m app.scripts.seed_admin --email admin@example.com
"""

import argparse
import asyncio
import getpass

import nacl.utils

from app.core.crypto import (
    PWHASH_MEMLIMIT_DEFAULT,
    PWHASH_OPSLIMIT_DEFAULT,
    PWHASH_SALT_BYTES,
    generate_keypair,
    keyed_blake2b,
    pwhash_argon2id,
    secretbox_encrypt,
)
from app.core.security import hash_auth_hash
from app.db.session import async_session_factory
from app.models.user import User, UserRole, UserStatus


async def create_admin(email: str, password: str) -> None:
    salt = nacl.utils.random(PWHASH_SALT_BYTES)
    stretch_key = pwhash_argon2id(password.encode(), salt, PWHASH_OPSLIMIT_DEFAULT, PWHASH_MEMLIMIT_DEFAULT)

    private_key, public_key = generate_keypair()
    wrapped_private_key, nonce = secretbox_encrypt(private_key, stretch_key)

    # Wire format for auth_hash is always a string (hex here) - the browser does the
    # same conversion, since JSON can't carry raw binary. The server never interprets
    # it as bytes again, only argon2-hashes/verifies it as an opaque string.
    auth_hash = keyed_blake2b(password.encode(), key=stretch_key).hex()

    user = User(
        email=email,
        role=UserRole.admin,
        status=UserStatus.active,
        public_key=public_key,
        wrapped_private_key=wrapped_private_key,
        wrapped_private_key_nonce=nonce,
        kdf_salt=salt,
        kdf_ops_limit=PWHASH_OPSLIMIT_DEFAULT,
        kdf_mem_limit=PWHASH_MEMLIMIT_DEFAULT,
        auth_hash=hash_auth_hash(auth_hash),
    )

    async with async_session_factory() as session:
        session.add(user)
        await session.commit()

    print(f"Created superadmin {email}. Log in with the master password you just entered.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True)
    args = parser.parse_args()

    password = getpass.getpass("Master password for the new superadmin: ")
    confirm = getpass.getpass("Confirm master password: ")
    if password != confirm:
        raise SystemExit("Passwords did not match.")
    if len(password) < 12:
        raise SystemExit("Use at least 12 characters for a superadmin master password.")

    asyncio.run(create_admin(args.email, password))


if __name__ == "__main__":
    main()
