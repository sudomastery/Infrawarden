"""libsodium primitives shared by the token-decrypt path (app/services/token_service.py)
and the local admin-seed bootstrap script. Everyday user vault crypto (master password
KDF, private-key wrapping, sharing) happens client-side in the browser - this module is
NOT used on the normal request path for that, only for the two exceptions above."""

import nacl.bindings
import nacl.encoding
import nacl.hash
import nacl.pwhash
import nacl.public
import nacl.secret
import nacl.utils

AEAD_KEY_BYTES = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
AEAD_NONCE_BYTES = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

# Argon2id defaults for the seed-admin bootstrap script only (see pwhash_argon2id).
# The browser uses its own, independently-configured ops/mem limits for real users -
# these constants never gate normal login/unlock.
PWHASH_SALT_BYTES = nacl.pwhash.argon2id.SALTBYTES
PWHASH_OPSLIMIT_DEFAULT = nacl.pwhash.argon2id.OPSLIMIT_MODERATE
PWHASH_MEMLIMIT_DEFAULT = nacl.pwhash.argon2id.MEMLIMIT_MODERATE


def generate_keypair() -> tuple[bytes, bytes]:
    """Returns (private_key, public_key), 32 bytes each (X25519)."""
    key = nacl.public.PrivateKey.generate()
    return bytes(key), bytes(key.public_key)


def pwhash_argon2id(password: bytes, salt: bytes, ops_limit: int, mem_limit: int) -> bytes:
    """Derives a 32-byte key from a password. `salt` must be nacl.pwhash.argon2id.SALTBYTES long."""
    return nacl.pwhash.argon2id.kdf(
        AEAD_KEY_BYTES, password, salt, opslimit=ops_limit, memlimit=mem_limit
    )


def secretbox_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """crypto_secretbox (XSalsa20-Poly1305) - used specifically for wrapping a user's
    private key with their master-password-derived stretch key, per the crypto design.
    Distinct from aead_encrypt below, which is XChaCha20-Poly1305-IETF and used for
    everything else (resource/note/token content)."""
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    box = nacl.secret.SecretBox(key)
    ciphertext = box.encrypt(plaintext, nonce).ciphertext
    return ciphertext, nonce


def secretbox_decrypt(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    box = nacl.secret.SecretBox(key)
    return box.decrypt(ciphertext, nonce)


def aead_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """XChaCha20-Poly1305-IETF AEAD encrypt. Returns (ciphertext, nonce)."""
    nonce = nacl.utils.random(AEAD_NONCE_BYTES)
    ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, None, nonce, key)
    return ciphertext, nonce


def aead_decrypt(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    """Raises nacl.exceptions.CryptoError on tampered/wrong-key ciphertext."""
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, None, nonce, key)


def keyed_blake2b(message: bytes, key: bytes, digest_size: int = 32) -> bytes:
    return nacl.hash.blake2b(message, digest_size=digest_size, key=key, encoder=nacl.encoding.RawEncoder)


TOKEN_WRAP_KEY_DOMAIN = b"infrawarden-token-wrap-v1:"


def derive_token_wrap_key(token_id: str, token_secret: bytes) -> bytes:
    """Derives the key that wraps a client's data key for a scoped API token.
    token_id (the token's own UUID, as its string form) is folded in as domain
    separation context so the same token_secret bytes can never accidentally
    derive the same key for two different tokens. Must match the browser's
    lib/crypto.ts derivation exactly - see docs/ARCHITECTURE.md."""
    return keyed_blake2b(TOKEN_WRAP_KEY_DOMAIN + token_id.encode(), key=token_secret)


def seal_for_public_key(plaintext: bytes, public_key: bytes) -> bytes:
    """crypto_box_seal - wraps `plaintext` (e.g. a client data key) so only the holder
    of the matching private key can open it. Self-contained ciphertext, no nonce needed."""
    box = nacl.public.SealedBox(nacl.public.PublicKey(public_key))
    return box.encrypt(plaintext)


def unseal_with_private_key(sealed: bytes, private_key: bytes) -> bytes:
    box = nacl.public.SealedBox(nacl.public.PrivateKey(private_key))
    return box.decrypt(sealed)
