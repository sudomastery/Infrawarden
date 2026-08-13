// All client-side vault cryptography lives here. Mirrors backend/app/core/crypto.py -
// same libsodium primitives on both sides so wire formats match exactly. See
// docs/ARCHITECTURE.md for why each primitive was chosen.
import sodium from "libsodium-wrappers-sumo";

let readyPromise: Promise<typeof sodium> | null = null;

async function ready(): Promise<typeof sodium> {
  if (!readyPromise) {
    readyPromise = sodium.ready.then(() => sodium);
  }
  return readyPromise;
}

export interface KdfParams {
  opsLimit: number;
  memLimit: number;
}

// Matches backend PWHASH_OPSLIMIT_DEFAULT / PWHASH_MEMLIMIT_DEFAULT (argon2id MODERATE).
export const DEFAULT_KDF_PARAMS: KdfParams = {
  opsLimit: 3,
  memLimit: 268435456,
};

export interface Keypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export async function generateKeypair(): Promise<Keypair> {
  const s = await ready();
  const kp = s.crypto_box_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

/** A fresh random symmetric data key for a new client vault. */
export async function generateDataKey(): Promise<Uint8Array> {
  const s = await ready();
  return s.randombytes_buf(32);
}

export async function generateKdfSalt(): Promise<Uint8Array> {
  const s = await ready();
  return s.randombytes_buf(s.crypto_pwhash_SALTBYTES);
}

/** Derives the 32-byte stretch key from the master password. Never leaves the caller. */
export async function deriveStretchKey(
  password: string,
  salt: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<Uint8Array> {
  const s = await ready();
  return s.crypto_pwhash(
    32,
    password,
    salt,
    params.opsLimit,
    params.memLimit,
    s.crypto_pwhash_ALG_ARGON2ID13,
  );
}

/** The login verifier sent to the server - never the password or stretch key itself. */
export async function deriveAuthHash(password: string, stretchKey: Uint8Array): Promise<string> {
  const s = await ready();
  const digest = s.crypto_generichash(32, s.from_string(password), stretchKey);
  return s.to_hex(digest);
}

/** crypto_secretbox (XSalsa20-Poly1305) - wraps the private key with the stretch key. */
export async function wrapPrivateKey(
  privateKey: Uint8Array,
  stretchKey: Uint8Array,
): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
  const s = await ready();
  const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);
  const ciphertext = s.crypto_secretbox_easy(privateKey, nonce, stretchKey);
  return { ciphertext, nonce };
}

export async function unwrapPrivateKey(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  stretchKey: Uint8Array,
): Promise<Uint8Array> {
  const s = await ready();
  return s.crypto_secretbox_open_easy(ciphertext, nonce, stretchKey);
}

/** crypto_box_seal - wraps a symmetric key (e.g. a client data key) to a public key. */
export async function sealForPublicKey(plaintext: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
  const s = await ready();
  return s.crypto_box_seal(plaintext, publicKey);
}

export async function unsealWithKeypair(
  sealed: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
): Promise<Uint8Array> {
  const s = await ready();
  return s.crypto_box_seal_open(sealed, publicKey, privateKey);
}

/** XChaCha20-Poly1305-IETF AEAD - used for resource/note content and token-wrapped data keys. */
export async function aeadEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
  const s = await ready();
  const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, null, null, nonce, key);
  return { ciphertext, nonce };
}

export async function aeadDecrypt(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
  const s = await ready();
  return s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, nonce, key);
}

/** Convenience wrappers for resource/note content, which is always JSON before encryption. */
export async function encryptJson(
  value: unknown,
  key: Uint8Array,
): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
  const s = await ready();
  return aeadEncrypt(s.from_string(JSON.stringify(value)), key);
}

export async function decryptJson<T>(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Promise<T> {
  const s = await ready();
  const plaintext = await aeadDecrypt(ciphertext, nonce, key);
  return JSON.parse(s.to_string(plaintext)) as T;
}

export async function toBase64(bytes: Uint8Array): Promise<string> {
  const s = await ready();
  return s.to_base64(bytes, s.base64_variants.ORIGINAL);
}

export async function fromBase64(b64: string): Promise<Uint8Array> {
  const s = await ready();
  return s.from_base64(b64, s.base64_variants.ORIGINAL);
}
