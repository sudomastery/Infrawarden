// libsodium-wrappers-sumo ships its own .d.ts, but its package.json "exports" map
// doesn't expose a "types" condition for the ESM entry point, so TypeScript's
// "bundler" module resolution can't find it automatically. This covers exactly the
// surface lib/crypto.ts uses, rather than pulling in `any`.
declare module "libsodium-wrappers-sumo" {
  interface KeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
    keyType: string;
  }

  interface BaseSodium {
    ready: Promise<void>;

    crypto_box_keypair(): KeyPair;
    crypto_box_seal(message: Uint8Array, publicKey: Uint8Array): Uint8Array;
    crypto_box_seal_open(ciphertext: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array): Uint8Array;

    crypto_secretbox_NONCEBYTES: number;
    crypto_secretbox_easy(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
    crypto_secretbox_open_easy(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;

    crypto_pwhash_SALTBYTES: number;
    crypto_pwhash_ALG_ARGON2ID13: number;
    crypto_pwhash(
      keyLength: number,
      password: string,
      salt: Uint8Array,
      opsLimit: number,
      memLimit: number,
      algorithm: number,
    ): Uint8Array;

    crypto_generichash(hashLength: number, message: Uint8Array, key?: Uint8Array | null): Uint8Array;

    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: number;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
      message: Uint8Array,
      additionalData: Uint8Array | null,
      secretNonce: null,
      publicNonce: Uint8Array,
      key: Uint8Array,
    ): Uint8Array;
    crypto_aead_xchacha20poly1305_ietf_decrypt(
      secretNonce: null,
      ciphertext: Uint8Array,
      additionalData: Uint8Array | null,
      publicNonce: Uint8Array,
      key: Uint8Array,
    ): Uint8Array;

    randombytes_buf(length: number): Uint8Array;

    from_string(str: string): Uint8Array;
    to_string(bytes: Uint8Array): string;
    to_hex(bytes: Uint8Array): string;

    base64_variants: { ORIGINAL: number };
    to_base64(bytes: Uint8Array, variant: number): string;
    from_base64(str: string, variant: number): Uint8Array;
  }

  const sodium: BaseSodium;
  export default sodium;
}
