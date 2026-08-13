# Infrawarden Architecture

This is the living reference for how Infrawarden actually works. It mirrors the crypto design agreed
on before implementation started; update it whenever the mechanism changes, don't let it drift from
the code.

## What Infrawarden is

A password-manager-style vault, organized per client/environment instead of per login, built for
people who work across many client sites and need to hand a scoped, temporary slice of infrastructure
credentials to an AI coding agent (Claude Code) without ever pasting plaintext secrets into a chat.

## Primitives

All cryptography uses libsodium: `libsodium-wrappers-sumo` in the browser (WASM), `PyNaCl` on the
backend. One library family on both sides avoids wire-format mismatches between client and server AEAD
implementations.

- `crypto_pwhash` (Argon2id) - master-password KDF
- X25519 keypairs (`crypto_box_keypair`) - one per user
- `crypto_box_seal` / `crypto_box_seal_open` - wraps a symmetric key to a specific user's public key
- XChaCha20-Poly1305-IETF AEAD - all content encryption
- Keyed BLAKE2b (`crypto_generichash` with a key) - PRF for deriving a token-specific wrap key

## Master password -> vault plaintext (fully client-side)

1. On invite acceptance, the browser generates an X25519 keypair locally.
2. `stretch_key = crypto_pwhash(master_password, salt, ops_limit, mem_limit)` - never leaves the browser.
3. `wrapped_private_key = crypto_secretbox(private_key, nonce, key=stretch_key)`.
4. `auth_hash = crypto_generichash(message=master_password, key=stretch_key)` - a login verifier that
   reveals nothing about the master password or `stretch_key`.
5. The browser sends `{public_key, wrapped_private_key, wrapped_private_key_nonce, kdf_salt,
   kdf_ops_limit, kdf_mem_limit, auth_hash}`. The server rehashes `auth_hash` with argon2-cffi before
   storing it, but never sees the master password, `stretch_key`, or the private key.
6. Login re-derives `stretch_key`/`auth_hash` client-side - but a fresh browser session has no way to
   know a user's `kdf_salt`/`kdf_ops_limit`/`kdf_mem_limit` yet, so it first calls `POST
   /api/v1/auth/prelogin` with just the email to fetch them. Unknown emails get a deterministic fake
   salt with platform-default params instead of a 404, so this can't be used to enumerate accounts
   (the same pattern Bitwarden's own prelogin endpoint uses). The server verifies `auth_hash` and issues
   a JWT session (access token short-lived, silently refreshed via `POST /api/v1/auth/refresh` on a 401
   using the longer-lived refresh token - both persisted client-side, since neither is vault key
   material). Vault unlock is a separate client-side step: fetch `wrapped_private_key`/`kdf_*`, unwrap
   locally with `stretch_key`. The unwrapped private key lives only in an in-memory store - never
   `localStorage` - and is cleared on logout or tab close.
7. Unwrapping a client vault: `crypto_box_seal_open(wrapped_data_key, my_keypair)` using the per-user
   wrapped copy in `client_access_grants`.
8. Sharing: the grantor (who already has the data key unwrapped) fetches the colleague's public key and
   runs `crypto_box_seal(data_key, colleague_public_key)` client-side, then POSTs the result. No
   interaction from the colleague is required, and no private key is ever exposed.

## Agent access via a scoped, TTL-limited token

The problem this has to solve: the server must be able to decrypt on behalf of a valid token *later*,
possibly while the human who created it is offline, without ever holding standing plaintext access to
any vault.

The mechanism: **the client's data key is re-wrapped under a key derived from the token's own bearer
secret, at token-creation time, while the vault is unlocked in the browser** - not under any server-held
master key.

**Token creation** (browser, data key already unwrapped in memory):
1. Browser generates `token_secret` (32 random bytes, hex-encoded for display/transmission -
   simpler than base62 across two languages with no custom encoder needed on either side,
   verified byte-for-byte identical between libsodium-wrappers-sumo and PyNaCl).
2. `token_wrap_key = crypto_generichash(message="infrawarden-token-wrap-v1" || token_id, key=token_secret)`.
3. `wrapped_data_key = AEAD_encrypt(data_key, nonce, key=token_wrap_key)`.
4. `token_hash = sha256(token_secret)`.
5. Browser POSTs `{client_id, scope, ttl_seconds, token_hash, wrapped_data_key, wrapped_data_key_nonce}`.
   **The server never receives `token_secret` or the plaintext data key.**
6. Browser composes `token_id.token_secret`, shown to the user exactly once.

**Agent request** (`Authorization: Bearer <token_id>.<token_secret>`):
1. Server looks up the token, checks `revoked_at is null` and `expires_at > now()`.
2. Recomputes `sha256(token_secret)`, constant-time-compares against `token_hash`.
3. Derives `token_wrap_key` from the now-known `token_secret`, AEAD-decrypts `wrapped_data_key` into the
   plaintext data key, **in request-handler memory only**.
4. Uses the data key to decrypt only the resources in scope, at each resource's version pinned to the
   token creator's `resource_user_state.current_version_id` (see below), renders to markdown, returns
   it, and lets everything fall out of scope at request end.
5. Updates `last_used_at`.

**Physical expiry, not just an app-level check**: on first access after expiry, or on explicit revoke,
the server nulls `wrapped_data_key`/`wrapped_data_key_nonce` in the same transaction as marking the
token revoked - so even a correct `token_secret` can no longer recover anything after that point, not
just "the app refuses." A periodic sweep job is cheap defense in depth for tokens that expire but are
never reaccessed.

**Why not a server-held master KEK**: that would give the server (or anyone who compromises it) a
single key that decrypts every vault at any time, with TTL/scope enforcement living entirely in
application logic a compromised operator could bypass. Tying decrypt capability to the token secret
means a DB-only breach with no captured live bearer tokens exposes nothing.

## Residual trust assumptions (stated plainly, not glossed over)

- The FastAPI process holds the plaintext data key and doc content in memory for the duration of an
  agent request. This is the accepted cost of server-side decrypt - not zero-knowledge from the agent's
  perspective, only from the at-rest/DB perspective.
- A resource-scoped token's derived data key can cryptographically decrypt the *entire* client vault
  (there is one data key per client, not one per resource). Scope restriction to "just this host" or
  "just Storage" is enforced by application query logic, not cryptographic separation. True per-resource
  key isolation is deferred - meaningfully more complexity than the MVP needs.
- Grant revocation and token revocation don't undo already-exfiltrated plaintext, and grant revocation
  doesn't rotate the underlying data key. No key-rotation tooling exists yet.
- Master password loss is unrecoverable by design - the admin never has a user's private key. The
  workaround is manual: another grant-holder re-shares to a freshly re-invited identity.
- `token_hash` intentionally uses plain SHA-256, not a slow KDF - correct because `token_secret` is
  high-entropy random, not a guessable password.

## Per-user version divergence ("PR-style" credential changes)

There is no single mutable "current value" per resource. Every edit creates a new immutable
`resource_versions` row (same client data key, new ciphertext, never overwritten or deleted). Each user
has their own `resource_user_state` row per resource tracking which version is *their* current value.

- A brand-new resource, or a newly-granted user, starts pointed at the head version - nothing to
  reconcile yet.
- When someone edits a resource, only their own pointer auto-advances. Everyone else's pointer stays put,
  which is exactly what surfaces a pending-change banner (`latest_version_id != current_version_id`) in
  their UI.
- Diffs are computed client-side: the browser decrypts both versions locally and does a field-by-field
  comparison. No plaintext change summary is ever stored server-side.
- "Accept" moves the pointer to the latest version. "Ignore" just dismisses the banner
  (`last_seen_version_id`) without adopting the new value - genuinely divergent values can persist
  until the user chooses to reconcile them.
- An API token renders whatever version its creator's pointer is on - "the agent sees my instance."

See the plan file this was implemented from for the full data model and API surface at
`~/.claude/plans/i-want-to-build-mutable-hammock.md` on the machine this was built on (not part of this
repo).

## Superadmin access model

The `admin` role is the platform's superadmin tier and needs **guaranteed** decrypt access to every
client, including ones created before a given user became superadmin. The base per-user-grant crypto
model doesn't give this for free, so it's made explicit:

- **On every client creation**, the creator's browser wraps the new data key not just for itself but
  for every *current* superadmin's public key too, in the same request. No extra step for the creator.
- **On promoting a user to superadmin**, existing clients need a bulk reconciliation - the promotion
  itself can't retroactively decrypt anything. The promoting superadmin (who already holds a wrapped
  copy of every existing client's data key) must be online with an unlocked vault to run it: their
  browser iterates every client, unwraps each data key, wraps a fresh copy for the newly-promoted
  user's public key, and POSTs the new grants in bulk. This is explicitly **not instant** - it depends
  on a superadmin session being available to perform it.
- **Trust trade-off, stated plainly**: every superadmin account becomes a maximally high-value target -
  a compromised one can decrypt everything on the platform, by design. This is a deliberate, narrower
  version of a master-key capability: still per-account asymmetric keys (compromising one superadmin
  doesn't hand over other users' private keys; revoking a superadmin is a normal grant-revoke, not a
  platform-wide re-key), not a single shared server-held recovery key - but it's a real concentration of
  risk worth being honest about. Superadmin accounts should get the strongest master-password guidance;
  MFA on top of the master password is valuable future work, not designed here.

## Deletion model: personal hide vs. owner delete vs. superadmin recovery

"Delete" means different things depending on who does it, so credentials are never silently destroyed:

- **Non-owner grant holder deletes a resource**: purely cosmetic and personal - sets
  `resource_user_state.hidden_at` for that one user. The resource, its full version history, and every
  other grant holder's access are completely untouched.
- **Owner or superadmin deletes a resource** (owner = whoever created that specific resource, not
  necessarily whoever created the client - a superadmin has the same authority regardless of who
  created it, consistent with already having universal decrypt access): `resources.status` flips to
  `pending_delete`, `deleted_by_user_id`/`deleted_at` are set. The resource disappears from every grant
  holder's active view and from the agent-facing doc immediately. It is never hard-deleted -
  `resource_versions`/`resource_notes` rows are untouched.
- **Superadmin recovery**: superadmins have a Deleted Items dashboard listing every `pending_delete`
  resource across every client (decryptable, since they hold every client's data key). They can restore
  a resource (`status` back to `active`) or leave it archived. This is the actual mechanism behind "no
  credentials are ever lost": deletion by a non-superadmin is never truly destructive, only a status
  flip a superadmin can always undo.

## What's deliberately out of scope for the MVP

Audit log UI, SSO, mobile app, automated key rotation, billing/multi-tenancy-as-product, RBAC beyond
admin/user, and the email-capture self-documentation pipeline (its schema - `client_timeline_entries` -
is reserved, but ingestion/matching/summarization is fast-follow work). OAuth login is a future
extension point; it has a genuine unresolved tension with E2E vault encryption (no master password to
derive keys from for an OAuth-only user) that needs its own design pass.
