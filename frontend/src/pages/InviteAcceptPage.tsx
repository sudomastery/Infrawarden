import { FormEvent, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  DEFAULT_KDF_PARAMS,
  deriveAuthHash,
  deriveStretchKey,
  generateKdfSalt,
  generateKeypair,
  toBase64,
  wrapPrivateKey,
} from "../lib/crypto";
import { acceptInvite, ApiError, getInvite, getMe, InvitePublic } from "../lib/api";
import { useVaultStore } from "../store/vaultStore";
import AuthCard from "../components/AuthCard";
import { ErrorText, FormInput, FormLabel, PrimaryButton } from "../components/form";

export default function InviteAcceptPage() {
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();
  const [invite, setInvite] = useState<InvitePublic | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const setSession = useVaultStore((s) => s.setSession);
  const setCurrentUser = useVaultStore((s) => s.setCurrentUser);
  const setPrivateKey = useVaultStore((s) => s.setPrivateKey);

  useEffect(() => {
    if (!token) return;
    getInvite(token)
      .then(setInvite)
      .catch((err) => setLoadError(err instanceof ApiError ? err.message : "Invite not found or expired"));
  }, [token]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!token) return;
    setError(null);
    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }
    if (password.length < 12) {
      setError("Use at least 12 characters for your master password");
      return;
    }
    setSubmitting(true);
    try {
      const salt = await generateKdfSalt();
      const stretchKey = await deriveStretchKey(password, salt, DEFAULT_KDF_PARAMS);
      const { publicKey, privateKey } = await generateKeypair();
      const { ciphertext, nonce } = await wrapPrivateKey(privateKey, stretchKey);
      const authHash = await deriveAuthHash(password, stretchKey);

      const tokens = await acceptInvite(token, {
        public_key: await toBase64(publicKey),
        wrapped_private_key: await toBase64(ciphertext),
        wrapped_private_key_nonce: await toBase64(nonce),
        kdf_salt: await toBase64(salt),
        kdf_ops_limit: DEFAULT_KDF_PARAMS.opsLimit,
        kdf_mem_limit: DEFAULT_KDF_PARAMS.memLimit,
        auth_hash: authHash,
      });
      setSession(tokens.access_token, tokens.refresh_token);

      const me = await getMe();
      setCurrentUser({
        id: me.id,
        email: me.email,
        role: me.role,
        status: me.status,
        publicKey: me.public_key,
        wrappedPrivateKey: me.wrapped_private_key,
        wrappedPrivateKeyNonce: me.wrapped_private_key_nonce,
        kdfSalt: me.kdf_salt,
        kdfOpsLimit: me.kdf_ops_limit,
        kdfMemLimit: me.kdf_mem_limit,
      });
      setPrivateKey(privateKey);

      navigate("/clients");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not accept invite");
    } finally {
      setSubmitting(false);
    }
  }

  if (loadError) {
    return (
      <AuthCard title="Invite not found">
        <p className="text-sm text-gray-600">{loadError}</p>
      </AuthCard>
    );
  }

  if (!invite) {
    return (
      <AuthCard title="Loading invite...">
        <p className="text-sm text-gray-400">One moment.</p>
      </AuthCard>
    );
  }

  return (
    <AuthCard title={`Set up your vault for ${invite.email}`}>
      <p className="mb-4 text-xs text-gray-500">
        Your master password encrypts your vault end to end - it never leaves your browser, and
        nobody (including an Infrawarden admin) can recover it if you forget it.
      </p>
      <form onSubmit={handleSubmit}>
        <FormLabel htmlFor="password">Master password</FormLabel>
        <FormInput
          id="password"
          type="password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
        />
        <FormLabel htmlFor="confirmPassword">Confirm master password</FormLabel>
        <FormInput
          id="confirmPassword"
          type="password"
          required
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          autoComplete="new-password"
        />
        <ErrorText>{error}</ErrorText>
        <PrimaryButton type="submit" disabled={submitting}>
          {submitting ? "Setting up..." : "Create vault"}
        </PrimaryButton>
      </form>
    </AuthCard>
  );
}
