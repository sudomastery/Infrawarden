import { FormEvent, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { deriveAuthHash, deriveStretchKey, fromBase64, unwrapPrivateKey } from "../lib/crypto";
import { ApiError, getMe, login, prelogin } from "../lib/api";
import { useVaultStore } from "../store/vaultStore";
import AuthCard from "../components/AuthCard";
import { ErrorText, FormInput, FormLabel, PrimaryButton } from "../components/form";

export default function LoginPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const setSession = useVaultStore((s) => s.setSession);
  const setCurrentUser = useVaultStore((s) => s.setCurrentUser);
  const setPrivateKey = useVaultStore((s) => s.setPrivateKey);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const kdf = await prelogin(email);
      const salt = await fromBase64(kdf.kdf_salt);
      const stretchKey = await deriveStretchKey(password, salt, {
        opsLimit: kdf.kdf_ops_limit,
        memLimit: kdf.kdf_mem_limit,
      });
      const authHash = await deriveAuthHash(password, stretchKey);

      const tokens = await login(email, authHash);
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

      // We already have the password in hand from this same submit, so unlock the
      // vault immediately rather than making the user re-enter it on a /unlock page -
      // that page exists for returning to an already-authenticated session after a
      // reload, not for a fresh login.
      const wrappedPrivateKey = await fromBase64(me.wrapped_private_key);
      const nonce = await fromBase64(me.wrapped_private_key_nonce);
      const privateKey = await unwrapPrivateKey(wrappedPrivateKey, nonce, stretchKey);
      setPrivateKey(privateKey);

      navigate("/clients");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthCard title="Log in">
      <form onSubmit={handleSubmit}>
        <FormLabel htmlFor="email">Email</FormLabel>
        <FormInput
          id="email"
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          autoComplete="email"
        />
        <FormLabel htmlFor="password">Master password</FormLabel>
        <FormInput
          id="password"
          type="password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
        />
        <ErrorText>{error}</ErrorText>
        <PrimaryButton type="submit" disabled={loading}>
          {loading ? "Logging in..." : "Log in"}
        </PrimaryButton>
      </form>
      <p className="mt-4 text-center text-xs text-gray-400">
        Need access? Ask an admin for an invite link. <Link className="text-primary-600" to="/unlock">Unlock</Link>
      </p>
    </AuthCard>
  );
}
