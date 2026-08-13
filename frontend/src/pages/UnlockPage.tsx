import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { deriveStretchKey, fromBase64, unwrapPrivateKey } from "../lib/crypto";
import { useVaultStore } from "../store/vaultStore";
import AuthCard from "../components/AuthCard";
import { ErrorText, FormInput, FormLabel, PrimaryButton } from "../components/form";

export default function UnlockPage() {
  const navigate = useNavigate();
  const currentUser = useVaultStore((s) => s.currentUser);
  const setPrivateKey = useVaultStore((s) => s.setPrivateKey);
  const clearSession = useVaultStore((s) => s.clearSession);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  if (!currentUser) {
    navigate("/login");
    return null;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const salt = await fromBase64(currentUser!.kdfSalt);
      const stretchKey = await deriveStretchKey(password, salt, {
        opsLimit: currentUser!.kdfOpsLimit,
        memLimit: currentUser!.kdfMemLimit,
      });
      const wrappedPrivateKey = await fromBase64(currentUser!.wrappedPrivateKey);
      const nonce = await fromBase64(currentUser!.wrappedPrivateKeyNonce);
      // Wrong password fails MAC verification right here, locally - no server
      // round-trip needed to know the password was wrong.
      const privateKey = await unwrapPrivateKey(wrappedPrivateKey, nonce, stretchKey);
      setPrivateKey(privateKey);
      navigate("/clients");
    } catch {
      setError("Wrong master password");
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthCard title={`Unlock vault for ${currentUser.email}`}>
      <form onSubmit={handleSubmit}>
        <FormLabel htmlFor="password">Master password</FormLabel>
        <FormInput
          id="password"
          type="password"
          required
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
        />
        <ErrorText>{error}</ErrorText>
        <PrimaryButton type="submit" disabled={loading}>
          {loading ? "Unlocking..." : "Unlock"}
        </PrimaryButton>
      </form>
      <button
        type="button"
        onClick={() => {
          clearSession();
          navigate("/login");
        }}
        className="mt-4 w-full text-center text-xs text-gray-400 hover:text-gray-600"
      >
        Not you? Log out
      </button>
    </AuthCard>
  );
}
