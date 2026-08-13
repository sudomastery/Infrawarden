import { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useVaultStore } from "../store/vaultStore";

/** Route wrapper: requires a logged-in session AND an unwrapped private key in
 * memory. Redirects to /login if there's no session, or /unlock if there's a
 * session but the vault key was lost (e.g. after a page reload). */
export default function VaultUnlockGate({ children }: { children: ReactNode }) {
  const accessToken = useVaultStore((s) => s.accessToken);
  const currentUser = useVaultStore((s) => s.currentUser);
  const privateKey = useVaultStore((s) => s.privateKey);

  if (!accessToken || !currentUser) {
    return <Navigate to="/login" replace />;
  }
  if (!privateKey) {
    return <Navigate to="/unlock" replace />;
  }
  return <>{children}</>;
}
