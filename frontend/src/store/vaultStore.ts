import { create } from "zustand";
import { persist } from "zustand/middleware";

interface UserMe {
  id: string;
  email: string;
  role: "admin" | "user";
  status: string;
  publicKey: string; // base64
  wrappedPrivateKey: string; // base64
  wrappedPrivateKeyNonce: string; // base64
  kdfSalt: string; // base64
  kdfOpsLimit: number;
  kdfMemLimit: number;
}

interface VaultState {
  // Session tokens - persisted, since these are not vault secrets themselves.
  accessToken: string | null;
  refreshToken: string | null;
  currentUser: UserMe | null;
  setSession: (accessToken: string, refreshToken: string) => void;
  setCurrentUser: (user: UserMe) => void;
  clearSession: () => void;

  // Unwrapped vault key material - NEVER persisted. Cleared on logout/tab close by
  // virtue of living only in JS memory. Populated by the /unlock flow.
  privateKey: Uint8Array | null;
  dataKeysByClientId: Record<string, Uint8Array>;
  setPrivateKey: (key: Uint8Array | null) => void;
  setClientDataKey: (clientId: string, key: Uint8Array) => void;
  lockVault: () => void;
}

export const useVaultStore = create<VaultState>()(
  persist(
    (set) => ({
      accessToken: null,
      refreshToken: null,
      currentUser: null,
      setSession: (accessToken, refreshToken) => set({ accessToken, refreshToken }),
      setCurrentUser: (user) => set({ currentUser: user }),
      clearSession: () =>
        set({ accessToken: null, refreshToken: null, currentUser: null, privateKey: null, dataKeysByClientId: {} }),

      privateKey: null,
      dataKeysByClientId: {},
      setPrivateKey: (key) => set({ privateKey: key }),
      setClientDataKey: (clientId, key) =>
        set((state) => ({ dataKeysByClientId: { ...state.dataKeysByClientId, [clientId]: key } })),
      lockVault: () => set({ privateKey: null, dataKeysByClientId: {} }),
    }),
    {
      name: "infrawarden-session",
      // Only the session tokens/current user survive a reload - key material never does.
      partialize: (state) => ({
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        currentUser: state.currentUser,
      }),
    },
  ),
);
