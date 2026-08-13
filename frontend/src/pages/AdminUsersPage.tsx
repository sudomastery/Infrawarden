import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { UserPublicResponse, getClient, listUsers, promoteUser, shareClientAccess, toUserMessage } from "../lib/api";
import { fromBase64, sealForPublicKey, toBase64, unsealWithKeypair } from "../lib/crypto";
import { useVaultStore } from "../store/vaultStore";
import { ErrorText } from "../components/form";

export default function AdminUsersPage() {
  const currentUser = useVaultStore((s) => s.currentUser);
  const privateKey = useVaultStore((s) => s.privateKey);
  const [users, setUsers] = useState<UserPublicResponse[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyUserId, setBusyUserId] = useState<string | null>(null);
  const [statusByUserId, setStatusByUserId] = useState<Record<string, string>>({});

  async function refresh() {
    setUsers(await listUsers());
  }

  useEffect(() => {
    refresh().catch((err) => setError(toUserMessage(err, "Could not load users")));
  }, []);

  async function handlePromote(user: UserPublicResponse) {
    if (!currentUser || !privateKey) return;
    setError(null);
    setBusyUserId(user.id);
    try {
      const result = await promoteUser(user.id);
      const total = result.clients_needing_reconciliation.length;
      // Reconcile every pre-existing client immediately, while we're online with
      // our own vault unlocked - see docs/ARCHITECTURE.md "Superadmin access model".
      for (let i = 0; i < total; i++) {
        const clientId = result.clients_needing_reconciliation[i];
        setStatusByUserId((s) => ({ ...s, [user.id]: `Reconciling ${i + 1}/${total}...` }));

        const clientDetail = await getClient(clientId);
        const ownPublicKey = await fromBase64(currentUser.publicKey);
        const wrapped = await fromBase64(clientDetail.wrapped_data_key);
        const dataKey = await unsealWithKeypair(wrapped, ownPublicKey, privateKey);

        const targetPublicKey = await fromBase64(user.public_key);
        const rewrapped = await sealForPublicKey(dataKey, targetPublicKey);
        await shareClientAccess(clientId, user.id, await toBase64(rewrapped));
      }
      setStatusByUserId((s) => ({ ...s, [user.id]: `Promoted, reconciled ${total} client(s)` }));
      await refresh();
    } catch (err) {
      setError(toUserMessage(err, "Could not promote user"));
    } finally {
      setBusyUserId(null);
    }
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="border-b border-gray-200 bg-white px-6 py-4">
        <div className="mx-auto flex max-w-3xl flex-wrap items-center gap-2">
          <Link to="/clients" className="shrink-0 text-sm text-gray-500 hover:text-gray-700">
            &larr; Clients
          </Link>
          <span className="ml-2 text-base font-medium text-gray-900">Users</span>
        </div>
      </header>
      <main className="mx-auto max-w-3xl px-6 py-8">
        <ErrorText>{error}</ErrorText>
        {users === null ? (
          <p className="text-sm text-gray-400">Loading...</p>
        ) : (
          <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
            {users.map((u) => (
              <li key={u.id} className="flex items-center justify-between px-4 py-3">
                <div>
                  <span className="text-sm text-gray-900">{u.email}</span>
                  {u.role === "admin" && (
                    <span className="ml-2 rounded bg-primary-100 px-1.5 py-0.5 text-xs font-medium text-primary-700">
                      superadmin
                    </span>
                  )}
                  {statusByUserId[u.id] && <p className="text-xs text-gray-500">{statusByUserId[u.id]}</p>}
                </div>
                {u.role !== "admin" && (
                  <button
                    onClick={() => handlePromote(u)}
                    disabled={busyUserId === u.id}
                    className="text-xs text-primary-600 hover:underline disabled:opacity-50"
                  >
                    {busyUserId === u.id ? "Promoting..." : "Promote to superadmin"}
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </main>
    </div>
  );
}
