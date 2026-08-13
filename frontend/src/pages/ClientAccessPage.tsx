import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  AccessGrantResponse,
  UserPublicResponse,
  getClient,
  listClientAccess,
  listUsers,
  revokeClientAccess,
  shareClientAccess,
} from "../lib/api";
import { fromBase64, sealForPublicKey, toBase64, unsealWithKeypair } from "../lib/crypto";
import { useVaultStore } from "../store/vaultStore";
import { ErrorText, PrimaryButton } from "../components/form";

export default function ClientAccessPage() {
  const { clientId } = useParams<{ clientId: string }>();
  const currentUser = useVaultStore((s) => s.currentUser);
  const privateKey = useVaultStore((s) => s.privateKey);
  const dataKeysByClientId = useVaultStore((s) => s.dataKeysByClientId);
  const setClientDataKey = useVaultStore((s) => s.setClientDataKey);

  const [access, setAccess] = useState<AccessGrantResponse[] | null>(null);
  const [users, setUsers] = useState<UserPublicResponse[] | null>(null);
  const [selectedUserId, setSelectedUserId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [sharing, setSharing] = useState(false);

  async function refresh() {
    if (!clientId) return;
    setAccess(await listClientAccess(clientId));
    setUsers(await listUsers());
  }

  useEffect(() => {
    refresh().catch((err) => setError(err instanceof Error ? err.message : "Could not load access list"));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clientId]);

  async function ensureDataKey(): Promise<Uint8Array> {
    if (!clientId || !currentUser || !privateKey) throw new Error("Vault is locked");
    const cached = dataKeysByClientId[clientId];
    if (cached) return cached;
    const client = await getClient(clientId);
    const publicKey = await fromBase64(currentUser.publicKey);
    const wrapped = await fromBase64(client.wrapped_data_key);
    const key = await unsealWithKeypair(wrapped, publicKey, privateKey);
    setClientDataKey(clientId, key);
    return key;
  }

  async function handleShare() {
    if (!clientId || !selectedUserId || !users) return;
    setError(null);
    setSharing(true);
    try {
      const targetUser = users.find((u) => u.id === selectedUserId);
      if (!targetUser) return;
      const dataKey = await ensureDataKey();
      const targetPublicKey = await fromBase64(targetUser.public_key);
      const wrapped = await sealForPublicKey(dataKey, targetPublicKey);
      await shareClientAccess(clientId, selectedUserId, await toBase64(wrapped));
      setSelectedUserId("");
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not share access");
    } finally {
      setSharing(false);
    }
  }

  async function handleRevoke(userId: string) {
    if (!clientId) return;
    setError(null);
    try {
      await revokeClientAccess(clientId, userId);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not revoke access");
    }
  }

  const grantedUserIds = new Set((access ?? []).map((a) => a.user_id));
  const shareableUsers = (users ?? []).filter((u) => !grantedUserIds.has(u.id));

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="border-b border-gray-200 bg-white px-6 py-4">
        <div className="mx-auto flex max-w-2xl items-center gap-2">
          <Link to={`/clients/${clientId}`} className="text-sm text-gray-500 hover:text-gray-700">
            &larr; Back
          </Link>
          <span className="ml-2 text-base font-medium text-gray-900">Access</span>
        </div>
      </header>
      <main className="mx-auto max-w-2xl px-6 py-8">
        <ErrorText>{error}</ErrorText>

        <div className="mb-6 rounded border border-gray-200 bg-white p-4">
          <h2 className="mb-3 text-sm font-medium text-gray-700">Share with a colleague</h2>
          <div className="flex gap-2">
            <select
              value={selectedUserId}
              onChange={(e) => setSelectedUserId(e.target.value)}
              className="flex-1 rounded border border-gray-300 px-2 py-1.5 text-sm"
            >
              <option value="">Select a person...</option>
              {shareableUsers.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.email}
                </option>
              ))}
            </select>
            <div className="w-32">
              <PrimaryButton type="button" disabled={!selectedUserId || sharing} onClick={handleShare}>
                {sharing ? "Sharing..." : "Share"}
              </PrimaryButton>
            </div>
          </div>
        </div>

        <h2 className="mb-3 text-sm font-medium text-gray-700">Who has access</h2>
        {access === null ? (
          <p className="text-sm text-gray-400">Loading...</p>
        ) : (
          <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
            {access.map((grant) => {
              const grantUser = (users ?? []).find((u) => u.id === grant.user_id);
              const isSuperadmin = grantUser?.role === "admin";
              return (
                <li key={grant.user_id} className="flex items-center justify-between px-4 py-3">
                  <span className="text-sm text-gray-900">
                    {grant.email}
                    {isSuperadmin && (
                      <span className="ml-2 rounded bg-primary-100 px-1.5 py-0.5 text-xs font-medium text-primary-700">
                        superadmin
                      </span>
                    )}
                  </span>
                  {!isSuperadmin && (
                    <button
                      onClick={() => handleRevoke(grant.user_id)}
                      className="text-xs text-danger-600 hover:underline"
                    >
                      Revoke
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </main>
    </div>
  );
}
