import { FormEvent, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ClientResponse, createClient, listClients, listUsers, logout, toUserMessage } from "../lib/api";
import { generateDataKey, sealForPublicKey, toBase64, fromBase64 } from "../lib/crypto";
import { useVaultStore } from "../store/vaultStore";
import { ErrorText, FormInput, FormLabel, InlineButton, PrimaryButton } from "../components/form";

export default function ClientsDashboardPage() {
  const navigate = useNavigate();
  const currentUser = useVaultStore((s) => s.currentUser);
  const clearSession = useVaultStore((s) => s.clearSession);

  async function handleLogout() {
    try {
      await logout();
    } catch {
      // best-effort - the session is being cleared client-side regardless
    }
    clearSession();
    navigate("/login");
  }
  const [clients, setClients] = useState<ClientResponse[] | null>(null);
  const [showNewClient, setShowNewClient] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  async function refresh() {
    setClients(await listClients());
  }

  useEffect(() => {
    refresh().catch((err) => setError(toUserMessage(err, "Could not load clients")));
  }, []);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!currentUser) return;
    setError(null);
    setCreating(true);
    try {
      const dataKey = await generateDataKey();
      const selfPublicKey = await fromBase64(currentUser.publicKey);
      const grants = [
        { user_id: currentUser.id, wrapped_data_key: await toBase64(await sealForPublicKey(dataKey, selfPublicKey)) },
      ];

      // Every current superadmin gets a grant too, wrapped now while we have the
      // data key in hand - see docs/ARCHITECTURE.md "Superadmin access model".
      const users = await listUsers();
      for (const user of users) {
        if (user.role === "admin" && user.id !== currentUser.id) {
          const pubKey = await fromBase64(user.public_key);
          grants.push({ user_id: user.id, wrapped_data_key: await toBase64(await sealForPublicKey(dataKey, pubKey)) });
        }
      }

      await createClient(name, description || null, grants);
      setName("");
      setDescription("");
      setShowNewClient(false);
      await refresh();
    } catch (err) {
      setError(toUserMessage(err, "Could not create client"));
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="border-b border-gray-200 bg-white px-6 py-4">
        <div className="mx-auto flex max-w-3xl flex-wrap items-center gap-x-2 gap-y-1">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded bg-primary-600 text-sm font-bold text-white">
            IW
          </div>
          <span className="shrink-0 text-lg font-semibold text-gray-900">Infrawarden</span>
          {currentUser?.role === "admin" && (
            <span className="shrink-0 rounded bg-primary-100 px-2 py-0.5 text-xs font-medium text-primary-700">
              superadmin
            </span>
          )}
          {currentUser?.role === "admin" && (
            <Link to="/admin/users" className="ml-2 shrink-0 text-sm text-primary-600 hover:underline">
              Users
            </Link>
          )}
          <span className="ml-auto min-w-0 truncate text-sm text-gray-500">{currentUser?.email}</span>
          <button onClick={handleLogout} className="shrink-0 text-sm text-gray-400 hover:text-gray-600">
            Log out
          </button>
        </div>
      </header>
      <main className="mx-auto max-w-3xl px-6 py-8">
        <div className="mb-4 flex items-center justify-between">
          <h1 className="text-base font-medium text-gray-900">Clients</h1>
          <InlineButton onClick={() => setShowNewClient((v) => !v)}>New client</InlineButton>
        </div>

        {showNewClient && (
          <form onSubmit={handleCreate} className="mb-6 rounded border border-gray-200 bg-white p-4">
            <FormLabel htmlFor="name">Name</FormLabel>
            <FormInput id="name" required value={name} onChange={(e) => setName(e.target.value)} />
            <FormLabel htmlFor="description">Description (optional)</FormLabel>
            <FormInput id="description" value={description} onChange={(e) => setDescription(e.target.value)} />
            <ErrorText>{error}</ErrorText>
            <PrimaryButton type="submit" disabled={creating}>
              {creating ? "Creating..." : "Create client"}
            </PrimaryButton>
          </form>
        )}

        {clients === null ? (
          <p className="text-sm text-gray-400">Loading...</p>
        ) : clients.length === 0 ? (
          <p className="text-sm text-gray-500">No clients yet. Create one to get started.</p>
        ) : (
          <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
            {clients.map((c) => (
              <li key={c.id}>
                <Link to={`/clients/${c.id}`} className="block px-4 py-3 hover:bg-gray-50">
                  <p className="text-sm font-medium text-gray-900">{c.name}</p>
                  {c.description && <p className="text-xs text-gray-500">{c.description}</p>}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </main>
    </div>
  );
}
