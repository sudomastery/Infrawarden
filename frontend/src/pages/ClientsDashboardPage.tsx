import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ClientResponse, createClient, listClients, listUsers } from "../lib/api";
import { generateDataKey, sealForPublicKey, toBase64, fromBase64 } from "../lib/crypto";
import { useVaultStore } from "../store/vaultStore";
import { ErrorText, FormInput, FormLabel, PrimaryButton } from "../components/form";

export default function ClientsDashboardPage() {
  const currentUser = useVaultStore((s) => s.currentUser);
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
    refresh().catch((err) => setError(err instanceof Error ? err.message : "Could not load clients"));
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
      setError(err instanceof Error ? err.message : "Could not create client");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="border-b border-gray-200 bg-white px-6 py-4">
        <div className="mx-auto flex max-w-3xl items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded bg-primary-600 text-sm font-bold text-white">
            IW
          </div>
          <span className="text-lg font-semibold text-gray-900">Infrawarden</span>
          {currentUser?.role === "admin" && (
            <span className="ml-1 rounded bg-primary-100 px-2 py-0.5 text-xs font-medium text-primary-700">
              superadmin
            </span>
          )}
          <span className="ml-auto text-sm text-gray-500">{currentUser?.email}</span>
        </div>
      </header>
      <main className="mx-auto max-w-3xl px-6 py-8">
        <div className="mb-4 flex items-center justify-between">
          <h1 className="text-base font-medium text-gray-900">Clients</h1>
          <button
            onClick={() => setShowNewClient((v) => !v)}
            className="rounded bg-primary-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-700"
          >
            New client
          </button>
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
