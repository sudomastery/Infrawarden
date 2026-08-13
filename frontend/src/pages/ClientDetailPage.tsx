import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { createResource, getClient, listResources, ResourceResponse, ResourceType } from "../lib/api";
import { decryptJson, encryptJson, fromBase64, toBase64, unsealWithKeypair } from "../lib/crypto";
import { RESOURCE_TYPE_LABELS, ResourceFieldValues } from "../lib/resourceTypes";
import { useVaultStore } from "../store/vaultStore";
import ResourceTypeForm from "../components/ResourceTypeForm";
import { ErrorText } from "../components/form";

interface DecryptedResource {
  resource: ResourceResponse;
  values: ResourceFieldValues;
}

export default function ClientDetailPage() {
  const { clientId } = useParams<{ clientId: string }>();
  const currentUser = useVaultStore((s) => s.currentUser);
  const privateKey = useVaultStore((s) => s.privateKey);
  const dataKeysByClientId = useVaultStore((s) => s.dataKeysByClientId);
  const setClientDataKey = useVaultStore((s) => s.setClientDataKey);

  const [clientName, setClientName] = useState<string | null>(null);
  const [resources, setResources] = useState<DecryptedResource[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showNewResource, setShowNewResource] = useState(false);
  const [newResourceType, setNewResourceType] = useState<ResourceType>("host");

  const dataKey = clientId ? dataKeysByClientId[clientId] : undefined;

  useEffect(() => {
    if (!clientId || !currentUser || !privateKey) return;
    let cancelled = false;

    async function load() {
      try {
        const client = await getClient(clientId!);
        if (cancelled) return;
        setClientName(client.name);

        let key = dataKeysByClientId[clientId!];
        if (!key) {
          const publicKey = await fromBase64(currentUser!.publicKey);
          const wrapped = await fromBase64(client.wrapped_data_key);
          key = await unsealWithKeypair(wrapped, publicKey, privateKey!);
          setClientDataKey(clientId!, key);
        }

        const resourceList = await listResources(clientId!);
        if (cancelled) return;
        const decrypted = await Promise.all(
          resourceList.map(async (resource) => ({
            resource,
            values: await decryptJson<ResourceFieldValues>(
              await fromBase64(resource.current_version.ciphertext),
              await fromBase64(resource.current_version.nonce),
              key,
            ),
          })),
        );
        if (!cancelled) setResources(decrypted);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not load client");
      }
    }

    load();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clientId, currentUser, privateKey]);

  async function handleCreateResource(values: ResourceFieldValues) {
    if (!clientId || !dataKey) return;
    const { ciphertext, nonce } = await encryptJson(values, dataKey);
    const created = await createResource(clientId, newResourceType, await toBase64(ciphertext), await toBase64(nonce));
    setResources((prev) => [...(prev ?? []), { resource: created, values }]);
    setShowNewResource(false);
  }

  if (!privateKey) return null; // VaultUnlockGate handles redirecting to /unlock

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="border-b border-gray-200 bg-white px-6 py-4">
        <div className="mx-auto flex max-w-3xl items-center gap-2">
          <Link to="/clients" className="text-sm text-gray-500 hover:text-gray-700">
            &larr; Clients
          </Link>
          <span className="ml-2 text-base font-medium text-gray-900">{clientName ?? "Loading..."}</span>
          <Link to={`/clients/${clientId}/timeline`} className="ml-auto text-sm text-primary-600 hover:underline">
            Timeline
          </Link>
          <Link to={`/clients/${clientId}/tokens`} className="text-sm text-primary-600 hover:underline">
            API Tokens
          </Link>
          <Link to={`/clients/${clientId}/access`} className="text-sm text-primary-600 hover:underline">
            Access
          </Link>
        </div>
      </header>
      <main className="mx-auto max-w-3xl px-6 py-8">
        <ErrorText>{error}</ErrorText>

        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-medium text-gray-700">Resources</h2>
          <div className="flex items-center gap-2">
            <select
              value={newResourceType}
              onChange={(e) => setNewResourceType(e.target.value as ResourceType)}
              className="rounded border border-gray-300 px-2 py-1.5 text-sm"
            >
              {Object.entries(RESOURCE_TYPE_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
            <button
              onClick={() => setShowNewResource((v) => !v)}
              className="rounded bg-primary-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-700"
            >
              New resource
            </button>
          </div>
        </div>

        {showNewResource && (
          <div className="mb-6 rounded border border-gray-200 bg-white p-4">
            <ResourceTypeForm
              resourceType={newResourceType}
              submitLabel="Create resource"
              onSubmit={handleCreateResource}
            />
          </div>
        )}

        {resources === null ? (
          <p className="text-sm text-gray-400">Loading...</p>
        ) : resources.length === 0 ? (
          <p className="text-sm text-gray-500">No resources yet.</p>
        ) : (
          <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
            {resources.map(({ resource, values }) => (
              <li key={resource.id}>
                <Link
                  to={`/clients/${clientId}/resources/${resource.id}`}
                  className="flex items-center justify-between px-4 py-3 hover:bg-gray-50"
                >
                  <div>
                    <span className="mr-2 rounded bg-gray-100 px-1.5 py-0.5 text-xs font-medium text-gray-600">
                      {RESOURCE_TYPE_LABELS[resource.resource_type]}
                    </span>
                    <span className="text-sm font-medium text-gray-900">{values.name || "(unnamed)"}</span>
                    {values.ip && <span className="ml-2 text-xs text-gray-500">{values.ip}</span>}
                  </div>
                  <div className="flex items-center gap-2">
                    {resource.hidden && <span className="text-xs text-gray-400">hidden</span>}
                    {resource.has_pending_change && (
                      <span className="rounded bg-warning-100 px-1.5 py-0.5 text-xs font-medium text-warning-700">
                        change pending
                      </span>
                    )}
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </main>
    </div>
  );
}
