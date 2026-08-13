import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  ResourceResponse,
  TokenResponse,
  TokenScopeType,
  createToken,
  getClient,
  listResources,
  listTokens,
  revokeToken,
  toUserMessage,
} from "../lib/api";
import {
  aeadEncrypt,
  deriveTokenWrapKey,
  fromBase64,
  generateTokenSecret,
  sha256Hex,
  toBase64,
  toHex,
  unsealWithKeypair,
} from "../lib/crypto";
import { RESOURCE_TYPE_LABELS } from "../lib/resourceTypes";
import { useVaultStore } from "../store/vaultStore";
import { ErrorText, FormLabel, FormSelect, PrimaryButton } from "../components/form";
import ConfirmDialog from "../components/ConfirmDialog";

const TTL_OPTIONS = [
  { label: "30 minutes", seconds: 1800 },
  { label: "1 hour", seconds: 3600 },
  { label: "1 day", seconds: 86400 },
];

export default function ClientTokensPage() {
  const { clientId } = useParams<{ clientId: string }>();
  const currentUser = useVaultStore((s) => s.currentUser);
  const privateKey = useVaultStore((s) => s.privateKey);
  const dataKeysByClientId = useVaultStore((s) => s.dataKeysByClientId);
  const setClientDataKey = useVaultStore((s) => s.setClientDataKey);

  const [tokens, setTokens] = useState<TokenResponse[] | null>(null);
  const [resources, setResources] = useState<ResourceResponse[] | null>(null);
  const [ttlSeconds, setTtlSeconds] = useState(3600);
  const [scopeType, setScopeType] = useState<TokenScopeType>("all_resources");
  const [selectedResourceIds, setSelectedResourceIds] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [revealedBearer, setRevealedBearer] = useState<string | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<TokenResponse | null>(null);

  async function refresh() {
    if (!clientId) return;
    setTokens(await listTokens(clientId));
    setResources(await listResources(clientId));
  }

  useEffect(() => {
    refresh().catch((err) => setError(toUserMessage(err, "Could not load tokens")));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clientId]);

  async function ensureDataKey(): Promise<Uint8Array> {
    if (!clientId || !currentUser || !privateKey) throw new Error("Vault is locked");
    const cached = dataKeysByClientId[clientId];
    if (cached) return cached;
    const clientDetail = await getClient(clientId);
    const publicKey = await fromBase64(currentUser.publicKey);
    const wrapped = await fromBase64(clientDetail.wrapped_data_key);
    const key = await unsealWithKeypair(wrapped, publicKey, privateKey);
    setClientDataKey(clientId, key);
    return key;
  }

  async function handleCreate() {
    if (!clientId) return;
    setError(null);
    setCreating(true);
    try {
      const dataKey = await ensureDataKey();

      const tokenId = crypto.randomUUID();
      const tokenSecret = await generateTokenSecret();
      const wrapKey = await deriveTokenWrapKey(tokenId, tokenSecret);
      const { ciphertext, nonce } = await aeadEncrypt(dataKey, wrapKey);
      const tokenHash = await sha256Hex(tokenSecret);

      await createToken(clientId, {
        token_id: tokenId,
        scope_type: scopeType,
        resource_ids: scopeType === "selected_resources" ? selectedResourceIds : null,
        ttl_seconds: ttlSeconds,
        token_hash: tokenHash,
        wrapped_data_key: await toBase64(ciphertext),
        wrapped_data_key_nonce: await toBase64(nonce),
      });

      const tokenSecretHex = await toHex(tokenSecret);
      setRevealedBearer(`${tokenId}.${tokenSecretHex}`);
      setSelectedResourceIds([]);
      await refresh();
    } catch (err) {
      setError(toUserMessage(err, "Could not create token"));
    } finally {
      setCreating(false);
    }
  }

  async function handleConfirmRevoke() {
    if (!clientId || !revokeTarget) return;
    setError(null);
    try {
      await revokeToken(clientId, revokeTarget.id);
      setRevokeTarget(null);
      await refresh();
    } catch (err) {
      setError(toUserMessage(err, "Could not revoke token"));
      setRevokeTarget(null);
    }
  }

  function resourceLabel(resource: ResourceResponse): string {
    return `${RESOURCE_TYPE_LABELS[resource.resource_type]} - ${resource.id.slice(0, 8)}`;
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="border-b border-gray-200 bg-white px-6 py-4">
        <div className="mx-auto flex max-w-3xl flex-wrap items-center gap-2">
          <Link to={`/clients/${clientId}`} className="shrink-0 text-sm text-gray-500 hover:text-gray-700">
            &larr; Back
          </Link>
          <span className="ml-2 text-base font-medium text-gray-900">API Tokens</span>
        </div>
      </header>
      <main className="mx-auto max-w-3xl px-6 py-8">
        <ErrorText>{error}</ErrorText>

        {revealedBearer && (
          <div className="mb-6 rounded border border-primary-200 bg-primary-50 p-4">
            <p className="mb-2 text-sm font-medium text-primary-800">
              Copy this now - it won't be shown again. Set it as INFRAWARDEN_API_KEY in your MCP config.
            </p>
            <code className="block break-all rounded bg-white px-3 py-2 text-xs text-gray-800">{revealedBearer}</code>
            <button
              onClick={() => setRevealedBearer(null)}
              className="mt-2 text-xs text-primary-700 hover:underline"
            >
              I've copied it
            </button>
          </div>
        )}

        <div className="mb-6 rounded border border-gray-200 bg-white p-4">
          <h2 className="mb-3 text-sm font-medium text-gray-700">Create a token</h2>

          <FormLabel htmlFor="ttl">Expires after</FormLabel>
          <FormSelect
            id="ttl"
            value={ttlSeconds}
            onChange={(e) => setTtlSeconds(Number(e.target.value))}
            className="mb-3 w-full"
          >
            {TTL_OPTIONS.map((opt) => (
              <option key={opt.seconds} value={opt.seconds}>
                {opt.label}
              </option>
            ))}
          </FormSelect>

          <FormLabel htmlFor="scope">Scope</FormLabel>
          <FormSelect
            id="scope"
            value={scopeType}
            onChange={(e) => setScopeType(e.target.value as TokenScopeType)}
            className="mb-3 w-full"
          >
            <option value="all_resources">Entire environment</option>
            <option value="selected_resources">Specific resources</option>
          </FormSelect>

          {scopeType === "selected_resources" && (
            <div className="mb-3 max-h-40 overflow-y-auto rounded border border-gray-200 p-2">
              {(resources ?? []).map((r) => (
                <label key={r.id} className="flex items-center gap-2 py-1 text-sm">
                  <input
                    type="checkbox"
                    checked={selectedResourceIds.includes(r.id)}
                    onChange={(e) =>
                      setSelectedResourceIds((prev) =>
                        e.target.checked ? [...prev, r.id] : prev.filter((id) => id !== r.id),
                      )
                    }
                  />
                  {resourceLabel(r)}
                </label>
              ))}
            </div>
          )}

          <PrimaryButton
            type="button"
            onClick={handleCreate}
            disabled={creating || (scopeType === "selected_resources" && selectedResourceIds.length === 0)}
          >
            {creating ? "Creating..." : "Create token"}
          </PrimaryButton>
        </div>

        <h2 className="mb-3 text-sm font-medium text-gray-700">Existing tokens</h2>
        {tokens === null ? (
          <p className="text-sm text-gray-400">Loading...</p>
        ) : tokens.length === 0 ? (
          <p className="text-sm text-gray-500">No tokens yet.</p>
        ) : (
          <ul className="divide-y divide-gray-200 rounded border border-gray-200 bg-white">
            {tokens.map((t) => {
              const isExpired = new Date(t.expires_at) < new Date();
              const isRevoked = t.revoked_at !== null;
              return (
                <li key={t.id} className="flex items-center justify-between px-4 py-3">
                  <div>
                    <p className="text-sm text-gray-900">
                      {t.scope_type === "all_resources" ? "Entire environment" : `${t.resource_ids.length} resource(s)`}
                    </p>
                    <p className="text-xs text-gray-500">
                      {isRevoked ? "Revoked" : isExpired ? "Expired" : `Expires ${new Date(t.expires_at).toLocaleString()}`}
                      {t.last_used_at && ` - last used ${new Date(t.last_used_at).toLocaleString()}`}
                    </p>
                  </div>
                  {!isRevoked && !isExpired && (
                    <button onClick={() => setRevokeTarget(t)} className="text-xs text-danger-600 hover:underline">
                      Revoke
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        )}

        {revokeTarget && (
          <ConfirmDialog
            title="Revoke this token?"
            message="Any agent using this token will immediately lose access - the next request will fail, even mid-session."
            confirmLabel="Revoke token"
            onConfirm={handleConfirmRevoke}
            onCancel={() => setRevokeTarget(null)}
          />
        )}
      </main>
    </div>
  );
}
