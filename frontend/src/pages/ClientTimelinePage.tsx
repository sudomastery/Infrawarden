import { FormEvent, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { createTimelineEntry, getClient, listTimelineEntries, TimelineEntryResponse, toUserMessage } from "../lib/api";
import { decryptJson, encryptJson, fromBase64, toBase64, unsealWithKeypair } from "../lib/crypto";
import { useVaultStore } from "../store/vaultStore";
import { ErrorText, FormInput, PrimaryButton } from "../components/form";

interface DecryptedEntry {
  entry: TimelineEntryResponse;
  text: string;
}

export default function ClientTimelinePage() {
  const { clientId } = useParams<{ clientId: string }>();
  const currentUser = useVaultStore((s) => s.currentUser);
  const privateKey = useVaultStore((s) => s.privateKey);
  const dataKeysByClientId = useVaultStore((s) => s.dataKeysByClientId);
  const setClientDataKey = useVaultStore((s) => s.setClientDataKey);

  const [entries, setEntries] = useState<DecryptedEntry[] | null>(null);
  const [newText, setNewText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

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

  async function refresh() {
    if (!clientId) return;
    const dataKey = await ensureDataKey();
    const raw = await listTimelineEntries(clientId);
    const decrypted = await Promise.all(
      raw.map(async (entry) => ({
        entry,
        text: await decryptJson<string>(await fromBase64(entry.ciphertext), await fromBase64(entry.nonce), dataKey),
      })),
    );
    setEntries(decrypted);
  }

  useEffect(() => {
    refresh().catch((err) => setError(toUserMessage(err, "Could not load timeline")));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clientId]);

  async function handleAdd(e: FormEvent) {
    e.preventDefault();
    if (!clientId || !newText.trim()) return;
    setError(null);
    setSubmitting(true);
    try {
      const dataKey = await ensureDataKey();
      const { ciphertext, nonce } = await encryptJson(newText.trim(), dataKey);
      await createTimelineEntry(clientId, await toBase64(ciphertext), await toBase64(nonce));
      setNewText("");
      await refresh();
    } catch (err) {
      setError(toUserMessage(err, "Could not add entry"));
    } finally {
      setSubmitting(false);
    }
  }

  const manualEntries = (entries ?? []).filter((e) => e.entry.source === "manual");
  const emailEntries = (entries ?? []).filter((e) => e.entry.source === "email");

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="border-b border-gray-200 bg-white px-6 py-4">
        <div className="mx-auto flex max-w-3xl flex-wrap items-center gap-2">
          <Link to={`/clients/${clientId}`} className="shrink-0 text-sm text-gray-500 hover:text-gray-700">
            &larr; Back
          </Link>
          <span className="ml-2 text-base font-medium text-gray-900">Activity Timeline</span>
        </div>
      </header>
      <main className="mx-auto max-w-3xl px-6 py-8">
        <ErrorText>{error}</ErrorText>

        <section className="mb-8">
          <h2 className="mb-3 text-sm font-medium text-gray-700">Manual entries</h2>
          <form onSubmit={handleAdd} className="mb-4 flex gap-2">
            <div className="flex-1">
              <FormInput
                placeholder="e.g. maintenance window scheduled for Saturday"
                value={newText}
                onChange={(e) => setNewText(e.target.value)}
              />
            </div>
            <div className="w-28">
              <PrimaryButton type="submit" disabled={submitting}>
                {submitting ? "Adding..." : "Add"}
              </PrimaryButton>
            </div>
          </form>
          {entries === null ? (
            <p className="text-sm text-gray-400">Loading...</p>
          ) : manualEntries.length === 0 ? (
            <p className="text-sm text-gray-500">No manual entries yet.</p>
          ) : (
            <ul className="space-y-2">
              {manualEntries.map(({ entry, text }) => (
                <li key={entry.id} className="rounded border border-gray-200 bg-white p-3">
                  <p className="text-sm text-gray-800">{text}</p>
                  <p className="mt-1 text-xs text-gray-400">{new Date(entry.created_at).toLocaleString()}</p>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section>
          <div className="mb-3 flex items-center gap-2">
            <h2 className="text-sm font-medium text-gray-700">Email summaries</h2>
            <span className="rounded bg-gray-100 px-1.5 py-0.5 text-xs font-medium text-gray-500">coming soon</span>
          </div>
          <p className="mb-3 text-xs text-gray-500">
            When a client contact thread is CC'd to Infrawarden, an AI-generated summary will appear here as its own
            entry, separate from manual notes - this section is reserved for that.
          </p>
          {emailEntries.length === 0 ? (
            <p className="text-sm text-gray-400">Nothing yet.</p>
          ) : (
            <ul className="space-y-2">
              {emailEntries.map(({ entry, text }) => (
                <li key={entry.id} className="rounded border border-info-200 bg-info-50 p-3">
                  <p className="text-sm text-gray-800">{text}</p>
                  <p className="mt-1 text-xs text-gray-400">{new Date(entry.created_at).toLocaleString()}</p>
                </li>
              ))}
            </ul>
          )}
        </section>
      </main>
    </div>
  );
}
