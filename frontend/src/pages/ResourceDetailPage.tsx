import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  acceptResourceChange,
  createResourceNote,
  createResourceVersion,
  deleteResource,
  getResource,
  hideResource,
  ignoreResourceChange,
  listResourceNotes,
  listResourceVersions,
  listUsers,
  ResourceResponse,
  unhideResource,
} from "../lib/api";
import { decryptJson, encryptJson, fromBase64, toBase64 } from "../lib/crypto";
import { diffResourceValues } from "../lib/diff";
import { RESOURCE_TYPE_LABELS, ResourceFieldValues } from "../lib/resourceTypes";
import { useVaultStore } from "../store/vaultStore";
import ResourceTypeForm from "../components/ResourceTypeForm";
import ResourceChangeBanner from "../components/ResourceChangeBanner";
import NoteTimeline, { DecryptedNote } from "../components/NoteTimeline";
import { ErrorText } from "../components/form";

export default function ResourceDetailPage() {
  const { clientId, resourceId } = useParams<{ clientId: string; resourceId: string }>();
  const navigate = useNavigate();
  const currentUser = useVaultStore((s) => s.currentUser);
  const dataKeysByClientId = useVaultStore((s) => s.dataKeysByClientId);
  const dataKey = clientId ? dataKeysByClientId[clientId] : undefined;

  const [resource, setResource] = useState<ResourceResponse | null>(null);
  const [values, setValues] = useState<ResourceFieldValues | null>(null);
  const [pendingDiff, setPendingDiff] = useState<{ changedBy: string; diffs: ReturnType<typeof diffResourceValues> } | null>(
    null,
  );
  const [notes, setNotes] = useState<DecryptedNote[] | null>(null);
  const [editing, setEditing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    if (!resourceId || !dataKey) return;
    const r = await getResource(resourceId);
    setResource(r);

    const currentValues = await decryptJson<ResourceFieldValues>(
      await fromBase64(r.current_version.ciphertext),
      await fromBase64(r.current_version.nonce),
      dataKey,
    );
    setValues(currentValues);

    const users = await listUsers();
    const byId: Record<string, string> = {};
    for (const u of users) byId[u.id] = u.email;

    if (r.has_pending_change) {
      const versions = await listResourceVersions(resourceId);
      const latest = versions[versions.length - 1];
      const latestValues = await decryptJson<ResourceFieldValues>(
        await fromBase64(latest.ciphertext),
        await fromBase64(latest.nonce),
        dataKey,
      );
      setPendingDiff({
        changedBy: byId[latest.changed_by_user_id] ?? latest.changed_by_user_id,
        diffs: diffResourceValues(currentValues, latestValues),
      });
    } else {
      setPendingDiff(null);
    }

    const rawNotes = await listResourceNotes(resourceId);
    const decryptedNotes = await Promise.all(
      rawNotes.map(async (n) => ({
        id: n.id,
        authorEmail: byId[n.author_user_id] ?? n.author_user_id,
        text: await decryptJson<string>(await fromBase64(n.ciphertext), await fromBase64(n.nonce), dataKey),
        createdAt: n.created_at,
      })),
    );
    setNotes(decryptedNotes);
  }

  useEffect(() => {
    load().catch((err) => setError(err instanceof Error ? err.message : "Could not load resource"));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resourceId, dataKey]);

  async function handleAccept() {
    if (!resourceId) return;
    await acceptResourceChange(resourceId);
    await load();
  }

  async function handleIgnore() {
    if (!resourceId) return;
    await ignoreResourceChange(resourceId);
    await load();
  }

  async function handleSaveEdit(newValues: ResourceFieldValues) {
    if (!resourceId || !dataKey) return;
    const { ciphertext, nonce } = await encryptJson(newValues, dataKey);
    await createResourceVersion(resourceId, await toBase64(ciphertext), await toBase64(nonce));
    setEditing(false);
    await load();
  }

  async function handleAddNote(text: string) {
    if (!resourceId || !dataKey) return;
    const { ciphertext, nonce } = await encryptJson(text, dataKey);
    await createResourceNote(resourceId, await toBase64(ciphertext), await toBase64(nonce));
    await load();
  }

  async function handleDelete() {
    if (!resourceId || !clientId) return;
    try {
      await deleteResource(resourceId);
      navigate(`/clients/${clientId}`);
    } catch {
      // not the owner/admin - fall back to hiding it from just this view
      await hideResource(resourceId);
      navigate(`/clients/${clientId}`);
    }
  }

  async function handleUnhide() {
    if (!resourceId) return;
    await unhideResource(resourceId);
    await load();
  }

  if (!resource || !values) {
    return (
      <div className="mx-auto max-w-2xl px-6 py-8">
        <ErrorText>{error}</ErrorText>
        <p className="text-sm text-gray-400">Loading...</p>
      </div>
    );
  }

  const isOwner = currentUser?.id === resource.created_by_user_id;
  const canHardDelete = isOwner || currentUser?.role === "admin";

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="border-b border-gray-200 bg-white px-6 py-4">
        <div className="mx-auto flex max-w-2xl items-center gap-2">
          <Link to={`/clients/${clientId}`} className="text-sm text-gray-500 hover:text-gray-700">
            &larr; Back
          </Link>
          <span className="ml-2 rounded bg-gray-100 px-1.5 py-0.5 text-xs font-medium text-gray-600">
            {RESOURCE_TYPE_LABELS[resource.resource_type]}
          </span>
          <span className="text-base font-medium text-gray-900">{values.name || "(unnamed)"}</span>
        </div>
      </header>
      <main className="mx-auto max-w-2xl px-6 py-8">
        <ErrorText>{error}</ErrorText>

        {resource.hidden && (
          <div className="mb-4 flex items-center justify-between rounded border border-gray-200 bg-gray-100 px-4 py-2 text-sm text-gray-600">
            <span>Hidden from your view</span>
            <button onClick={handleUnhide} className="text-primary-600 hover:underline">
              Unhide
            </button>
          </div>
        )}

        {pendingDiff && (
          <ResourceChangeBanner
            changedBy={pendingDiff.changedBy}
            diffs={pendingDiff.diffs}
            onAccept={handleAccept}
            onIgnore={handleIgnore}
          />
        )}

        <div className="mb-6 rounded border border-gray-200 bg-white p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-medium text-gray-700">Fields</h2>
            <div className="flex gap-2">
              <button onClick={() => setEditing((v) => !v)} className="text-xs text-primary-600 hover:underline">
                {editing ? "Cancel" : "Edit"}
              </button>
              <button
                onClick={handleDelete}
                className="text-xs text-danger-600 hover:underline"
                title={canHardDelete ? "Delete for everyone" : "Remove from my view"}
              >
                {canHardDelete ? "Delete" : "Remove from my view"}
              </button>
            </div>
          </div>
          {editing ? (
            <ResourceTypeForm
              resourceType={resource.resource_type}
              initialValues={values}
              submitLabel="Save change"
              onSubmit={handleSaveEdit}
            />
          ) : (
            <dl className="space-y-1 text-sm">
              {Object.entries(values).map(([key, value]) =>
                key === "management_interfaces" ? null : (
                  <div key={key} className="flex gap-2">
                    <dt className="w-32 shrink-0 text-gray-500">{key}</dt>
                    <dd className="text-gray-900">{String(value)}</dd>
                  </div>
                ),
              )}
            </dl>
          )}
        </div>

        <div>
          <h2 className="mb-3 text-sm font-medium text-gray-700">Notes / history</h2>
          <NoteTimeline notes={notes ?? []} onAddNote={handleAddNote} />
        </div>
      </main>
    </div>
  );
}
