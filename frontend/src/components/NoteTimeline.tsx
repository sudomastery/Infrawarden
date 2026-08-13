import { FormEvent, useState } from "react";
import { FormInput, PrimaryButton } from "./form";

export interface DecryptedNote {
  id: string;
  authorEmail: string;
  text: string;
  createdAt: string;
}

export default function NoteTimeline({
  notes,
  onAddNote,
}: {
  notes: DecryptedNote[];
  onAddNote: (text: string) => Promise<void>;
}) {
  const [text, setText] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!text.trim()) return;
    setSubmitting(true);
    try {
      await onAddNote(text.trim());
      setText("");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div>
      <ul className="mb-4 space-y-3">
        {notes.length === 0 && <li className="text-sm text-gray-400">No notes yet.</li>}
        {notes.map((note) => (
          <li key={note.id} className="rounded border border-gray-200 bg-white p-3">
            <p className="text-sm text-gray-800">{note.text}</p>
            <p className="mt-1 text-xs text-gray-400">
              {note.authorEmail} &middot; {new Date(note.createdAt).toLocaleString()}
            </p>
          </li>
        ))}
      </ul>
      <form onSubmit={handleSubmit} className="flex gap-2">
        <div className="flex-1">
          <FormInput
            placeholder="Add a note - e.g. this switch was decommissioned"
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
        </div>
        <div className="w-32">
          <PrimaryButton type="submit" disabled={submitting}>
            {submitting ? "Adding..." : "Add note"}
          </PrimaryButton>
        </div>
      </form>
    </div>
  );
}
