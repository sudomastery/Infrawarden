import { FieldDiff } from "../lib/diff";

export default function ResourceChangeBanner({
  changedBy,
  diffs,
  onAccept,
  onIgnore,
}: {
  changedBy: string;
  diffs: FieldDiff[];
  onAccept: () => void;
  onIgnore: () => void;
}) {
  return (
    <div className="mb-4 rounded border border-warning-200 bg-warning-50 p-4">
      <p className="mb-2 text-sm font-medium text-warning-800">Changed by {changedBy}</p>
      <ul className="mb-3 space-y-1 text-xs text-warning-700">
        {diffs.map((d) => (
          <li key={d.key}>
            <span className="font-medium">{d.key}</span>: {d.before ?? "(empty)"} &rarr; {d.after ?? "(empty)"}
          </li>
        ))}
      </ul>
      <div className="flex gap-2">
        <button
          onClick={onAccept}
          className="rounded bg-primary-600 px-3 py-1 text-xs font-medium text-white hover:bg-primary-700"
        >
          Accept
        </button>
        <button
          onClick={onIgnore}
          className="rounded border border-gray-300 px-3 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50"
        >
          Ignore
        </button>
      </div>
    </div>
  );
}
