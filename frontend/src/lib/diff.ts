export interface FieldDiff {
  key: string;
  before: string | undefined;
  after: string | undefined;
}

/** Field-by-field comparison of two decrypted resource value objects - the diff
 * itself never touches the network or gets stored; it's computed entirely from
 * two already-decrypted plaintext objects the caller obtained locally. */
export function diffResourceValues(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
): FieldDiff[] {
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  const diffs: FieldDiff[] = [];
  for (const key of keys) {
    const b = before[key];
    const a = after[key];
    if (JSON.stringify(b) !== JSON.stringify(a)) {
      diffs.push({ key, before: b === undefined ? undefined : String(b), after: a === undefined ? undefined : String(a) });
    }
  }
  return diffs;
}
