import { matchIssuer } from './classify.js';
import type { FetchLike, Issuer, VerifyResult } from './types.js';

const PLACEHOLDER = /^(|x+|changeme|change_me|todo|your[-_].*|<.*>|\.\.\.|null|undefined|test|example|placeholder|\*+)$/i;

export function mask(value: string): string {
  if (value.length <= 10) return '*'.repeat(Math.min(value.length, 6));
  return `${value.slice(0, 4)}…${value.slice(-2)} (${value.length} chars)`;
}

export interface VerifyRow {
  name: string;
  issuer: Issuer;
  masked: string;
  old: VerifyResult;
  /** Present when a new value was given for the same name. */
  next?: VerifyResult;
}

async function check(issuer: Issuer, value: string | undefined, fetch: FetchLike): Promise<VerifyResult> {
  if (value === undefined) return { status: 'no-value', detail: 'no value given' };
  if (PLACEHOLDER.test(value.trim())) return { status: 'placeholder', detail: 'value looks like a placeholder' };
  if (!issuer.verify) return { status: 'manual', detail: issuer.manualCheck ?? 'no automatic check for this issuer' };
  return issuer.verify(value, fetch);
}

/**
 * Check each old value against its issuer's read-only auth endpoint.
 * A rotated key should come back `dead`. If new values are given, they should come back `live`.
 * Values only go to the hard-coded issuer host and are never printed.
 */
export async function verifyKeys(
  oldValues: Map<string, string>,
  newValues: Map<string, string>,
  fetch: FetchLike,
  onlyNames?: Set<string>,
  concurrency = 4,
): Promise<VerifyRow[]> {
  const names = [...oldValues.keys()].filter((n) => !onlyNames || onlyNames.has(n)).sort();
  const rows: VerifyRow[] = new Array(names.length);
  let next = 0;
  const worker = async () => {
    while (next < names.length) {
      const i = next++;
      const name = names[i]!;
      const oldValue = oldValues.get(name)!;
      const { issuer } = matchIssuer(name, oldValue);
      const row: VerifyRow = { name, issuer, masked: mask(oldValue), old: await check(issuer, oldValue, fetch) };
      if (newValues.has(name)) {
        const newValue = newValues.get(name)!;
        row.next = newValue === oldValue ? { status: 'live', detail: 'NOT ROTATED: new value is the same as the old one' } : await check(issuer, newValue, fetch);
      }
      rows[i] = row;
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, names.length) }, worker));
  return rows;
}

/** True when an old key still works (or was not rotated at all). */
export function hasLiveOldKey(rows: VerifyRow[]): boolean {
  return rows.some((r) => r.old.status === 'live' || r.next?.detail.startsWith('NOT ROTATED'));
}
