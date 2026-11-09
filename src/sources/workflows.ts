import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Sighting } from '../types.js';

/** Built in to every Actions run and short-lived: nothing to rotate. */
const BUILT_IN = new Set(['GITHUB_TOKEN']);

/** Secret names referenced in a workflow file: `secrets.NAME` or `secrets['NAME']`. */
export function secretRefs(yaml: string): string[] {
  const names = new Set<string>();
  const re = /secrets\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_]*)|\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\])/g;
  for (const m of yaml.matchAll(re)) {
    const name = m[1] ?? m[2];
    if (name && !BUILT_IN.has(name)) names.add(name);
  }
  return [...names].sort();
}

export function scanWorkflows(root: string): Sighting[] {
  const dir = join(root, '.github', 'workflows');
  if (!existsSync(dir)) return [];
  const out: Sighting[] = [];
  for (const file of readdirSync(dir).sort()) {
    if (!/\.ya?ml$/.test(file)) continue;
    for (const name of secretRefs(readFileSync(join(dir, file), 'utf8'))) {
      out.push({ name, platform: 'github', location: `github-actions:${file}` });
    }
  }
  return out;
}
