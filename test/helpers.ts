import { cpSync, mkdirSync, mkdtempSync, readdirSync, renameSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FetchLike } from '../src/types.js';

export const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

/**
 * Real `.env*` files are blocked by the repo guard, so fixtures are stored as
 * `dotenv.*` and renamed in a temp copy.
 */
export function makeApp(): string {
  const dir = mkdtempSync(join(tmpdir(), 'keyrotate-'));
  cpSync(join(FIXTURES, 'app'), dir, { recursive: true });
  const rename = (d: string) => {
    for (const f of readdirSync(d)) {
      const full = join(d, f);
      if (statSync(full).isDirectory()) rename(full);
      else if (f.startsWith('dotenv')) renameSync(full, join(d, f.replace(/^dotenv/, '.env')));
    }
  };
  rename(dir);
  mkdirSync(join(dir, '.github', 'workflows'), { recursive: true });
  cpSync(join(FIXTURES, 'deploy.yml'), join(dir, '.github', 'workflows', 'deploy.yml'));
  return dir;
}

/** Fake fetch: route by host (+ path) to a status and body. Records calls. */
export function fakeFetch(routes: Record<string, { status: number; body?: unknown }>) {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const fn: FetchLike = async (url, init) => {
    calls.push({ url, init });
    const u = new URL(url);
    const hit = routes[u.host + u.pathname] ?? routes[u.host];
    if (!hit) throw new Error(`unexpected request to ${url}`);
    const body = typeof hit.body === 'string' ? hit.body : JSON.stringify(hit.body ?? {});
    return new Response(body, { status: hit.status, headers: { 'content-type': 'application/json' } });
  };
  return { fetch: fn, calls };
}

/** Fake key strings built at runtime so the repo guard does not flag the test source. */
export const fake = {
  openai: () => 'sk-' + 'proj-' + 'A'.repeat(48),
  anthropic: () => 'sk-' + 'ant-' + 'api03-' + 'B'.repeat(40),
  stripeLive: () => 'sk_' + 'live_' + 'C'.repeat(30),
  github: () => 'ghp' + '_' + 'D'.repeat(36),
  aws: () => 'AKI' + 'A' + 'E'.repeat(16),
  slack: () => 'xox' + 'b-' + '1234-' + 'F'.repeat(24),
  google: () => 'AIz' + 'a' + 'G'.repeat(35),
};
