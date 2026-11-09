import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import type { FetchLike, Sighting } from '../types.js';

async function getJson<T>(fetch: FetchLike, url: string, token: string, extra: Record<string, string> = {}): Promise<T> {
  const res = await fetch(url, { headers: { authorization: `Bearer ${token}`, 'user-agent': 'keyrotate', ...extra } });
  if (!res.ok) throw new Error(`${new URL(url).host} answered ${res.status} for ${new URL(url).pathname}`);
  return (await res.json()) as T;
}

interface VercelEnv {
  key: string;
  type?: string;
  target?: string[] | string;
}

/** Env var names of one Vercel project. Values are not read (we do not decrypt). */
export async function scanVercel(project: string, token: string, fetch: FetchLike, teamId?: string): Promise<Sighting[]> {
  const q = new URLSearchParams({ decrypt: 'false' });
  if (teamId) q.set('teamId', teamId);
  const data = await getJson<{ envs?: VercelEnv[] }>(fetch, `https://api.vercel.com/v9/projects/${encodeURIComponent(project)}/env?${q}`, token);
  const merged = new Map<string, Set<string>>();
  for (const env of data.envs ?? []) {
    if (env.type === 'system') continue;
    const targets = merged.get(env.key) ?? new Set<string>();
    for (const t of Array.isArray(env.target) ? env.target : env.target ? [env.target] : []) targets.add(t);
    merged.set(env.key, targets);
  }
  return [...merged].map(([name, targets]) => ({
    name,
    platform: 'vercel' as const,
    location: `vercel:${project}${targets.size ? ` (${[...targets].sort().join(', ')})` : ''}`,
  }));
}

/** Repo and environment secret names from the GitHub API. */
export async function scanGitHubSecrets(repo: string, token: string, fetch: FetchLike): Promise<Sighting[]> {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new Error(`--github expects owner/repo, got "${repo}"`);
  const api = `https://api.github.com/repos/${repo}`;
  const gh = { accept: 'application/vnd.github+json' };
  const out: Sighting[] = [];
  const repoSecrets = await getJson<{ secrets: Array<{ name: string }> }>(fetch, `${api}/actions/secrets?per_page=100`, token, gh);
  for (const s of repoSecrets.secrets) out.push({ name: s.name, platform: 'github', location: `github-secrets:${repo}` });

  const envs = await getJson<{ environments?: Array<{ name: string }> }>(fetch, `${api}/environments?per_page=100`, token, gh).catch(() => ({ environments: [] }));
  for (const env of envs.environments ?? []) {
    const secrets = await getJson<{ secrets: Array<{ name: string }> }>(fetch, `${api}/environments/${encodeURIComponent(env.name)}/secrets?per_page=100`, token, gh);
    for (const s of secrets.secrets) out.push({ name: s.name, platform: 'github', location: `github-secrets:${repo} (${env.name})` });
  }
  return out;
}

/** Railway service vars that Railway sets itself. */
const RAILWAY_SYSTEM = /^RAILWAY_(?!TOKEN$|API_TOKEN$)/;

/** Output of `railway variables --json` (an object of NAME: value). */
export function scanRailwayExport(path: string): Sighting[] {
  const data = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error(`${path}: expected the JSON object from "railway variables --json"`);
  return Object.entries(data)
    .filter(([name]) => !RAILWAY_SYSTEM.test(name))
    .map(([name, value]) => ({
      name,
      platform: 'railway' as const,
      location: `railway:${basename(path, '.json')}`,
      ...(typeof value === 'string' && value ? { value } : {}),
    }));
}

/** One name per line (or KEY=... lines; values are ignored). For platforms without an API here. */
export function scanNamesFile(path: string, label?: string): Sighting[] {
  const names = new Set<string>();
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)/.exec(line);
    if (m && !line.trim().startsWith('#')) names.add(m[1]!);
  }
  return [...names].map((name) => ({ name, platform: 'list' as const, location: label ?? basename(path) }));
}
