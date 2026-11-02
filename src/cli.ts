import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { classify } from './classify.js';
import { filterBreached, inventoryText, planMarkdown, verifyText } from './report.js';
import { findEnvFiles, parseEnv, scanEnvFile } from './sources/envfile.js';
import { scanGitHubSecrets, scanNamesFile, scanRailwayExport, scanVercel } from './sources/remote.js';
import { scanWorkflows } from './sources/workflows.js';
import type { Platform, Sighting } from './types.js';
import { hasLiveOldKey, verifyKeys } from './verify.js';

const VERSION = '0.1.0';
const PLATFORMS: Platform[] = ['env', 'github', 'vercel', 'railway', 'list'];

const HELP = `keyrotate ${VERSION}
After a platform breach: find every secret, plan the rotation, prove the old keys are dead.

Usage:
  keyrotate scan   [sources]            List env vars, their issuer and where they are stored
  keyrotate plan   [sources] [--out f]  Write a Markdown rotation checklist (high priority first)
  keyrotate verify --old <file> [--new <file>] [--only NAME]
                                        Check old keys now fail (and new keys work)

Sources (default: .env* files and .github/workflows in the current folder):
  --dir <path>             Folder to scan (default: .)
  --env-file <file>        Extra env file (repeatable)
  --no-local               Skip .env* files and workflows in --dir
  --vercel <project>       Vercel project name or id (needs VERCEL_TOKEN)
  --vercel-team <id>       Vercel team id
  --github <owner/repo>    Repo + environment secret names (needs GITHUB_TOKEN)
  --railway <file.json>    Output of: railway variables --json > railway.json
  --names-file <file>      One name per line, for any other platform

Options:
  --breached <platform>    Only secrets stored on: ${PLATFORMS.join(', ')}
  --json                   JSON output
  --out <file>             plan: write Markdown to a file
  -h, --help               Show help
  -v, --version            Show version

Secret values are only read from local files, never printed, and only sent
to the issuer's own API during "verify".`;

function fail(msg: string): never {
  console.error(`keyrotate: ${msg}`);
  process.exit(2);
}

async function collect(v: Record<string, unknown>): Promise<Sighting[]> {
  const root = resolve((v.dir as string) ?? '.');
  const out: Sighting[] = [];
  if (!v['no-local']) {
    for (const f of findEnvFiles(root)) out.push(...scanEnvFile(f, root));
    out.push(...scanWorkflows(root));
  }
  for (const f of (v['env-file'] as string[] | undefined) ?? []) {
    if (!existsSync(f)) fail(`env file not found: ${f}`);
    out.push(...scanEnvFile(resolve(f), root));
  }
  for (const project of (v.vercel as string[] | undefined) ?? []) {
    const token = process.env.VERCEL_TOKEN;
    if (!token) fail('--vercel needs VERCEL_TOKEN (create one at https://vercel.com/account/tokens)');
    out.push(...(await scanVercel(project, token, fetch, v['vercel-team'] as string | undefined)));
  }
  for (const repo of (v.github as string[] | undefined) ?? []) {
    const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
    if (!token) fail('--github needs GITHUB_TOKEN with "Secrets: read" (or run: GITHUB_TOKEN=$(gh auth token) keyrotate ...)');
    out.push(...(await scanGitHubSecrets(repo, token, fetch)));
  }
  for (const f of (v.railway as string[] | undefined) ?? []) out.push(...scanRailwayExport(f));
  for (const f of (v['names-file'] as string[] | undefined) ?? []) out.push(...scanNamesFile(f));
  return out;
}

function loadValues(files: string[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const f of files) {
    if (!existsSync(f)) fail(`file not found: ${f}`);
    const text = readFileSync(f, 'utf8');
    if (f.endsWith('.json')) {
      for (const [k, val] of Object.entries(JSON.parse(text) as Record<string, unknown>)) if (typeof val === 'string' && val) map.set(k, val);
    } else {
      for (const { name, value } of parseEnv(text)) if (value) map.set(name, value);
    }
  }
  return map;
}

async function main() {
  const { values: v, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      dir: { type: 'string' },
      'env-file': { type: 'string', multiple: true },
      'no-local': { type: 'boolean' },
      vercel: { type: 'string', multiple: true },
      'vercel-team': { type: 'string' },
      github: { type: 'string', multiple: true },
      railway: { type: 'string', multiple: true },
      'names-file': { type: 'string', multiple: true },
      breached: { type: 'string' },
      json: { type: 'boolean' },
      out: { type: 'string' },
      old: { type: 'string', multiple: true },
      new: { type: 'string', multiple: true },
      only: { type: 'string', multiple: true },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  });
  if (v.version) return console.log(VERSION);
  const cmd = positionals[0];
  if (v.help || !cmd) return console.log(HELP);

  const breached = v.breached as Platform | undefined;
  if (breached && !PLATFORMS.includes(breached)) fail(`--breached must be one of: ${PLATFORMS.join(', ')}`);

  if (cmd === 'scan' || cmd === 'plan') {
    const secrets = filterBreached(classify(await collect(v)), breached);
    if (v.json) {
      const json = secrets.map((s) => ({
        name: s.name,
        issuer: s.issuer.id,
        matchedBy: s.matchedBy,
        priority: s.priority,
        config: s.config,
        public: s.public,
        storedIn: s.sightings.map((x) => x.location),
        rotateUrl: s.issuer.rotateUrl,
        autoVerify: Boolean(s.issuer.verify),
        warnings: s.warnings,
      }));
      return console.log(JSON.stringify(json, null, 2));
    }
    if (cmd === 'scan') return console.log(inventoryText(secrets));
    const md = planMarkdown(secrets, { breached });
    if (v.out) {
      writeFileSync(v.out, md);
      return console.log(`Wrote ${v.out} (${secrets.filter((s) => !s.config).length} secrets).`);
    }
    return console.log(md);
  }

  if (cmd === 'verify') {
    if (!v.old?.length) fail('verify needs --old <file> with the OLD values (for example a backup of your .env before rotating)');
    const rows = await verifyKeys(loadValues(v.old), loadValues(v.new ?? []), fetch, v.only?.length ? new Set(v.only) : undefined);
    if (v.json) {
      console.log(JSON.stringify(rows.map((r) => ({ name: r.name, issuer: r.issuer.id, old: r.old, new: r.next })), null, 2));
    } else {
      console.log(verifyText(rows));
    }
    if (hasLiveOldKey(rows)) process.exitCode = 1;
    return;
  }

  fail(`unknown command "${cmd}". Run keyrotate --help`);
}

main().catch((err: Error) => fail(err.message));
