import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { findEnvFiles, parseEnv, scanEnvFile } from '../src/sources/envfile.js';
import { scanGitHubSecrets, scanNamesFile, scanRailwayExport, scanVercel } from '../src/sources/remote.js';
import { scanWorkflows, secretRefs } from '../src/sources/workflows.js';
import { FIXTURES, fakeFetch, makeApp } from './helpers.js';

describe('parseEnv', () => {
  it('handles export, quotes, inline comments and multi-line values', () => {
    const vars = Object.fromEntries(parseEnv(`# c\nexport A=1\nB="two words" \nC='x' \nD=val # note\nE="-----BEGIN\nmid\n-----END"\nF=\n bad line`).map((v) => [v.name, v.value]));
    expect(vars).toEqual({ A: '1', B: 'two words', C: 'x', D: 'val', E: '-----BEGIN\nmid\n-----END', F: '' });
  });
});

describe('env files', () => {
  it('finds nested .env files and skips template values', () => {
    const root = makeApp();
    const files = findEnvFiles(root).map((f) => f.slice(root.length + 1));
    expect(files).toEqual(['.env.example', '.env.local', join('apps', 'web', '.env.production')]);
    const example = scanEnvFile(join(root, '.env.example'), root);
    expect(example.every((s) => s.value === undefined)).toBe(true);
    const local = scanEnvFile(join(root, '.env.local'), root);
    expect(local.find((s) => s.name === 'PORT')).toMatchObject({ platform: 'env', location: '.env.local', value: '3000' });
  });
});

describe('workflows', () => {
  it('finds secret refs in both syntaxes and skips GITHUB_TOKEN', () => {
    expect(secretRefs('${{ secrets.A }} ${{secrets.B}} ${{ secrets["C"] }} ${{ secrets.GITHUB_TOKEN }} ${{ secrets.A }}')).toEqual(['A', 'B', 'C']);
    const s = scanWorkflows(makeApp());
    expect(s.map((x) => x.name)).toEqual(['NPM_TOKEN', 'OPENAI_API_KEY', 'VERCEL_TOKEN']);
    expect(s[0]!.location).toBe('github-actions:deploy.yml');
  });
});

describe('vercel', () => {
  it('lists names, merges targets, skips system vars, never decrypts', async () => {
    const { fetch, calls } = fakeFetch({
      'api.vercel.com': {
        status: 200,
        body: { envs: [
          { key: 'OPENAI_API_KEY', type: 'encrypted', target: ['production'] },
          { key: 'OPENAI_API_KEY', type: 'encrypted', target: ['preview', 'development'] },
          { key: 'VERCEL_URL', type: 'system', target: ['production'] },
          { key: 'STRIPE_SECRET_KEY', type: 'sensitive', target: 'production' },
        ] },
      },
    });
    const s = await scanVercel('shop', 'tok', fetch, 'team_1');
    expect(s).toEqual([
      { name: 'OPENAI_API_KEY', platform: 'vercel', location: 'vercel:shop (development, preview, production)' },
      { name: 'STRIPE_SECRET_KEY', platform: 'vercel', location: 'vercel:shop (production)' },
    ]);
    expect(calls[0]!.url).toContain('decrypt=false');
    expect(calls[0]!.url).toContain('teamId=team_1');
  });

  it('throws a clear error on a bad token', async () => {
    const { fetch } = fakeFetch({ 'api.vercel.com': { status: 403 } });
    await expect(scanVercel('shop', 'bad', fetch)).rejects.toThrow('api.vercel.com answered 403');
  });
});

describe('github secrets', () => {
  it('lists repo and environment secrets', async () => {
    const { fetch } = fakeFetch({
      'api.github.com/repos/o/r/actions/secrets': { status: 200, body: { secrets: [{ name: 'NPM_TOKEN' }] } },
      'api.github.com/repos/o/r/environments': { status: 200, body: { environments: [{ name: 'prod' }] } },
      'api.github.com/repos/o/r/environments/prod/secrets': { status: 200, body: { secrets: [{ name: 'DATABASE_URL' }] } },
    });
    expect((await scanGitHubSecrets('o/r', 't', fetch)).map((s) => s.location)).toEqual(['github-secrets:o/r', 'github-secrets:o/r (prod)']);
  });

  it('rejects a bad repo name', async () => {
    await expect(scanGitHubSecrets('nope', 't', fakeFetch({}).fetch)).rejects.toThrow('owner/repo');
  });
});

describe('railway + names file', () => {
  it('reads railway export, drops Railway system vars, keeps RAILWAY_TOKEN', () => {
    const s = scanRailwayExport(join(FIXTURES, 'railway.json'));
    expect(s.map((x) => x.name)).toEqual(['DATABASE_URL', 'RAILWAY_TOKEN', 'ANTHROPIC_API_KEY']);
    expect(s[0]!.value).toMatch(/^postgres:/);
    expect(s[1]!.value).toBeUndefined();
  });

  it('reads plain names and KEY=value lines', () => {
    const s = scanNamesFile(join(FIXTURES, 'app', 'dotenv.example'), 'netlify');
    expect(s).toEqual([
      { name: 'OPENAI_API_KEY', platform: 'list', location: 'netlify' },
      { name: 'RESEND_API_KEY', platform: 'list', location: 'netlify' },
    ]);
  });
});
