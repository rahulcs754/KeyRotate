import { describe, expect, it } from 'vitest';
import { verifyText } from '../src/report.js';
import { hasLiveOldKey, mask, verifyKeys } from '../src/verify.js';
import { fake, fakeFetch } from './helpers.js';

const m = (o: Record<string, string>) => new Map(Object.entries(o));

describe('verifyKeys', () => {
  it('reports dead, live, manual and placeholder', async () => {
    const { fetch, calls } = fakeFetch({
      'api.openai.com': { status: 401 },
      'api.anthropic.com': { status: 200 },
      'api.stripe.com': { status: 401 },
    });
    const rows = await verifyKeys(
      m({ OPENAI_API_KEY: fake.openai(), ANTHROPIC_API_KEY: fake.anthropic(), STRIPE_SECRET_KEY: fake.stripeLive(), AWS_ACCESS_KEY_ID: fake.aws(), RESEND_API_KEY: 'changeme' }),
      new Map(),
      fetch,
    );
    const by = Object.fromEntries(rows.map((r) => [r.name, r.old.status]));
    expect(by).toEqual({ OPENAI_API_KEY: 'dead', ANTHROPIC_API_KEY: 'live', STRIPE_SECRET_KEY: 'dead', AWS_ACCESS_KEY_ID: 'manual', RESEND_API_KEY: 'placeholder' });
    expect(hasLiveOldKey(rows)).toBe(true);
    // Each key only goes to its own issuer.
    const anthropicCall = calls.find((c) => c.url.includes('anthropic'))!;
    expect((anthropicCall.init!.headers as Record<string, string>)['x-api-key']).toBe(fake.anthropic());
    expect(calls).toHaveLength(3);
  });

  it('checks new keys and catches "not rotated"', async () => {
    const { fetch } = fakeFetch({ 'api.github.com': { status: 401 }, 'api.openai.com': { status: 200 } });
    const oldGh = fake.github();
    const rows = await verifyKeys(m({ GH_TOKEN: oldGh, OPENAI_API_KEY: fake.openai() }), m({ GH_TOKEN: 'ghp_' + 'Z'.repeat(36), OPENAI_API_KEY: fake.openai() }), fetch);
    const gh = rows.find((r) => r.name === 'GH_TOKEN')!;
    expect(gh.old.status).toBe('dead');
    expect(gh.next!.status).toBe('dead'); // fake fetch says 401 for both
    const oa = rows.find((r) => r.name === 'OPENAI_API_KEY')!;
    expect(oa.next!.detail).toMatch(/NOT ROTATED/);
    expect(hasLiveOldKey(rows)).toBe(true);
    const text = verifyText(rows);
    expect(text).toContain('❌ same as old');
    expect(text).toContain('❌ fails');
  });

  it('reads Slack and Google answers that are not plain 401', async () => {
    const { fetch } = fakeFetch({
      'slack.com': { status: 200, body: { ok: false, error: 'invalid_auth' } },
      'generativelanguage.googleapis.com': { status: 400, body: { error: { message: 'API key not valid. Please pass a valid API key.' } } },
    });
    const rows = await verifyKeys(m({ SLACK_BOT_TOKEN: fake.slack(), GEMINI_API_KEY: fake.google() }), new Map(), fetch);
    expect(rows.map((r) => r.old.status)).toEqual(['dead', 'dead']);
  });

  it('treats a network error as unknown, not dead', async () => {
    const rows = await verifyKeys(m({ OPENAI_API_KEY: fake.openai() }), new Map(), async () => {
      throw new Error('ECONNRESET');
    });
    expect(rows[0]!.old).toMatchObject({ status: 'unknown' });
    expect(hasLiveOldKey(rows)).toBe(false);
  });

  it('can limit to some names', async () => {
    const { fetch } = fakeFetch({ 'api.openai.com': { status: 401 } });
    const rows = await verifyKeys(m({ OPENAI_API_KEY: fake.openai(), GH_TOKEN: fake.github() }), new Map(), fetch, new Set(['OPENAI_API_KEY']));
    expect(rows.map((r) => r.name)).toEqual(['OPENAI_API_KEY']);
  });
});

describe('output', () => {
  it('masks values', () => {
    expect(mask(fake.openai())).toBe('sk-p…AA (56 chars)');
    expect(mask('short')).toBe('*****');
  });

  it('never prints the value', async () => {
    const { fetch } = fakeFetch({ 'api.openai.com': { status: 200 } });
    const rows = await verifyKeys(m({ OPENAI_API_KEY: fake.openai() }), new Map(), fetch);
    const text = verifyText(rows);
    expect(text).toContain('❌ LIVE');
    expect(text).toContain('still work');
    expect(text).not.toContain(fake.openai());
  });
});
