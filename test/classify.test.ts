import { describe, expect, it } from 'vitest';
import { classify, matchIssuer } from '../src/classify.js';
import { planMarkdown, filterBreached, inventoryText } from '../src/report.js';
import type { Sighting } from '../src/types.js';
import { fake } from './helpers.js';

const s = (name: string, location = '.env', value?: string, platform: Sighting['platform'] = 'env'): Sighting => ({ name, location, platform, ...(value ? { value } : {}) });

describe('matchIssuer', () => {
  it.each([
    ['OPENAI_API_KEY', 'openai'],
    ['ANTHROPIC_API_KEY', 'anthropic'],
    ['AWS_SECRET_ACCESS_KEY', 'aws'],
    ['STRIPE_WEBHOOK_SECRET', 'stripe'],
    ['DATABASE_URL', 'database'],
    ['NEXTAUTH_SECRET', 'app-secret'],
    ['GH_TOKEN', 'github'],
    ['NODE_AUTH_TOKEN', 'npm'],
    ['VERCEL_TOKEN', 'vercel'],
    ['RAZORPAY_KEY_SECRET', 'razorpay'],
    ['UPSTASH_REDIS_REST_TOKEN', 'database'],
    ['GEMINI_API_KEY', 'google'],
    ['SLACK_BOT_TOKEN', 'slack'],
  ])('%s -> %s by name', (name, id) => {
    expect(matchIssuer(name).issuer.id).toBe(id);
  });

  it('guesses the issuer from the value when the name is generic', () => {
    expect(matchIssuer('API_KEY', fake.anthropic())).toMatchObject({ matchedBy: 'value', issuer: { id: 'anthropic' } });
    expect(matchIssuer('KEY', fake.openai()).issuer.id).toBe('openai');
    expect(matchIssuer('KEY', fake.aws()).issuer.id).toBe('aws');
    expect(matchIssuer('URL', 'mongodb+srv://u:p@x').issuer.id).toBe('database');
  });

  it('prefers a clear name over the value format (Clerk keys look like Stripe keys)', () => {
    expect(matchIssuer('CLERK_SECRET_KEY', fake.stripeLive()).issuer.id).toBe('clerk');
  });

  it('falls back to unknown', () => {
    expect(matchIssuer('MY_THING').issuer.id).toBe('unknown');
  });
});

describe('classify', () => {
  it('groups by name, sorts high first, marks config and public vars', () => {
    const out = classify([
      s('PORT'),
      s('OPENAI_API_KEY', '.env'),
      s('OPENAI_API_KEY', 'vercel:app', undefined, 'vercel'),
      s('OPENAI_API_KEY', '.env'),
      s('NEXT_PUBLIC_POSTHOG_KEY'),
      s('MY_WEBHOOK_SECRET'),
    ]);
    expect(out.map((x) => [x.name, x.priority])).toEqual([
      ['OPENAI_API_KEY', 'high'],
      ['MY_WEBHOOK_SECRET', 'medium'],
      ['NEXT_PUBLIC_POSTHOG_KEY', 'low'],
      ['PORT', 'low'],
    ]);
    expect(out[0]!.sightings).toHaveLength(2);
    expect(out.find((x) => x.name === 'PORT')!.config).toBe(true);
    expect(out.find((x) => x.name === 'MY_WEBHOOK_SECRET')!.config).toBe(false);
  });

  it('flags a real secret inside a public variable as high', () => {
    const [x] = classify([s('NEXT_PUBLIC_STRIPE_KEY', '.env', fake.stripeLive())]);
    expect(x!.priority).toBe('high');
    expect(x!.warnings[0]).toMatch(/public \(browser\) variable/);
  });

  it('warns when copies hold different values', () => {
    const [x] = classify([s('OPENAI_API_KEY', '.env', 'a'), s('OPENAI_API_KEY', 'railway:x', 'b', 'railway')]);
    expect(x!.warnings.join(' ')).toMatch(/Different values/);
  });
});

describe('plan + inventory', () => {
  const secrets = classify([
    s('STRIPE_SECRET_KEY', '.env.local'),
    s('STRIPE_SECRET_KEY', 'vercel:shop (production)', undefined, 'vercel'),
    s('RESEND_API_KEY', '.env.local'),
    s('PORT', '.env.local'),
  ]);

  it('writes a checklist with locations, links and verify hints', () => {
    const md = planMarkdown(secrets, { date: '2026-11-02' });
    expect(md).toContain('2 secrets found in 2 places');
    expect(md).toContain('## 🔴 High: rotate first (1)');
    expect(md).toContain('- [ ] **`STRIPE_SECRET_KEY`** (Stripe)');
    expect(md).toContain('Stored in: `.env.local`, `vercel:shop (production)`');
    expect(md).toContain('https://dashboard.stripe.com/apikeys');
    expect(md).toContain('Verify: automatic');
    expect(md).toContain('Verify by hand'); // Resend
    expect(md).toContain('## Probably not secrets (1)');
  });

  it('filters to the breached platform', () => {
    const only = filterBreached(secrets, 'vercel');
    expect(only.map((x) => x.name)).toEqual(['STRIPE_SECRET_KEY']);
    expect(planMarkdown(only, { breached: 'vercel', date: 'd' })).toContain('Breached platform: vercel');
  });

  it('prints a table', () => {
    expect(inventoryText(secrets)).toMatch(/STRIPE_SECRET_KEY\s+Stripe\s+\.env\.local, vercel:shop/);
    expect(inventoryText([])).toMatch(/No env vars found/);
  });

  it('never prints values', () => {
    const withValue = classify([s('OPENAI_API_KEY', '.env', fake.openai())]);
    expect(planMarkdown(withValue)).not.toContain(fake.openai());
    expect(inventoryText(withValue)).not.toContain(fake.openai());
  });
});
