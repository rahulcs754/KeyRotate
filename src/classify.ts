import { ISSUERS, UNKNOWN_ISSUER } from './issuers.js';
import type { Issuer, Priority, Secret, Sighting } from './types.js';

const PUBLIC_PREFIX = /^(NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_)/;
const SECRET_WORDS = /(KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PWD|AUTH|CREDENTIAL|PRIVATE|DSN|WEBHOOK|SALT|SIGNING|CERT|_URL$|_URI$|CONNECTION)/;
/** Values that clearly are secrets wherever they sit (also in NEXT_PUBLIC_ vars). */
const HARD_SECRET_VALUE = /^(sk_live_|rk_live_|sk-ant-|sk-proj-|sk-svcacct-|AKIA|ghp_|github_pat_|npm_|xox[bp]-|sb_secret_|-----BEGIN)/;

export const PRIORITY_ORDER: Record<Priority, number> = { high: 0, medium: 1, low: 2 };

export function matchIssuer(name: string, value?: string): { issuer: Issuer; matchedBy: Secret['matchedBy'] } {
  const upper = name.toUpperCase().replace(PUBLIC_PREFIX, '');
  // A clear name wins: "CLERK_SECRET_KEY=sk_live_..." is Clerk, not Stripe.
  const byName = ISSUERS.find((i) => i.names.some((re) => re.test(upper)));
  if (byName) return { issuer: byName, matchedBy: 'name' };
  if (value) {
    const byValue = ISSUERS.find((i) => i.values?.some((re) => re.test(value)));
    if (byValue) return { issuer: byValue, matchedBy: 'value' };
  }
  return { issuer: UNKNOWN_ISSUER, matchedBy: 'none' };
}

/** Group sightings by name and attach issuer, priority and warnings. */
export function classify(sightings: Sighting[]): Secret[] {
  const byName = new Map<string, Sighting[]>();
  for (const s of sightings) {
    const list = byName.get(s.name) ?? [];
    // Same name in the same place twice (e.g. two Vercel targets merged) adds nothing.
    if (!list.some((x) => x.location === s.location)) list.push(s);
    byName.set(s.name, list);
  }

  const secrets: Secret[] = [];
  for (const [name, list] of byName) {
    const value = list.find((s) => s.value)?.value;
    const { issuer, matchedBy } = matchIssuer(name, value);
    const isPublic = PUBLIC_PREFIX.test(name);
    const config = matchedBy === 'none' && !SECRET_WORDS.test(name.toUpperCase()) && !(value && HARD_SECRET_VALUE.test(value));
    const warnings: string[] = [];
    let priority: Priority = issuer.priority;

    if (isPublic) {
      if (value && HARD_SECRET_VALUE.test(value)) {
        warnings.push('This is a secret key in a public (browser) variable. Anyone who opened your site has it. Rotate it and move it to a server-only variable.');
        priority = 'high';
      } else {
        warnings.push('Public variable: it already ships to the browser. Rotate only if it is meant to be secret.');
        priority = 'low';
      }
    }
    if (config) priority = 'low';
    if (matchedBy === 'value') warnings.push(`Issuer guessed from the value's format (${issuer.name}). Confirm before rotating.`);
    const values = new Set(list.map((s) => s.value).filter(Boolean));
    if (values.size > 1) warnings.push(`Different values in different places (${values.size}). Some copies may already be stale; rotate all of them.`);

    secrets.push({ name, issuer, matchedBy, priority, config, public: isPublic, sightings: list, warnings });
  }

  return secrets.sort((a, b) => PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority] || a.name.localeCompare(b.name));
}
