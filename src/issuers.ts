import type { FetchLike, Issuer, VerifyResult } from './types.js';

const TIMEOUT_MS = 10_000;

/** GET/POST an issuer's read-only auth endpoint and read the status code. */
function httpCheck(opts: {
  url: string | ((v: string) => string);
  method?: 'GET' | 'POST';
  headers?: (v: string) => Record<string, string>;
  /** Optional body check for APIs that answer 200 on a bad key. */
  parse?: (status: number, body: string) => VerifyResult | undefined;
}) {
  return async (value: string, fetch: FetchLike): Promise<VerifyResult> => {
    const url = typeof opts.url === 'function' ? opts.url(value) : opts.url;
    const host = new URL(url).host;
    let res: Response;
    try {
      res = await fetch(url, {
        method: opts.method ?? 'GET',
        headers: { 'user-agent': 'keyrotate', ...(opts.headers?.(value) ?? { authorization: `Bearer ${value}` }) },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (err) {
      return { status: 'unknown', detail: `could not reach ${host}: ${(err as Error).message}` };
    }
    const body = opts.parse ? await res.text().catch(() => '') : '';
    const parsed = opts.parse?.(res.status, body);
    if (parsed) return parsed;
    if (res.status === 401 || res.status === 403) return { status: 'dead', detail: `${host} answered ${res.status}` };
    if (res.status >= 200 && res.status < 300) return { status: 'live', detail: `${host} accepted the key (${res.status})` };
    return { status: 'unknown', detail: `${host} answered ${res.status}` };
  };
}

const bearer = (v: string) => ({ authorization: `Bearer ${v}` });

const DEFAULT_STEPS = [
  'Create a new key at the issuer.',
  'Update it in every place under "Stored in", then redeploy.',
  'Revoke (delete) the old key at the issuer.',
];

/**
 * Issuer catalog. Order matters: the first match wins, so put the more
 * specific entries (Anthropic `sk-ant-`, OpenRouter `sk-or-`) before broad ones (OpenAI `sk-`).
 */
export const ISSUERS: Issuer[] = [
  {
    id: 'aws',
    name: 'AWS',
    priority: 'high',
    names: [/^AWS_/, /(^|_)AWS(_|$)/],
    values: [/^(AKIA|ASIA)[A-Z0-9]{16}$/],
    rotateUrl: 'https://console.aws.amazon.com/iam/home#/security_credentials',
    steps: [
      'In IAM, create a second access key for the same user or role (each user can hold two).',
      'Update AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY everywhere, then redeploy.',
      'Set the old key to Inactive, watch for errors for a day, then delete it.',
      'Check CloudTrail for calls made with the old key since the breach date.',
    ],
    manualCheck: 'AWS_ACCESS_KEY_ID=<old id> AWS_SECRET_ACCESS_KEY=<old secret> aws sts get-caller-identity   # must fail with InvalidClientTokenId',
  },
  {
    id: 'stripe',
    name: 'Stripe',
    priority: 'high',
    names: [/STRIPE/],
    values: [/^(sk|rk)_(live|test)_[A-Za-z0-9]{10,}$/, /^whsec_/],
    rotateUrl: 'https://dashboard.stripe.com/apikeys',
    steps: [
      'Use "Roll key" on the secret or restricted key. Pick an expiry for the old key (or "now").',
      'Webhook secrets (whsec_): roll the signing secret on the webhook endpoint page.',
      'Update every place under "Stored in", then redeploy.',
    ],
    verify: async (value, fetch) => {
      if (!/^(sk|rk)_/.test(value)) return { status: 'manual', detail: 'webhook secrets cannot be checked from outside; confirm the endpoint shows only the new secret' };
      return httpCheck({ url: 'https://api.stripe.com/v1/balance', headers: bearer })(value, fetch);
    },
  },
  {
    id: 'razorpay',
    name: 'Razorpay',
    priority: 'high',
    names: [/RAZORPAY/, /^RZP_/],
    values: [/^rzp_(live|test)_/],
    rotateUrl: 'https://dashboard.razorpay.com/app/website-app-settings/api-keys',
    steps: ['Regenerate the API key (key id + secret) in Account & Settings > API Keys.', 'Regenerate webhook secrets too.', ...DEFAULT_STEPS.slice(1, 2)],
    manualCheck: 'curl -u <old key_id>:<old secret> https://api.razorpay.com/v1/payments?count=1   # must return 401',
  },
  {
    id: 'database',
    name: 'Database',
    priority: 'high',
    names: [/DATABASE_URL/, /POSTGRES/, /^PG(PASSWORD|_URL|_PASSWORD)/, /MYSQL/, /MONGO/, /^DB_(PASS|PASSWORD|URL|URI)/, /REDIS_(URL|PASSWORD|TOKEN)/, /^KV_/, /UPSTASH/, /NEON/, /PLANETSCALE/, /TURSO/],
    values: [/^(postgres(ql)?|mysql|mongodb(\+srv)?|rediss?):\/\//],
    steps: [
      'Change the database user password (or create a new user) in your DB provider.',
      'Update the connection string everywhere, then redeploy and restart workers.',
      'Drop the old user or old password, and kill open sessions that still use it.',
      'If the DB was reachable from the internet, review recent logins and data exports.',
    ],
    manualCheck: 'psql "<old url>" -c "select 1"   # (or mysql / mongosh / redis-cli) must fail to log in',
  },
  {
    id: 'app-secret',
    name: 'Your app (self-generated secret)',
    priority: 'high',
    names: [/NEXTAUTH_SECRET/, /^AUTH_SECRET$/, /BETTER_AUTH_SECRET/, /JWT_(SECRET|PRIVATE_KEY|SIGNING)/, /SESSION_SECRET/, /COOKIE_SECRET/, /ENCRYPTION_KEY/, /SIGNING_(KEY|SECRET)/, /^APP_KEY$/, /SECRET_KEY_BASE/, /^SECRET_KEY$/, /CRON_SECRET/, /REVALIDATE_SECRET/, /PREVIEW_SECRET/],
    steps: [
      'Generate a new value: openssl rand -base64 32',
      'Update every place under "Stored in", then redeploy. Users may be logged out and old tokens stop working.',
      'If it encrypts stored data (ENCRYPTION_KEY): re-encrypt the data with the new key before you drop the old one.',
    ],
    manualCheck: 'Send a request signed with the old secret (old session cookie, old cron header) and confirm it is rejected.',
  },
  {
    id: 'github',
    name: 'GitHub',
    priority: 'high',
    names: [/^(GH|GITHUB)_.*(TOKEN|PAT|KEY|SECRET)/, /^GH_TOKEN$/],
    values: [/^(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}$/, /^github_pat_/],
    rotateUrl: 'https://github.com/settings/tokens',
    steps: [
      'Create a new fine-grained token with only the repos and scopes it needs.',
      'Update every place under "Stored in".',
      'Delete the old token. For a GitHub App private key, generate a new key and delete the old one on the App page.',
      'Check the audit log for the old token since the breach date.',
    ],
    verify: httpCheck({ url: 'https://api.github.com/user', headers: (v) => ({ authorization: `Bearer ${v}`, accept: 'application/vnd.github+json' }) }),
  },
  {
    id: 'npm',
    name: 'npm',
    priority: 'high',
    names: [/^NPM_TOKEN$/, /NODE_AUTH_TOKEN/, /NPM_AUTH/],
    values: [/^npm_[A-Za-z0-9]{36}$/],
    rotateUrl: 'https://www.npmjs.com/settings/~/tokens',
    steps: ['Create a new granular token (publish only, limited packages, short expiry).', 'Update CI, then delete the old token.', 'Check that no unexpected package versions were published since the breach date.'],
    verify: httpCheck({ url: 'https://registry.npmjs.org/-/whoami' }),
  },
  {
    id: 'vercel',
    name: 'Vercel',
    priority: 'high',
    names: [/^VERCEL_(TOKEN|API_TOKEN|ACCESS_TOKEN)$/],
    rotateUrl: 'https://vercel.com/account/tokens',
    steps: ['Create a new token scoped to one team, with an expiry.', 'Update CI, then delete the old token.'],
    verify: httpCheck({ url: 'https://api.vercel.com/v2/user' }),
  },
  {
    id: 'railway',
    name: 'Railway',
    priority: 'high',
    names: [/^RAILWAY_(TOKEN|API_TOKEN)$/],
    rotateUrl: 'https://railway.com/account/tokens',
    steps: ['Create a new token (project token if possible).', 'Update CI, then delete the old token.'],
    manualCheck: 'RAILWAY_TOKEN=<old token> railway whoami   # must fail',
  },
  {
    id: 'cloudflare',
    name: 'Cloudflare',
    priority: 'high',
    names: [/CLOUDFLARE/, /^CF_(API|ACCOUNT)_?TOKEN/, /^CF_API_KEY$/],
    rotateUrl: 'https://dash.cloudflare.com/profile/api-tokens',
    steps: ['Use "Roll" on the API token, or create a new one with the same permissions.', 'Update every place under "Stored in", then delete the old token.'],
    verify: httpCheck({ url: 'https://api.cloudflare.com/client/v4/user/tokens/verify' }),
  },
  {
    id: 'supabase',
    name: 'Supabase',
    priority: 'high',
    names: [/SUPABASE/],
    values: [/^sb_secret_/],
    rotateUrl: 'https://supabase.com/dashboard/project/_/settings/api-keys',
    steps: [
      'Create a new secret key (or roll the JWT secret for legacy service_role keys).',
      'Update every place under "Stored in", then redeploy.',
      'Delete the old secret key. Rolling the legacy JWT secret also changes the anon key.',
    ],
    manualCheck: 'curl -H "apikey: <old key>" -H "Authorization: Bearer <old key>" https://<project>.supabase.co/rest/v1/   # must return 401',
  },
  {
    id: 'clerk',
    name: 'Clerk',
    priority: 'high',
    names: [/CLERK/],
    rotateUrl: 'https://dashboard.clerk.com/last-active?path=api-keys',
    steps: DEFAULT_STEPS,
    verify: httpCheck({ url: 'https://api.clerk.com/v1/users?limit=1' }),
  },
  {
    id: 'anthropic',
    name: 'Anthropic',
    priority: 'high',
    names: [/ANTHROPIC/, /CLAUDE_API_KEY/],
    values: [/^sk-ant-/],
    rotateUrl: 'https://console.anthropic.com/settings/keys',
    steps: [...DEFAULT_STEPS, 'Check usage in the Console for spikes since the breach date. Set a spend limit.'],
    verify: httpCheck({ url: 'https://api.anthropic.com/v1/models', headers: (v) => ({ 'x-api-key': v, 'anthropic-version': '2023-06-01' }) }),
  },
  {
    id: 'openrouter',
    name: 'OpenRouter',
    priority: 'high',
    names: [/OPENROUTER/],
    values: [/^sk-or-/],
    rotateUrl: 'https://openrouter.ai/settings/keys',
    steps: [...DEFAULT_STEPS, 'Set a credit limit on the new key.'],
    manualCheck: 'Delete the old key in OpenRouter settings and confirm it no longer shows in the key list.',
  },
  {
    id: 'openai',
    name: 'OpenAI',
    priority: 'high',
    names: [/OPENAI/],
    values: [/^sk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}$/],
    rotateUrl: 'https://platform.openai.com/api-keys',
    steps: [...DEFAULT_STEPS, 'Check usage for spikes since the breach date. Set a project budget.'],
    verify: httpCheck({ url: 'https://api.openai.com/v1/models' }),
  },
  {
    id: 'google',
    name: 'Google Cloud / Gemini',
    priority: 'medium',
    names: [/GEMINI/, /GOOGLE_(API_KEY|GENERATIVE|AI)/, /^GOOGLE_APPLICATION_CREDENTIALS/, /GCP_/, /GOOGLE_(CLIENT_SECRET|SERVICE_ACCOUNT|PRIVATE_KEY)/, /FIREBASE_(PRIVATE_KEY|SERVICE_ACCOUNT|ADMIN)/],
    values: [/^AIza[0-9A-Za-z_-]{35}$/],
    rotateUrl: 'https://console.cloud.google.com/apis/credentials',
    steps: [
      'API key: "Regenerate key", or create a new key with API and app restrictions.',
      'Service account: create a new JSON key, then delete the old key id.',
      'OAuth client secret: add a new secret, deploy, then disable the old one.',
      'Update every place under "Stored in", then redeploy.',
    ],
    verify: async (value, fetch) => {
      if (!/^AIza/.test(value)) return { status: 'manual', detail: 'only API keys (AIza...) can be checked automatically' };
      return httpCheck({
        url: (v) => `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(v)}`,
        headers: () => ({}),
        parse: (status, body) => {
          if (status === 400 && /API_KEY_INVALID|API key not valid/i.test(body)) return { status: 'dead', detail: 'Google says the key is not valid' };
          if (status === 200) return { status: 'live', detail: 'Google accepted the key' };
          // 403 usually means a valid key without the Gemini API enabled: not proof it is dead.
          return { status: 'unknown', detail: `Google answered ${status}; check the key list in the Cloud Console` };
        },
      })(value, fetch);
    },
  },
  {
    id: 'groq',
    name: 'Groq',
    priority: 'medium',
    names: [/GROQ/],
    values: [/^gsk_/],
    rotateUrl: 'https://console.groq.com/keys',
    steps: DEFAULT_STEPS,
    verify: httpCheck({ url: 'https://api.groq.com/openai/v1/models' }),
  },
  {
    id: 'mistral',
    name: 'Mistral',
    priority: 'medium',
    names: [/MISTRAL/],
    rotateUrl: 'https://console.mistral.ai/api-keys',
    steps: DEFAULT_STEPS,
    verify: httpCheck({ url: 'https://api.mistral.ai/v1/models' }),
  },
  {
    id: 'huggingface',
    name: 'Hugging Face',
    priority: 'medium',
    names: [/^HF_/, /HUGGING_?FACE/],
    values: [/^hf_[A-Za-z0-9]{30,}$/],
    rotateUrl: 'https://huggingface.co/settings/tokens',
    steps: DEFAULT_STEPS,
    verify: httpCheck({ url: 'https://huggingface.co/api/whoami-v2' }),
  },
  {
    id: 'replicate',
    name: 'Replicate',
    priority: 'medium',
    names: [/REPLICATE/],
    values: [/^r8_/],
    rotateUrl: 'https://replicate.com/account/api-tokens',
    steps: DEFAULT_STEPS,
    verify: httpCheck({ url: 'https://api.replicate.com/v1/account' }),
  },
  {
    id: 'pinecone',
    name: 'Pinecone',
    priority: 'medium',
    names: [/PINECONE/],
    values: [/^pcsk_/],
    rotateUrl: 'https://app.pinecone.io/',
    steps: DEFAULT_STEPS,
    verify: httpCheck({ url: 'https://api.pinecone.io/indexes', headers: (v) => ({ 'api-key': v, 'x-pinecone-api-version': '2025-04' }) }),
  },
  {
    id: 'slack',
    name: 'Slack',
    priority: 'medium',
    names: [/SLACK/],
    values: [/^xox[abposr]-/, /^https:\/\/hooks\.slack\.com\//],
    rotateUrl: 'https://api.slack.com/apps',
    steps: ['Bot/user token: on the app page use "Revoke tokens", then reinstall the app.', 'Signing secret: "Regenerate" on Basic Information.', 'Webhook URL: remove the old incoming webhook and add a new one.', 'Update every place under "Stored in".'],
    verify: async (value, fetch) => {
      if (!/^xox/.test(value)) return { status: 'manual', detail: 'only tokens (xox...) can be checked automatically' };
      return httpCheck({
        url: 'https://slack.com/api/auth.test',
        method: 'POST',
        headers: bearer,
        parse: (status, body) => {
          if (status !== 200) return undefined;
          try {
            const json = JSON.parse(body) as { ok?: boolean; error?: string };
            if (json.ok) return { status: 'live', detail: 'Slack accepted the token' };
            if (json.error && /invalid_auth|token_revoked|account_inactive|not_authed|token_expired/.test(json.error)) return { status: 'dead', detail: `Slack said ${json.error}` };
            return { status: 'unknown', detail: `Slack said ${json.error ?? 'unknown error'}` };
          } catch {
            return { status: 'unknown', detail: 'Slack sent an unreadable answer' };
          }
        },
      })(value, fetch);
    },
  },
  {
    id: 'sendgrid',
    name: 'SendGrid',
    priority: 'medium',
    names: [/SENDGRID/],
    values: [/^SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$/],
    rotateUrl: 'https://app.sendgrid.com/settings/api_keys',
    steps: DEFAULT_STEPS,
    verify: httpCheck({ url: 'https://api.sendgrid.com/v3/scopes' }),
  },
  {
    id: 'resend',
    name: 'Resend',
    priority: 'medium',
    names: [/RESEND/],
    values: [/^re_[A-Za-z0-9_]{20,}$/],
    rotateUrl: 'https://resend.com/api-keys',
    steps: DEFAULT_STEPS,
    manualCheck: 'Delete the old key in the Resend dashboard and confirm it is gone from the list.',
  },
  {
    id: 'twilio',
    name: 'Twilio',
    priority: 'medium',
    names: [/TWILIO/],
    rotateUrl: 'https://console.twilio.com/us1/account/keys-credentials/api-keys',
    steps: ['Create a new API key (or promote a secondary auth token).', 'Update every place under "Stored in".', 'Delete the old API key, or request a new secondary auth token and promote it.'],
    manualCheck: 'curl -u <old sid>:<old secret> https://api.twilio.com/2010-04-01/Accounts.json   # must return 401',
  },
  {
    id: 'sentry',
    name: 'Sentry',
    priority: 'medium',
    names: [/SENTRY/],
    values: [/^sntry[su]_/],
    rotateUrl: 'https://sentry.io/settings/account/api/auth-tokens/',
    steps: ['Auth token: create a new one, update CI, revoke the old one.', 'DSN: low risk (it is public in the browser); create a new client key only if you see spam events.'],
    manualCheck: 'curl -H "Authorization: Bearer <old token>" https://sentry.io/api/0/   # must return 401',
  },
];

export const UNKNOWN_ISSUER: Issuer = {
  id: 'unknown',
  name: 'Unknown issuer',
  priority: 'medium',
  names: [],
  steps: ['Find which service issued this value (search your code for the name).', ...DEFAULT_STEPS],
  manualCheck: 'Call the service with the old value and confirm it is rejected.',
};

export function issuerById(id: string): Issuer | undefined {
  return id === UNKNOWN_ISSUER.id ? UNKNOWN_ISSUER : ISSUERS.find((i) => i.id === id);
}
