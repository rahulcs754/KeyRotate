#!/usr/bin/env node

// src/cli.ts
import { existsSync as existsSync2, readFileSync as readFileSync4, writeFileSync } from "fs";
import { resolve } from "path";
import { parseArgs } from "util";

// src/issuers.ts
var TIMEOUT_MS = 1e4;
function httpCheck(opts) {
  return async (value, fetch2) => {
    const url = typeof opts.url === "function" ? opts.url(value) : opts.url;
    const host = new URL(url).host;
    let res;
    try {
      res = await fetch2(url, {
        method: opts.method ?? "GET",
        headers: { "user-agent": "keyrotate", ...opts.headers?.(value) ?? { authorization: `Bearer ${value}` } },
        signal: AbortSignal.timeout(TIMEOUT_MS)
      });
    } catch (err) {
      return { status: "unknown", detail: `could not reach ${host}: ${err.message}` };
    }
    const body = opts.parse ? await res.text().catch(() => "") : "";
    const parsed = opts.parse?.(res.status, body);
    if (parsed) return parsed;
    if (res.status === 401 || res.status === 403) return { status: "dead", detail: `${host} answered ${res.status}` };
    if (res.status >= 200 && res.status < 300) return { status: "live", detail: `${host} accepted the key (${res.status})` };
    return { status: "unknown", detail: `${host} answered ${res.status}` };
  };
}
var bearer = (v) => ({ authorization: `Bearer ${v}` });
var DEFAULT_STEPS = [
  "Create a new key at the issuer.",
  'Update it in every place under "Stored in", then redeploy.',
  "Revoke (delete) the old key at the issuer."
];
var ISSUERS = [
  {
    id: "aws",
    name: "AWS",
    priority: "high",
    names: [/^AWS_/, /(^|_)AWS(_|$)/],
    values: [/^(AKIA|ASIA)[A-Z0-9]{16}$/],
    rotateUrl: "https://console.aws.amazon.com/iam/home#/security_credentials",
    steps: [
      "In IAM, create a second access key for the same user or role (each user can hold two).",
      "Update AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY everywhere, then redeploy.",
      "Set the old key to Inactive, watch for errors for a day, then delete it.",
      "Check CloudTrail for calls made with the old key since the breach date."
    ],
    manualCheck: "AWS_ACCESS_KEY_ID=<old id> AWS_SECRET_ACCESS_KEY=<old secret> aws sts get-caller-identity   # must fail with InvalidClientTokenId"
  },
  {
    id: "stripe",
    name: "Stripe",
    priority: "high",
    names: [/STRIPE/],
    values: [/^(sk|rk)_(live|test)_[A-Za-z0-9]{10,}$/, /^whsec_/],
    rotateUrl: "https://dashboard.stripe.com/apikeys",
    steps: [
      'Use "Roll key" on the secret or restricted key. Pick an expiry for the old key (or "now").',
      "Webhook secrets (whsec_): roll the signing secret on the webhook endpoint page.",
      'Update every place under "Stored in", then redeploy.'
    ],
    verify: async (value, fetch2) => {
      if (!/^(sk|rk)_/.test(value)) return { status: "manual", detail: "webhook secrets cannot be checked from outside; confirm the endpoint shows only the new secret" };
      return httpCheck({ url: "https://api.stripe.com/v1/balance", headers: bearer })(value, fetch2);
    }
  },
  {
    id: "razorpay",
    name: "Razorpay",
    priority: "high",
    names: [/RAZORPAY/, /^RZP_/],
    values: [/^rzp_(live|test)_/],
    rotateUrl: "https://dashboard.razorpay.com/app/website-app-settings/api-keys",
    steps: ["Regenerate the API key (key id + secret) in Account & Settings > API Keys.", "Regenerate webhook secrets too.", ...DEFAULT_STEPS.slice(1, 2)],
    manualCheck: "curl -u <old key_id>:<old secret> https://api.razorpay.com/v1/payments?count=1   # must return 401"
  },
  {
    id: "database",
    name: "Database",
    priority: "high",
    names: [/DATABASE_URL/, /POSTGRES/, /^PG(PASSWORD|_URL|_PASSWORD)/, /MYSQL/, /MONGO/, /^DB_(PASS|PASSWORD|URL|URI)/, /REDIS_(URL|PASSWORD|TOKEN)/, /^KV_/, /UPSTASH/, /NEON/, /PLANETSCALE/, /TURSO/],
    values: [/^(postgres(ql)?|mysql|mongodb(\+srv)?|rediss?):\/\//],
    steps: [
      "Change the database user password (or create a new user) in your DB provider.",
      "Update the connection string everywhere, then redeploy and restart workers.",
      "Drop the old user or old password, and kill open sessions that still use it.",
      "If the DB was reachable from the internet, review recent logins and data exports."
    ],
    manualCheck: 'psql "<old url>" -c "select 1"   # (or mysql / mongosh / redis-cli) must fail to log in'
  },
  {
    id: "app-secret",
    name: "Your app (self-generated secret)",
    priority: "high",
    names: [/NEXTAUTH_SECRET/, /^AUTH_SECRET$/, /BETTER_AUTH_SECRET/, /JWT_(SECRET|PRIVATE_KEY|SIGNING)/, /SESSION_SECRET/, /COOKIE_SECRET/, /ENCRYPTION_KEY/, /SIGNING_(KEY|SECRET)/, /^APP_KEY$/, /SECRET_KEY_BASE/, /^SECRET_KEY$/, /CRON_SECRET/, /REVALIDATE_SECRET/, /PREVIEW_SECRET/],
    steps: [
      "Generate a new value: openssl rand -base64 32",
      'Update every place under "Stored in", then redeploy. Users may be logged out and old tokens stop working.',
      "If it encrypts stored data (ENCRYPTION_KEY): re-encrypt the data with the new key before you drop the old one."
    ],
    manualCheck: "Send a request signed with the old secret (old session cookie, old cron header) and confirm it is rejected."
  },
  {
    id: "github",
    name: "GitHub",
    priority: "high",
    names: [/^(GH|GITHUB)_.*(TOKEN|PAT|KEY|SECRET)/, /^GH_TOKEN$/],
    values: [/^(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}$/, /^github_pat_/],
    rotateUrl: "https://github.com/settings/tokens",
    steps: [
      "Create a new fine-grained token with only the repos and scopes it needs.",
      'Update every place under "Stored in".',
      "Delete the old token. For a GitHub App private key, generate a new key and delete the old one on the App page.",
      "Check the audit log for the old token since the breach date."
    ],
    verify: httpCheck({ url: "https://api.github.com/user", headers: (v) => ({ authorization: `Bearer ${v}`, accept: "application/vnd.github+json" }) })
  },
  {
    id: "npm",
    name: "npm",
    priority: "high",
    names: [/^NPM_TOKEN$/, /NODE_AUTH_TOKEN/, /NPM_AUTH/],
    values: [/^npm_[A-Za-z0-9]{36}$/],
    rotateUrl: "https://www.npmjs.com/settings/~/tokens",
    steps: ["Create a new granular token (publish only, limited packages, short expiry).", "Update CI, then delete the old token.", "Check that no unexpected package versions were published since the breach date."],
    verify: httpCheck({ url: "https://registry.npmjs.org/-/whoami" })
  },
  {
    id: "vercel",
    name: "Vercel",
    priority: "high",
    names: [/^VERCEL_(TOKEN|API_TOKEN|ACCESS_TOKEN)$/],
    rotateUrl: "https://vercel.com/account/tokens",
    steps: ["Create a new token scoped to one team, with an expiry.", "Update CI, then delete the old token."],
    verify: httpCheck({ url: "https://api.vercel.com/v2/user" })
  },
  {
    id: "railway",
    name: "Railway",
    priority: "high",
    names: [/^RAILWAY_(TOKEN|API_TOKEN)$/],
    rotateUrl: "https://railway.com/account/tokens",
    steps: ["Create a new token (project token if possible).", "Update CI, then delete the old token."],
    manualCheck: "RAILWAY_TOKEN=<old token> railway whoami   # must fail"
  },
  {
    id: "cloudflare",
    name: "Cloudflare",
    priority: "high",
    names: [/CLOUDFLARE/, /^CF_(API|ACCOUNT)_?TOKEN/, /^CF_API_KEY$/],
    rotateUrl: "https://dash.cloudflare.com/profile/api-tokens",
    steps: ['Use "Roll" on the API token, or create a new one with the same permissions.', 'Update every place under "Stored in", then delete the old token.'],
    verify: httpCheck({ url: "https://api.cloudflare.com/client/v4/user/tokens/verify" })
  },
  {
    id: "supabase",
    name: "Supabase",
    priority: "high",
    names: [/SUPABASE/],
    values: [/^sb_secret_/],
    rotateUrl: "https://supabase.com/dashboard/project/_/settings/api-keys",
    steps: [
      "Create a new secret key (or roll the JWT secret for legacy service_role keys).",
      'Update every place under "Stored in", then redeploy.',
      "Delete the old secret key. Rolling the legacy JWT secret also changes the anon key."
    ],
    manualCheck: 'curl -H "apikey: <old key>" -H "Authorization: Bearer <old key>" https://<project>.supabase.co/rest/v1/   # must return 401'
  },
  {
    id: "clerk",
    name: "Clerk",
    priority: "high",
    names: [/CLERK/],
    rotateUrl: "https://dashboard.clerk.com/last-active?path=api-keys",
    steps: DEFAULT_STEPS,
    verify: httpCheck({ url: "https://api.clerk.com/v1/users?limit=1" })
  },
  {
    id: "anthropic",
    name: "Anthropic",
    priority: "high",
    names: [/ANTHROPIC/, /CLAUDE_API_KEY/],
    values: [/^sk-ant-/],
    rotateUrl: "https://console.anthropic.com/settings/keys",
    steps: [...DEFAULT_STEPS, "Check usage in the Console for spikes since the breach date. Set a spend limit."],
    verify: httpCheck({ url: "https://api.anthropic.com/v1/models", headers: (v) => ({ "x-api-key": v, "anthropic-version": "2023-06-01" }) })
  },
  {
    id: "openrouter",
    name: "OpenRouter",
    priority: "high",
    names: [/OPENROUTER/],
    values: [/^sk-or-/],
    rotateUrl: "https://openrouter.ai/settings/keys",
    steps: [...DEFAULT_STEPS, "Set a credit limit on the new key."],
    manualCheck: "Delete the old key in OpenRouter settings and confirm it no longer shows in the key list."
  },
  {
    id: "openai",
    name: "OpenAI",
    priority: "high",
    names: [/OPENAI/],
    values: [/^sk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}$/],
    rotateUrl: "https://platform.openai.com/api-keys",
    steps: [...DEFAULT_STEPS, "Check usage for spikes since the breach date. Set a project budget."],
    verify: httpCheck({ url: "https://api.openai.com/v1/models" })
  },
  {
    id: "google",
    name: "Google Cloud / Gemini",
    priority: "medium",
    names: [/GEMINI/, /GOOGLE_(API_KEY|GENERATIVE|AI)/, /^GOOGLE_APPLICATION_CREDENTIALS/, /GCP_/, /GOOGLE_(CLIENT_SECRET|SERVICE_ACCOUNT|PRIVATE_KEY)/, /FIREBASE_(PRIVATE_KEY|SERVICE_ACCOUNT|ADMIN)/],
    values: [/^AIza[0-9A-Za-z_-]{35}$/],
    rotateUrl: "https://console.cloud.google.com/apis/credentials",
    steps: [
      'API key: "Regenerate key", or create a new key with API and app restrictions.',
      "Service account: create a new JSON key, then delete the old key id.",
      "OAuth client secret: add a new secret, deploy, then disable the old one.",
      'Update every place under "Stored in", then redeploy.'
    ],
    verify: async (value, fetch2) => {
      if (!/^AIza/.test(value)) return { status: "manual", detail: "only API keys (AIza...) can be checked automatically" };
      return httpCheck({
        url: (v) => `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(v)}`,
        headers: () => ({}),
        parse: (status, body) => {
          if (status === 400 && /API_KEY_INVALID|API key not valid/i.test(body)) return { status: "dead", detail: "Google says the key is not valid" };
          if (status === 200) return { status: "live", detail: "Google accepted the key" };
          return { status: "unknown", detail: `Google answered ${status}; check the key list in the Cloud Console` };
        }
      })(value, fetch2);
    }
  },
  {
    id: "groq",
    name: "Groq",
    priority: "medium",
    names: [/GROQ/],
    values: [/^gsk_/],
    rotateUrl: "https://console.groq.com/keys",
    steps: DEFAULT_STEPS,
    verify: httpCheck({ url: "https://api.groq.com/openai/v1/models" })
  },
  {
    id: "mistral",
    name: "Mistral",
    priority: "medium",
    names: [/MISTRAL/],
    rotateUrl: "https://console.mistral.ai/api-keys",
    steps: DEFAULT_STEPS,
    verify: httpCheck({ url: "https://api.mistral.ai/v1/models" })
  },
  {
    id: "huggingface",
    name: "Hugging Face",
    priority: "medium",
    names: [/^HF_/, /HUGGING_?FACE/],
    values: [/^hf_[A-Za-z0-9]{30,}$/],
    rotateUrl: "https://huggingface.co/settings/tokens",
    steps: DEFAULT_STEPS,
    verify: httpCheck({ url: "https://huggingface.co/api/whoami-v2" })
  },
  {
    id: "replicate",
    name: "Replicate",
    priority: "medium",
    names: [/REPLICATE/],
    values: [/^r8_/],
    rotateUrl: "https://replicate.com/account/api-tokens",
    steps: DEFAULT_STEPS,
    verify: httpCheck({ url: "https://api.replicate.com/v1/account" })
  },
  {
    id: "pinecone",
    name: "Pinecone",
    priority: "medium",
    names: [/PINECONE/],
    values: [/^pcsk_/],
    rotateUrl: "https://app.pinecone.io/",
    steps: DEFAULT_STEPS,
    verify: httpCheck({ url: "https://api.pinecone.io/indexes", headers: (v) => ({ "api-key": v, "x-pinecone-api-version": "2025-04" }) })
  },
  {
    id: "slack",
    name: "Slack",
    priority: "medium",
    names: [/SLACK/],
    values: [/^xox[abposr]-/, /^https:\/\/hooks\.slack\.com\//],
    rotateUrl: "https://api.slack.com/apps",
    steps: ['Bot/user token: on the app page use "Revoke tokens", then reinstall the app.', 'Signing secret: "Regenerate" on Basic Information.', "Webhook URL: remove the old incoming webhook and add a new one.", 'Update every place under "Stored in".'],
    verify: async (value, fetch2) => {
      if (!/^xox/.test(value)) return { status: "manual", detail: "only tokens (xox...) can be checked automatically" };
      return httpCheck({
        url: "https://slack.com/api/auth.test",
        method: "POST",
        headers: bearer,
        parse: (status, body) => {
          if (status !== 200) return void 0;
          try {
            const json = JSON.parse(body);
            if (json.ok) return { status: "live", detail: "Slack accepted the token" };
            if (json.error && /invalid_auth|token_revoked|account_inactive|not_authed|token_expired/.test(json.error)) return { status: "dead", detail: `Slack said ${json.error}` };
            return { status: "unknown", detail: `Slack said ${json.error ?? "unknown error"}` };
          } catch {
            return { status: "unknown", detail: "Slack sent an unreadable answer" };
          }
        }
      })(value, fetch2);
    }
  },
  {
    id: "sendgrid",
    name: "SendGrid",
    priority: "medium",
    names: [/SENDGRID/],
    values: [/^SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$/],
    rotateUrl: "https://app.sendgrid.com/settings/api_keys",
    steps: DEFAULT_STEPS,
    verify: httpCheck({ url: "https://api.sendgrid.com/v3/scopes" })
  },
  {
    id: "resend",
    name: "Resend",
    priority: "medium",
    names: [/RESEND/],
    values: [/^re_[A-Za-z0-9_]{20,}$/],
    rotateUrl: "https://resend.com/api-keys",
    steps: DEFAULT_STEPS,
    manualCheck: "Delete the old key in the Resend dashboard and confirm it is gone from the list."
  },
  {
    id: "twilio",
    name: "Twilio",
    priority: "medium",
    names: [/TWILIO/],
    rotateUrl: "https://console.twilio.com/us1/account/keys-credentials/api-keys",
    steps: ["Create a new API key (or promote a secondary auth token).", 'Update every place under "Stored in".', "Delete the old API key, or request a new secondary auth token and promote it."],
    manualCheck: "curl -u <old sid>:<old secret> https://api.twilio.com/2010-04-01/Accounts.json   # must return 401"
  },
  {
    id: "sentry",
    name: "Sentry",
    priority: "medium",
    names: [/SENTRY/],
    values: [/^sntry[su]_/],
    rotateUrl: "https://sentry.io/settings/account/api/auth-tokens/",
    steps: ["Auth token: create a new one, update CI, revoke the old one.", "DSN: low risk (it is public in the browser); create a new client key only if you see spam events."],
    manualCheck: 'curl -H "Authorization: Bearer <old token>" https://sentry.io/api/0/   # must return 401'
  }
];
var UNKNOWN_ISSUER = {
  id: "unknown",
  name: "Unknown issuer",
  priority: "medium",
  names: [],
  steps: ["Find which service issued this value (search your code for the name).", ...DEFAULT_STEPS],
  manualCheck: "Call the service with the old value and confirm it is rejected."
};

// src/classify.ts
var PUBLIC_PREFIX = /^(NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_)/;
var SECRET_WORDS = /(KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PWD|AUTH|CREDENTIAL|PRIVATE|DSN|WEBHOOK|SALT|SIGNING|CERT|_URL$|_URI$|CONNECTION)/;
var HARD_SECRET_VALUE = /^(sk_live_|rk_live_|sk-ant-|sk-proj-|sk-svcacct-|AKIA|ghp_|github_pat_|npm_|xox[bp]-|sb_secret_|-----BEGIN)/;
var PRIORITY_ORDER = { high: 0, medium: 1, low: 2 };
function matchIssuer(name, value) {
  const upper = name.toUpperCase().replace(PUBLIC_PREFIX, "");
  const byName = ISSUERS.find((i) => i.names.some((re) => re.test(upper)));
  if (byName) return { issuer: byName, matchedBy: "name" };
  if (value) {
    const byValue = ISSUERS.find((i) => i.values?.some((re) => re.test(value)));
    if (byValue) return { issuer: byValue, matchedBy: "value" };
  }
  return { issuer: UNKNOWN_ISSUER, matchedBy: "none" };
}
function classify(sightings) {
  const byName = /* @__PURE__ */ new Map();
  for (const s of sightings) {
    const list = byName.get(s.name) ?? [];
    if (!list.some((x) => x.location === s.location)) list.push(s);
    byName.set(s.name, list);
  }
  const secrets = [];
  for (const [name, list] of byName) {
    const value = list.find((s) => s.value)?.value;
    const { issuer, matchedBy } = matchIssuer(name, value);
    const isPublic = PUBLIC_PREFIX.test(name);
    const config = matchedBy === "none" && !SECRET_WORDS.test(name.toUpperCase()) && !(value && HARD_SECRET_VALUE.test(value));
    const warnings = [];
    let priority = issuer.priority;
    if (isPublic) {
      if (value && HARD_SECRET_VALUE.test(value)) {
        warnings.push("This is a secret key in a public (browser) variable. Anyone who opened your site has it. Rotate it and move it to a server-only variable.");
        priority = "high";
      } else {
        warnings.push("Public variable: it already ships to the browser. Rotate only if it is meant to be secret.");
        priority = "low";
      }
    }
    if (config) priority = "low";
    if (matchedBy === "value") warnings.push(`Issuer guessed from the value's format (${issuer.name}). Confirm before rotating.`);
    const values = new Set(list.map((s) => s.value).filter(Boolean));
    if (values.size > 1) warnings.push(`Different values in different places (${values.size}). Some copies may already be stale; rotate all of them.`);
    secrets.push({ name, issuer, matchedBy, priority, config, public: isPublic, sightings: list, warnings });
  }
  return secrets.sort((a, b) => PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority] || a.name.localeCompare(b.name));
}

// src/report.ts
var ICON = { high: "\u{1F534}", medium: "\u{1F7E1}", low: "\u26AA" };
var TITLE = { high: "High: rotate first", medium: "Medium", low: "Low" };
function filterBreached(secrets, platform) {
  if (!platform) return secrets;
  return secrets.filter((s) => s.sightings.some((x) => x.platform === platform));
}
function inventoryText(secrets) {
  if (!secrets.length) return "No env vars found. Try --env-file, --vercel, --github, --railway or --names-file.";
  const rows = secrets.map((s) => [
    `${ICON[s.priority]} ${s.priority}`,
    s.name,
    s.config ? "config (probably not secret)" : s.issuer.name + (s.matchedBy === "value" ? " (by value)" : ""),
    s.sightings.map((x) => x.location).join(", ")
  ]);
  const head = ["Priority", "Name", "Issuer", "Stored in"];
  const width = head.map((h, i) => Math.max(h.length, ...rows.map((r) => r[i].length)));
  const line = (r) => r.map((c, i) => i === r.length - 1 ? c : c.padEnd(width[i])).join("  ");
  const secretsCount = secrets.filter((s) => !s.config).length;
  return [line(head), ...rows.map(line), "", `${secretsCount} secrets, ${secrets.length - secretsCount} config vars.`].join("\n");
}
var looksLikeCommand = (text) => /^([a-z]|[A-Z_]+=)/.test(text);
function planMarkdown(secrets, opts = {}) {
  const date = opts.date ?? (/* @__PURE__ */ new Date()).toISOString().slice(0, 10);
  const real = secrets.filter((s) => !s.config);
  const config = secrets.filter((s) => s.config);
  const places = new Set(secrets.flatMap((s) => s.sightings.map((x) => x.location)));
  const out = ["# Secret rotation plan", ""];
  out.push(`Generated by [KeyRotate](https://github.com/rahulcs754/KeyRotate) on ${date}. ${real.length} secrets found in ${places.size} places.`);
  if (opts.breached) out.push("", `**Breached platform: ${opts.breached}.** Only secrets stored there are listed. Rotate everything below, even values you think are unused.`);
  out.push(
    "",
    "For each secret, in order:",
    "",
    "1. Create the new key at the issuer.",
    '2. Update it in **every** place under "Stored in", then redeploy.',
    "3. Revoke the old key at the issuer.",
    "4. Run `keyrotate verify --old <backup of old .env>` to prove the old key is dead."
  );
  for (const p of ["high", "medium", "low"]) {
    const group = real.filter((s) => s.priority === p);
    if (!group.length) continue;
    out.push("", `## ${ICON[p]} ${TITLE[p]} (${group.length})`, "");
    for (const s of group) {
      out.push(`- [ ] **\`${s.name}\`** (${s.issuer.name})`);
      out.push(`  - Stored in: ${s.sightings.map((x) => `\`${x.location}\``).join(", ")}`);
      if (s.issuer.rotateUrl) out.push(`  - Rotate at: ${s.issuer.rotateUrl}`);
      for (const step of s.issuer.steps) out.push(`  - ${step}`);
      if (s.issuer.verify) out.push("  - Verify: automatic with `keyrotate verify`");
      else if (s.issuer.manualCheck) out.push(`  - Verify by hand: ${looksLikeCommand(s.issuer.manualCheck) ? `\`${s.issuer.manualCheck}\`` : s.issuer.manualCheck}`);
      for (const w of s.warnings) out.push(`  - \u26A0\uFE0F ${w}`);
    }
  }
  if (config.length) {
    out.push("", `## Probably not secrets (${config.length})`, "", "These names look like plain config. Check them once; rotate any that hold a credential.", "");
    out.push(config.map((s) => `\`${s.name}\``).join(", "));
  }
  out.push("");
  return out.join("\n");
}
var STATUS_TEXT = {
  dead: "\u2705 dead",
  live: "\u274C LIVE",
  unknown: "\u2754 unknown",
  manual: "\u270B check by hand",
  "no-value": "\xB7 no value",
  placeholder: "\xB7 placeholder"
};
function newKeyText(r) {
  if (!r.next) return "";
  if (r.next.detail.startsWith("NOT ROTATED")) return "\u274C same as old";
  if (r.next.status === "live") return "\u2705 works";
  if (r.next.status === "dead") return "\u274C fails";
  return STATUS_TEXT[r.next.status];
}
function verifyText(rows) {
  if (!rows.length) return "No values to check. Pass the old values with --old <file> (for example a backup of your old .env).";
  const hasNew = rows.some((r) => r.next);
  const head = ["Name", "Issuer", "Key", "Old key", ...hasNew ? ["New key"] : [], "Detail"];
  const table = rows.map((r) => [
    r.name,
    r.issuer.name,
    r.masked,
    STATUS_TEXT[r.old.status],
    ...hasNew ? [newKeyText(r)] : [],
    r.next?.detail.startsWith("NOT ROTATED") ? r.next.detail : r.next && r.next.status !== "live" ? `new key: ${r.next.detail}` : r.old.detail
  ]);
  const width = head.map((h, i) => Math.max(h.length, ...table.map((r) => r[i].length)));
  const line = (r) => r.map((c, i) => i === r.length - 1 ? c : c.padEnd(width[i])).join("  ");
  const live = rows.filter((r) => r.old.status === "live").length;
  const dead = rows.filter((r) => r.old.status === "dead").length;
  const summary = live ? `${live} old key(s) still work. Revoke them at the issuer now.` : `${dead} old key(s) confirmed dead. ${rows.length - dead} need a manual check or had no value.`;
  return [line(head), ...table.map(line), "", summary].join("\n");
}

// src/sources/envfile.ts
import { readFileSync, readdirSync, statSync } from "fs";
import { basename, join, relative } from "path";
function parseEnv(text) {
  const out = [];
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    const name = m[1];
    let raw = m[2];
    const quote = raw[0];
    let value;
    if (quote === '"' || quote === "'" || quote === "`") {
      let body = raw.slice(1);
      while (!body.includes(quote) && i + 1 < lines.length) body += "\n" + lines[++i];
      const end = body.indexOf(quote);
      value = end === -1 ? body : body.slice(0, end);
      if (quote === '"') value = value.replace(/\\n/g, "\n");
    } else {
      raw = raw.replace(/\s+#.*$/, "");
      value = raw.trim();
    }
    out.push({ name, value });
  }
  return out;
}
var ENV_FILE = /^\.env(\..+)?$/;
var SKIP_DIRS = /* @__PURE__ */ new Set(["node_modules", ".git", ".next", "dist", "build", "out", ".vercel", ".turbo", "coverage"]);
function findEnvFiles(root, depth = 3) {
  const found = [];
  const walk = (dir, level) => {
    let entries;
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (level < depth && !SKIP_DIRS.has(entry)) walk(full, level + 1);
      } else if (ENV_FILE.test(entry)) {
        found.push(full);
      }
    }
  };
  walk(root, 0);
  return found.sort();
}
function isTemplateFile(path) {
  return /\.(example|sample|template|dist)$/.test(basename(path));
}
function scanEnvFile(path, root = process.cwd()) {
  const template = isTemplateFile(path);
  const location = (relative(root, path) || basename(path)) + (template ? " (template)" : "");
  return parseEnv(readFileSync(path, "utf8")).map(({ name, value }) => ({
    name,
    platform: "env",
    location,
    ...template || !value ? {} : { value }
  }));
}

// src/sources/remote.ts
import { readFileSync as readFileSync2 } from "fs";
import { basename as basename2 } from "path";
async function getJson(fetch2, url, token, extra = {}) {
  const res = await fetch2(url, { headers: { authorization: `Bearer ${token}`, "user-agent": "keyrotate", ...extra } });
  if (!res.ok) throw new Error(`${new URL(url).host} answered ${res.status} for ${new URL(url).pathname}`);
  return await res.json();
}
async function scanVercel(project, token, fetch2, teamId) {
  const q = new URLSearchParams({ decrypt: "false" });
  if (teamId) q.set("teamId", teamId);
  const data = await getJson(fetch2, `https://api.vercel.com/v9/projects/${encodeURIComponent(project)}/env?${q}`, token);
  const merged = /* @__PURE__ */ new Map();
  for (const env of data.envs ?? []) {
    if (env.type === "system") continue;
    const targets = merged.get(env.key) ?? /* @__PURE__ */ new Set();
    for (const t of Array.isArray(env.target) ? env.target : env.target ? [env.target] : []) targets.add(t);
    merged.set(env.key, targets);
  }
  return [...merged].map(([name, targets]) => ({
    name,
    platform: "vercel",
    location: `vercel:${project}${targets.size ? ` (${[...targets].sort().join(", ")})` : ""}`
  }));
}
async function scanGitHubSecrets(repo, token, fetch2) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new Error(`--github expects owner/repo, got "${repo}"`);
  const api = `https://api.github.com/repos/${repo}`;
  const gh = { accept: "application/vnd.github+json" };
  const out = [];
  const repoSecrets = await getJson(fetch2, `${api}/actions/secrets?per_page=100`, token, gh);
  for (const s of repoSecrets.secrets) out.push({ name: s.name, platform: "github", location: `github-secrets:${repo}` });
  const envs = await getJson(fetch2, `${api}/environments?per_page=100`, token, gh).catch(() => ({ environments: [] }));
  for (const env of envs.environments ?? []) {
    const secrets = await getJson(fetch2, `${api}/environments/${encodeURIComponent(env.name)}/secrets?per_page=100`, token, gh);
    for (const s of secrets.secrets) out.push({ name: s.name, platform: "github", location: `github-secrets:${repo} (${env.name})` });
  }
  return out;
}
var RAILWAY_SYSTEM = /^RAILWAY_(?!TOKEN$|API_TOKEN$)/;
function scanRailwayExport(path) {
  const data = JSON.parse(readFileSync2(path, "utf8"));
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error(`${path}: expected the JSON object from "railway variables --json"`);
  return Object.entries(data).filter(([name]) => !RAILWAY_SYSTEM.test(name)).map(([name, value]) => ({
    name,
    platform: "railway",
    location: `railway:${basename2(path, ".json")}`,
    ...typeof value === "string" && value ? { value } : {}
  }));
}
function scanNamesFile(path, label) {
  const names = /* @__PURE__ */ new Set();
  for (const line of readFileSync2(path, "utf8").split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)/.exec(line);
    if (m && !line.trim().startsWith("#")) names.add(m[1]);
  }
  return [...names].map((name) => ({ name, platform: "list", location: label ?? basename2(path) }));
}

// src/sources/workflows.ts
import { existsSync, readFileSync as readFileSync3, readdirSync as readdirSync2 } from "fs";
import { join as join2 } from "path";
var BUILT_IN = /* @__PURE__ */ new Set(["GITHUB_TOKEN"]);
function secretRefs(yaml) {
  const names = /* @__PURE__ */ new Set();
  const re = /secrets\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_]*)|\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\])/g;
  for (const m of yaml.matchAll(re)) {
    const name = m[1] ?? m[2];
    if (name && !BUILT_IN.has(name)) names.add(name);
  }
  return [...names].sort();
}
function scanWorkflows(root) {
  const dir = join2(root, ".github", "workflows");
  if (!existsSync(dir)) return [];
  const out = [];
  for (const file of readdirSync2(dir).sort()) {
    if (!/\.ya?ml$/.test(file)) continue;
    for (const name of secretRefs(readFileSync3(join2(dir, file), "utf8"))) {
      out.push({ name, platform: "github", location: `github-actions:${file}` });
    }
  }
  return out;
}

// src/verify.ts
var PLACEHOLDER = /^(|x+|changeme|change_me|todo|your[-_].*|<.*>|\.\.\.|null|undefined|test|example|placeholder|\*+)$/i;
function mask(value) {
  if (value.length <= 10) return "*".repeat(Math.min(value.length, 6));
  return `${value.slice(0, 4)}\u2026${value.slice(-2)} (${value.length} chars)`;
}
async function check(issuer, value, fetch2) {
  if (value === void 0) return { status: "no-value", detail: "no value given" };
  if (PLACEHOLDER.test(value.trim())) return { status: "placeholder", detail: "value looks like a placeholder" };
  if (!issuer.verify) return { status: "manual", detail: issuer.manualCheck ?? "no automatic check for this issuer" };
  return issuer.verify(value, fetch2);
}
async function verifyKeys(oldValues, newValues, fetch2, onlyNames, concurrency = 4) {
  const names = [...oldValues.keys()].filter((n) => !onlyNames || onlyNames.has(n)).sort();
  const rows = new Array(names.length);
  let next = 0;
  const worker = async () => {
    while (next < names.length) {
      const i = next++;
      const name = names[i];
      const oldValue = oldValues.get(name);
      const { issuer } = matchIssuer(name, oldValue);
      const row = { name, issuer, masked: mask(oldValue), old: await check(issuer, oldValue, fetch2) };
      if (newValues.has(name)) {
        const newValue = newValues.get(name);
        row.next = newValue === oldValue ? { status: "live", detail: "NOT ROTATED: new value is the same as the old one" } : await check(issuer, newValue, fetch2);
      }
      rows[i] = row;
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, names.length) }, worker));
  return rows;
}
function hasLiveOldKey(rows) {
  return rows.some((r) => r.old.status === "live" || r.next?.detail.startsWith("NOT ROTATED"));
}

// src/cli.ts
var VERSION = "0.1.0";
var PLATFORMS = ["env", "github", "vercel", "railway", "list"];
var HELP = `keyrotate ${VERSION}
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
  --breached <platform>    Only secrets stored on: ${PLATFORMS.join(", ")}
  --json                   JSON output
  --out <file>             plan: write Markdown to a file
  -h, --help               Show help
  -v, --version            Show version

Secret values are only read from local files, never printed, and only sent
to the issuer's own API during "verify".`;
function fail(msg) {
  console.error(`keyrotate: ${msg}`);
  process.exit(2);
}
async function collect(v) {
  const root = resolve(v.dir ?? ".");
  const out = [];
  if (!v["no-local"]) {
    for (const f of findEnvFiles(root)) out.push(...scanEnvFile(f, root));
    out.push(...scanWorkflows(root));
  }
  for (const f of v["env-file"] ?? []) {
    if (!existsSync2(f)) fail(`env file not found: ${f}`);
    out.push(...scanEnvFile(resolve(f), root));
  }
  for (const project of v.vercel ?? []) {
    const token = process.env.VERCEL_TOKEN;
    if (!token) fail("--vercel needs VERCEL_TOKEN (create one at https://vercel.com/account/tokens)");
    out.push(...await scanVercel(project, token, fetch, v["vercel-team"]));
  }
  for (const repo of v.github ?? []) {
    const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
    if (!token) fail('--github needs GITHUB_TOKEN with "Secrets: read" (or run: GITHUB_TOKEN=$(gh auth token) keyrotate ...)');
    out.push(...await scanGitHubSecrets(repo, token, fetch));
  }
  for (const f of v.railway ?? []) out.push(...scanRailwayExport(f));
  for (const f of v["names-file"] ?? []) out.push(...scanNamesFile(f));
  return out;
}
function loadValues(files) {
  const map = /* @__PURE__ */ new Map();
  for (const f of files) {
    if (!existsSync2(f)) fail(`file not found: ${f}`);
    const text = readFileSync4(f, "utf8");
    if (f.endsWith(".json")) {
      for (const [k, val] of Object.entries(JSON.parse(text))) if (typeof val === "string" && val) map.set(k, val);
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
      dir: { type: "string" },
      "env-file": { type: "string", multiple: true },
      "no-local": { type: "boolean" },
      vercel: { type: "string", multiple: true },
      "vercel-team": { type: "string" },
      github: { type: "string", multiple: true },
      railway: { type: "string", multiple: true },
      "names-file": { type: "string", multiple: true },
      breached: { type: "string" },
      json: { type: "boolean" },
      out: { type: "string" },
      old: { type: "string", multiple: true },
      new: { type: "string", multiple: true },
      only: { type: "string", multiple: true },
      help: { type: "boolean", short: "h" },
      version: { type: "boolean", short: "v" }
    }
  });
  if (v.version) return console.log(VERSION);
  const cmd = positionals[0];
  if (v.help || !cmd) return console.log(HELP);
  const breached = v.breached;
  if (breached && !PLATFORMS.includes(breached)) fail(`--breached must be one of: ${PLATFORMS.join(", ")}`);
  if (cmd === "scan" || cmd === "plan") {
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
        warnings: s.warnings
      }));
      return console.log(JSON.stringify(json, null, 2));
    }
    if (cmd === "scan") return console.log(inventoryText(secrets));
    const md = planMarkdown(secrets, { breached });
    if (v.out) {
      writeFileSync(v.out, md);
      return console.log(`Wrote ${v.out} (${secrets.filter((s) => !s.config).length} secrets).`);
    }
    return console.log(md);
  }
  if (cmd === "verify") {
    if (!v.old?.length) fail("verify needs --old <file> with the OLD values (for example a backup of your .env before rotating)");
    const rows = await verifyKeys(loadValues(v.old), loadValues(v.new ?? []), fetch, v.only?.length ? new Set(v.only) : void 0);
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
main().catch((err) => fail(err.message));
