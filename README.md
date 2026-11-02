# KeyRotate

**A platform you use got breached. KeyRotate tells you which secrets to rotate, where each copy lives, in what order, and then proves the old keys are dead.**

Hosting and AI dev platforms keep getting breached (Vercel in April 2026, Railway and about eight others in October 2026), and the advice is always "rotate your secrets". A real app has dozens of env vars spread across Vercel, GitHub Actions, Railway and `.env` files. KeyRotate turns that into one checklist:

1. **`scan`**: finds every env var name and where it is stored.
2. **`plan`**: maps each one to its issuer (OpenAI, Anthropic, AWS, Stripe, GitHub, database, ...), sorts high priority first, and writes a Markdown checklist with the rotate link and steps for each.
3. **`verify`**: calls each issuer's read-only auth check with the **old** key and confirms it now fails. Exit code 1 if any old key still works.

Runs locally. No server, no account. Remote sources are read as **names only**. Secret values are only read from local files, are never printed (masked as `sk-p…AA`), and are only sent to the issuer's own API during `verify`.

Site: https://rahulcs754.github.io/KeyRotate/

## Quick start

Needs Node 20+.

```bash
# in your app folder: reads .env* files and .github/workflows
npx github:rahulcs754/KeyRotate scan
```

```
Priority   Name                Issuer                            Stored in
🔴 high    DATABASE_URL        Database                          .env.local, railway:prod
🔴 high    NEXTAUTH_SECRET     Your app (self-generated secret)  .env.local
🔴 high    OPENAI_API_KEY      OpenAI                            .env.local, github-actions:deploy.yml, vercel:shop (production)
🔴 high    STRIPE_SECRET_KEY   Stripe                            .env.local, vercel:shop (production)
🟡 medium  RESEND_API_KEY      Resend                            .env.example (template)
⚪ low      NODE_ENV            config (probably not secret)      .env.local
```

Write the checklist (only what was stored on the breached platform):

```bash
VERCEL_TOKEN=... npx github:rahulcs754/KeyRotate plan --vercel shop --breached vercel --out ROTATION.md
```

Each entry looks like this:

```markdown
- [ ] **`STRIPE_SECRET_KEY`** (Stripe)
  - Stored in: `.env.local`, `vercel:shop (production)`
  - Rotate at: https://dashboard.stripe.com/apikeys
  - Use "Roll key" on the secret or restricted key. Pick an expiry for the old key (or "now").
  - Update every place under "Stored in", then redeploy.
  - Verify: automatic with `keyrotate verify`
```

After rotating, prove the old keys are dead. Keep a backup of the old `.env` (never commit it):

```bash
cp .env.local /tmp/old.env      # before you rotate
# ...rotate keys, update .env.local...
npx github:rahulcs754/KeyRotate verify --old /tmp/old.env --new .env.local
```

```
Name               Issuer     Key                  Old key          New key  Detail
ANTHROPIC_API_KEY  Anthropic  sk-a…Qw (95 chars)   ✅ dead           ✅ works  api.anthropic.com answered 401
DATABASE_URL       Database   post…db (41 chars)   ✋ check by hand           psql "<old url>" -c "select 1" ...
OPENAI_API_KEY     OpenAI     sk-p…9x (160 chars)  ❌ LIVE           ✅ works  api.openai.com accepted the key (200)

1 old key(s) still work. Revoke them at the issuer now.
```

`verify` also catches "not rotated": a name whose new value is the same as the old one.

## Sources

| Flag | Reads | Needs |
| --- | --- | --- |
| (default) | `.env*` files (3 levels deep, skips `node_modules`) and `.github/workflows/*.yml` `secrets.*` refs in `--dir` | nothing |
| `--env-file <file>` | one more env file | nothing |
| `--vercel <project>` | project env var names and targets (`--vercel-team <id>` for teams) | `VERCEL_TOKEN` |
| `--github <owner/repo>` | repo and environment secret names | `GITHUB_TOKEN` with Secrets: read (or `GITHUB_TOKEN=$(gh auth token)`) |
| `--railway <file.json>` | output of `railway variables --json > railway.json` | Railway CLI |
| `--names-file <file>` | one name per line, for any other platform (Netlify, Render, Fly, ...) | nothing |

`--no-local` skips the default local scan. `--breached env|github|vercel|railway|list` keeps only secrets stored on that platform. `--json` prints JSON for scripts.

## Issuers

Mapped by name first (`CLERK_SECRET_KEY` is Clerk even though the value looks like Stripe), then by value format for generic names like `API_KEY`.

| Auto verify (read-only endpoint) | Manual check (command shown) |
| --- | --- |
| OpenAI, Anthropic, Stripe, GitHub, npm, Vercel, Cloudflare, Clerk, Google API keys, Groq, Mistral, Hugging Face, Replicate, Pinecone, Slack, SendGrid | AWS (`aws sts get-caller-identity`), databases (Postgres, MySQL, Mongo, Redis, Upstash, Neon...), Supabase, Razorpay, Railway, Twilio, Sentry, Resend, OpenRouter, your own app secrets (`NEXTAUTH_SECRET`, `JWT_SECRET`, ...) |

Also:

- **Public vars** (`NEXT_PUBLIC_`, `VITE_`, ...) are low priority, since they already ship to the browser. But if one holds a real secret key (`sk_live_`, `sk-ant-`, ...), it is raised to high with a warning.
- **Different values in different places** gets a warning: some copies are stale.
- Names that look like plain config (`PORT`, `NODE_ENV`) are listed separately as "probably not secrets".

Missing an issuer? Add it to [src/issuers.ts](src/issuers.ts): name patterns, value patterns, rotate link, steps, and an optional `verify` check.

## How `verify` decides

| Issuer answers | Status |
| --- | --- |
| 401 / 403 (or Slack `invalid_auth`, Google `API_KEY_INVALID`) | ✅ dead |
| 2xx | ❌ LIVE (exit code 1) |
| anything else, or network error | ❔ unknown (never counted as dead) |
| no read-only check exists | ✋ check by hand, with the command |

Placeholder values (`changeme`, `xxx`, `<your-key>`) are skipped.

## Develop

```bash
npm install
npm test          # vitest, no network (HTTP is mocked)
npm run typecheck
npm run build     # dist/cli.js (committed, CI checks it is up to date)
npm run dev -- scan --dir path/to/app
```

## Roadmap

- Decoy (canary) keys that alert when someone uses them.
- Rotate through issuer APIs where possible (GitHub, Vercel, Stripe roll).
- More platforms: Netlify, Render, Fly.io, Cloudflare Workers APIs.
- Small web view of the checklist with progress.

## License

MIT
