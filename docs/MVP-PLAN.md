# MVP plan

## Goal

A local CLI that, after a platform breach, finds every secret you store there, tells you who issued it, gives you a rotation checklist in priority order, and checks that each old key is really dead.

## How it works

1. **Scan** (names only by default, values never leave your machine):
   - local `.env*` files,
   - GitHub Actions workflows (`${{ secrets.NAME }}` references),
   - Vercel project env vars (API, needs `VERCEL_TOKEN`),
   - GitHub repo and environment secret names (API, needs `GITHUB_TOKEN`),
   - Railway variables exported with `railway variables --json`,
   - any plain list of names (`--names-file`).
2. **Map** each name (and value prefix, when a value is known) to an issuer: OpenAI, Anthropic, AWS, Stripe, GitHub, Slack, Google, database URLs, auth secrets, and more. Each issuer has a priority, a rotate link and short steps.
3. **Plan**: a Markdown checklist, high priority first (cloud, payments, AI, database), with where each secret is stored so you update every copy.
4. **Verify**: give it the old values (for example a backup `.env.old`). For issuers with a safe read-only auth endpoint it calls that endpoint and reports `dead` (401/403), `LIVE` (200) or `unknown`. Values are masked in all output.

## Not in MVP

- Rotating keys automatically through issuer APIs.
- Decoy (canary) keys that alert when used.
- A web dashboard.
- AWS SigV4 verify (shows the `aws sts get-caller-identity` command instead).

## Done when

- `keyrotate scan`, `plan` and `verify` work on a sample project.
- Unit tests for scanners, issuer mapping, plan output and verify (mocked HTTP).
- README how-to and a GitHub Pages site.
