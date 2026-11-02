# Research notes

Why this tool, in short (from the Nov 2026 market research round).

## The problem

- Hosting and AI dev platforms keep getting breached. Vercel reported an incident in April 2026, and in October 2026 ("Black October") Railway and about eight other AI dev platforms were hit. The attackers went after environment variables and AI API keys.
- After a breach, the platform's advice is always the same: "rotate your secrets". But a real app has 20 to 80 env vars across Vercel, GitHub Actions, Railway and local `.env` files, and each one is rotated in a different issuer dashboard.
- Teams also need to prove the old key is dead. A rotated key that was never revoked is still a live key in the attacker's hands. Reported cases: stolen AI keys tested within 30 minutes, one key used for 1.7M calls in 13 hours.

## Existing options

- GitGuardian, TruffleHog, gitleaks: find leaked secrets in code and history. They do not plan the rotation after a platform breach.
- Prowler and cloud security tools: cloud misconfig, not app env vars.
- Each platform's own breach checklist: generic, one platform at a time, no verification.

## Gap

One free, local CLI that answers "a platform I use was breached, what do I rotate, where, in what order, and is the old key really dead?"

## Users

Small teams and solo devs shipping Next.js / Node apps on Vercel, Railway and GitHub Actions, with AI, payment and database keys.

## Sources

- Helix, "AI platform breaches of October 2026": https://helix.ml/blog/black-october-ai-platform-breaches
- BleepingComputer, Railway asks devs to rotate secrets: https://www.bleepingcomputer.com/news/security/railway-warns-devs-to-rotate-secrets-after-potential-breach/
- dev.to, Vercel April 2026 breach checklist: https://dev.to/ianqqu/about-vercels-april-2026-breach-your-checklist-4cji
- GitGuardian on the Vercel incident: https://blog.gitguardian.com/vercel-april-2026-incident-non-sensitive-environment-variables-need-investigation-too
