# KeyRotate

**A platform you use got breached. KeyRotate tells you which secrets to rotate, where, in what order, and checks the old keys are really dead.**

Status: planning. The MVP is being built in a pull request. See [docs/MVP-PLAN.md](docs/MVP-PLAN.md) and [docs/RESEARCH.md](docs/RESEARCH.md).

## Planned

- `keyrotate scan`: list env var names from `.env` files, GitHub Actions, Vercel, Railway.
- `keyrotate plan`: map each one to its issuer (OpenAI, Anthropic, AWS, Stripe, ...) and write a rotation checklist with direct links.
- `keyrotate verify`: call each issuer's read-only auth check with the old key and confirm it now fails.

Runs locally. No server, and secret values never leave your machine except to the issuer's own API during `verify`.

## License

MIT
