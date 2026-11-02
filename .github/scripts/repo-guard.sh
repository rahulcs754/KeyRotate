#!/usr/bin/env bash
# Repo guard: fails if files that must never be in git are tracked,
# or if a tracked file looks like it holds a secret.
# Runs in CI (.github/workflows/repo-guard.yml) and before each push
# (enable once with: git config core.hooksPath .githooks).
#
# Allow a known-safe line: add "repo-guard: allow" on that line.
# Allow a whole path: list it in .repo-guard-allow (one path per line).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
fail=0
allow_file=.repo-guard-allow
allowed() { [[ -f $allow_file ]] && grep -qxF -- "$1" "$allow_file"; }

# 1) Files that must never be pushed.
blocked='(^|/)(CLAUDE\.md|\.claude/|\.env(\.[^/]*)?$|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$|[^/]*\.(pem|key|p12|pfx|keystore|jks)$|\.npmrc$|\.netrc$|credentials\.json$|service-account[^/]*\.json$)'
safe='(^|/)\.env\.(example|sample|template)$'
while IFS= read -r f; do
  [[ $f =~ $safe ]] && continue
  allowed "$f" && continue
  echo "::error file=$f::Blocked file is tracked in git: $f (remove it with: git rm --cached \"$f\")"
  fail=1
done < <(git ls-files | grep -iE "$blocked" || true)

# 2) Secret-looking strings in tracked text files.
patterns=(
  'ghp_[A-Za-z0-9]{36}'                  # GitHub classic token
  'github_pat_[A-Za-z0-9_]{60,}'         # GitHub fine-grained token
  'gh[ousr]_[A-Za-z0-9]{36}'             # other GitHub tokens
  'sk-ant-[A-Za-z0-9_-]{30,}'            # Anthropic
  'sk-(proj-)?[A-Za-z0-9_-]{40,}'        # OpenAI
  'AKIA[0-9A-Z]{16}'                     # AWS access key
  'AIza[0-9A-Za-z_-]{35}'                # Google API key
  'xox[abprs]-[A-Za-z0-9-]{20,}'         # Slack
  'npm_[A-Za-z0-9]{36}'                  # npm
  'sk_live_[A-Za-z0-9]{24,}'             # Stripe live
  'rzp_live_[A-Za-z0-9]{14,}'            # Razorpay live
  '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----' # private keys
)
regex=$(IFS='|'; echo "${patterns[*]}")
while IFS= read -r hit; do
  file=${hit%%:*}
  [[ $file == .github/scripts/repo-guard.sh ]] && continue
  allowed "$file" && continue
  [[ $hit == *"repo-guard: allow"* ]] && continue
  rest=${hit#*:}; line=${rest%%:*}
  echo "::error file=$file,line=$line::Possible secret in $file:$line. Remove it, rotate the key, and use an env var or GitHub secret."
  fail=1
done < <(git grep -nIE -e "$regex" -- . ':!package-lock.json' ':!pnpm-lock.yaml' ':!yarn.lock' || true)

if [[ $fail -ne 0 ]]; then
  echo "Repo guard failed. Fix the items above before pushing."
  exit 1
fi
echo "Repo guard passed: no blocked files or secrets found."
