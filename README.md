# git-guard

A zero-dependency, privacy-first security scanner for leaked GitHub Personal Access Tokens.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/0xshaikh/git-guard/actions)
[![npm version](https://img.shields.io/badge/npm-v1.0.0-blue)](https://www.npmjs.com/package/git-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## What is git-guard?

`git-guard` scans files, directories, and entire Git repositories for leaked GitHub Personal Access Tokens. It detects classic PATs, fine-grained PATs, OAuth tokens, and GitHub App tokens — then warns you when those tokens are granted more scopes than they should have.

It runs entirely offline. No API calls. No telemetry. No uploads. Your tokens stay on your machine.

## Installation

### Via npm (recommended)

```bash
npm install -g git-guard
```

### Via npx (no install)

```bash
npx git-guard scan --file .env
```

### From source

```bash
git clone https://github.com/0xshaikh/git-guard.git
cd git-guard
npm install
npm run build
npm link
```

## Quick Start

Three commands to get started:

```bash
# Scan a single file for leaked tokens
git-guard scan --file .env

# Recursively scan a directory
git-guard scan --dir ./secrets

# Audit a remote repository (clones + scans)
git-guard audit --repo https://github.com/example/repo
```

## Features

- ✅ **Zero dependencies** — runs anywhere Node.js runs
- ✅ **Offline-first** — no API calls, no network access, no telemetry
- ✅ **Detects all GitHub token types** — classic PATs, fine-grained PATs, OAuth, App tokens
- ✅ **Scope severity analysis** — warns on over-permissive scopes
- ✅ **Multiple output formats** — JSON, Markdown, SARIF (CI-friendly)
- ✅ **Privacy-first** — never uploads your tokens, ever
- ✅ **CI/CD ready** — exit codes for pipeline integration
- ✅ **Fast** — designed for pre-commit hooks and large repos

## CLI Reference

### `git-guard scan`

Scans files, directories, or a PAT string for leaked tokens.

#### Scan a file

```bash
git-guard scan --file path/to/file.env
```

Example output:

```
  Found 1 token in .env

  [!] ghp_XyZ...7890 (line 4)
      Type: Classic PAT
      Scopes: repo, admin:org
      Severity: HIGH
      Reason: admin:org grants full organization admin access
```

#### Scan a directory (recursive)

```bash
git-guard scan --dir ./secrets
```

Example output:

```
Scanning ./secrets (12 files)...

  secrets/production.env     2 tokens
  secrets/.gh_env            1 token
  secrets/deploy.sh          0 tokens

  Total: 3 tokens found
  HIGH: 2 | MEDIUM: 1 | LOW: 0
```

#### Scan a PAT string directly

```bash
git-guard scan --pat "ghp_XXXXXXXYYYYYYZZZZZZAAAAAA111111222222"
```

This analyzes the scopes granted to a single PAT without touching any files.

```bash
# Read the PAT from stdin
cat token.txt | git-guard scan --pat -

# Read from environment variable
git-guard scan --pat "$GITHUB_TOKEN"
```

### `git-guard audit`

Clones a remote repository and scans its full history for leaked tokens.

```bash
git-guard audit --repo https://github.com/example/repo
```

By default this clones the entire repository (full history). Use `--shallow` for a faster, history-less audit:

```bash
git-guard audit --repo https://github.com/example/repo --shallow
```

Example output:

```
Cloning https://github.com/example/repo...
Scanning 47 files across 1,204 commits...

  src/config/github.env     1 token (added in commit a1b2c3d)
  scripts/deploy.sh         2 tokens (added in commits a1b2c3d, e4f5g6h)
  .env.example              0 tokens (example values detected, skipped)

  Total: 3 unique tokens
  HIGH: 1 | MEDIUM: 2 | LOW: 0

  Recommended action: revoke all detected tokens immediately
```

### `git-guard report`

Generates a report from a previous scan or audit run.

#### Output as JSON

```bash
git-guard report --format json
```

```json
{
  "tool": "git-guard",
  "version": "1.0.0",
  "timestamp": "2026-10-23T13:37:00Z",
  "tokens": [
    {
      "value": "ghp_XyZ...7890",
      "type": "classic_pat",
      "scopes": ["repo", "admin:org"],
      "severity": "HIGH",
      "locations": [
        { "file": ".env", "line": 4 }
      ]
    }
  ],
  "summary": {
    "total": 1,
    "high": 1,
    "medium": 0,
    "low": 0
  }
}
```

#### Output as Markdown

```bash
git-guard report --format md
```

```markdown
## git-guard Report

**Scan time:** 2026-10-23 13:37 UTC
**Total tokens found:** 1

### HIGH severity (1)

| Token | Type | Scopes | Location |
|-------|------|--------|----------|
| `ghp_XyZ...7890` | Classic PAT | repo, admin:org | `.env:4` |

### Summary

- HIGH: 1
- MEDIUM: 0
- LOW: 0

**Recommended action:** Revoke all HIGH-severity tokens immediately.
```

#### Output as SARIF (for CI/code scanning integrations)

```bash
git-guard report --format sarif
```

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "git-guard",
          "version": "1.0.0",
          "rules": [
            { "id": "GH101", "name": "LeakedClassicPAT", "defaultConfiguration": { "level": "error" } },
            { "id": "GH102", "name": "LeakedFineGrainedPAT", "defaultConfiguration": { "level": "error" } },
            { "id": "GH103", "name": "LeakedOAuthToken", "defaultConfiguration": { "level": "error" } },
            { "id": "GH104", "name": "LeakedAppToken", "defaultConfiguration": { "level": "error" } }
          ]
        }
      },
      "results": [
        {
          "ruleId": "GH101",
          "level": "error",
          "message": { "text": "Classic PAT with over-permissive scopes (admin:org)" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": ".env" },
                "region": { "startLine": 4, "endLine": 4 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

### Common flags

```bash
# Verbose output (show all matches, not just unique tokens)
git-guard scan --dir ./src --verbose

# Quiet mode (exit code only, no console output)
git-guard scan --dir ./src --quiet

# Exit non-zero on any finding (for CI)
git-guard scan --dir ./src --strict

# Custom ignore patterns (repeatable)
git-guard scan --dir ./src --ignore 'node_modules/**' --ignore '*.test.js'
```

## Token Patterns Detected

`git-guard` recognizes the following GitHub token formats:

| Type | Pattern | Description |
|------|---------|-------------|
| Classic PAT | `ghp_[A-Za-z0-9]{36}` | Personal access tokens created via GitHub web UI |
| Fine-grained PAT | `github_pat_[A-Za-z0-9_]{50,}` | Fine-grained tokens with granular permissions |
| OAuth token | `gho_[A-Za-z0-9]{36}` | Tokens issued via GitHub OAuth flow |
| App user token | `ghu_[A-Za-z0-9]{36}` | Tokens created by a GitHub App on behalf of a user |
| App installation token | `ghs_[A-Za-z0-9]{36}` | Tokens created by a GitHub App installation |
| Refresh token | `ghr_[A-Za-z0-9]{36}` | OAuth refresh tokens |
| Server-to-server token | `ghb_[A-Za-z0-9]{36}` | Tokens created by a GitHub App |

Detection uses anchored regex matching — no substring false positives on random strings that happen to look like a token prefix.

## Scope Severity Levels

When `git-guard` detects a classic PAT, it analyzes the scopes granted to that token. Fine-grained tokens are evaluated by their permission set.

### HIGH severity — Revoke immediately

| Scope | Risk |
|-------|------|
| `admin:org` | Full organization admin — delete repos, change billing, invite users |
| `admin:repo_hook` | Add/remove webhook hooks on any repo — exfiltrate code, secrets |
| `write:packages` | Publish/delete packages — supply-chain attack vector |
| `admin:public_key` | Manage SSH/GPG keys — push arbitrary code to any repo |
| `write:check_run` | Write CI results — bypass status checks on protected branches |
| `write:public_key` | Manage SSH keys — full repo write access via SSH |

### MEDIUM severity — Review and narrow

| Scope | Risk |
|-------|------|
| `repo` | Full access to all private repos — code read/write, delete branches |
| `gist` | Create/edit/delete gists |
| `user:email` | Read all associated email addresses |
| `delete:packages` | Delete packages — destructive but not supply-chain |
| `write:discussion` | Write to repository discussions |
| `write:packages` (limited) | Scoped to org-level packages only |

### LOW severity — Generally safe

| Scope | Risk |
|-------|------|
| `read:org` | Read-only access to org membership, teams, repo metadata |
| `public_repo` | Read access to public repos only |
| `workflow` | Read workflow/run metadata (no execution) |
| `write:packages` (limited) | Write access to public packages only |

Any token carrying multiple MEDIUM scopes, or any HIGH scope combined with `repo`, is flagged as HIGH.

## Output Formats

### JSON

Machine-readable, designed for piping to other tools.

```bash
git-guard scan --dir . --format json | jq '.tokens[].value'
```

### Markdown

Human-readable, designed for pasting into issues or PRs.

```bash
git-guard scan --dir . --format md > report.md
```

### SARIF

CI-friendly, integrates with GitHub code scanning, Azure DevOps, and any SARIF-compatible tool.

```bash
git-guard audit --repo https://github.com/example/repo --format sarif > results.sarif
```

## Security Model

`git-guard` is designed for teams that care about supply-chain security and developer privacy.

### Privacy-first by design

- **No API calls.** `git-guard` never contacts `api.github.com`, `github.com`, or any other GitHub endpoint. Token analysis is purely local.
- **No telemetry.** The tool does not phone home, does not collect usage data, and does not include any analytics SDK.
- **No uploads.** Your tokens are never transmitted, stored, or written to disk outside of your own report files.
- **No third-party dependencies.** The tool is implemented in a single runtime with no transitive dependencies — there is no supply-chain surface to attack.

### Offline operation

Every scan runs entirely on the local machine. `git-guard` does not require network access to function. This means:

- It works on air-gapped CI runners.
- It does not slow down on VPN-strict networks.
- It does not leak data to a third-party scanning service.

### Local-only token analysis

When `git-guard` analyzes a PAT's scopes, it does so by parsing the token value locally. It does not call GitHub's OAuth introspection endpoint, which would both require network access and log the token on GitHub's servers.

### What this means in practice

| Concern | git-guard | Alternatives |
|---------|-----------|--------------|
| Sends tokens to an API | ❌ Never | Some scanners call GitHub introspection |
| Collects usage data | ❌ No | Some npm packages phone home |
| Third-party dependencies | ❌ None | Most tools have 50+ transitive deps |
| Works on air-gapped hosts | ✅ Yes | Most require network |
| Reads your git history | ✅ Only on `audit --repo` | — |

## FAQ

### Why not use `git-secrets`?

`git-secrets` is an excellent general-purpose secret scanner with a broad regex library. `git-guard` is intentionally narrow — it focuses specifically on GitHub Personal Access Tokens and their scope security. The tradeoff is:

- `git-guard` understands GitHub's token format and scope model deeply.
- `git-guard` gives you actionable severity ratings (not just "found a secret").
- `git-guard` runs offline with zero dependencies.

If you already use `git-secrets` for AWS keys, Stripe keys, private keys, etc., keep it. `git-guard` is not a replacement — it's a complement that does one thing (GitHub tokens) very well.

### Why not use `gitleaks`?

`gitleaks` is a mature, popular tool with a wide detection surface. It also detects GitHub tokens. The key differences:

- `gitleaks` calls out to GitHub's API for token validation (requires network).
- `git-guard` is GitHub-only and runs 100% offline.
- `git-guard` has no dependencies and is much smaller.
- `gitleaks` has a larger community and more rules.

If you need broad secret detection, use `gitleaks`. If you need GitHub-token-specific analysis that works offline and in restricted environments, use `git-guard`.

### Does git-guard report false positives?

`git-guard` uses anchored regexes and validates the token shape (length, character class, prefix). Random strings that merely start with `ghp_` will not match. Tokens shorter or longer than the expected pattern will not match.

You can also use `--ignore` patterns to skip files where false positives are expected (e.g., test fixtures, example config files):

```bash
git-guard scan --dir . --ignore 'tests/**' --ignore '**/*.example'
```

### Can git-guard revoke tokens for me?

No, and it should not. Revocation requires authentication with GitHub, which would mean `git-guard` would need to handle and transmit your credentials. That violates the privacy-first model.

`git-guard` tells you *which* tokens to revoke and *why* they're dangerous. Revoking them is a deliberate human action you take on GitHub.com.

### What's the performance?

`git-guard` scans files at approximately 1–5 MB/s depending on file size and token density. A typical repository with thousands of files completes in seconds. The `audit` command is slower because it walks Git history, but `--shallow` reduces that to a single commit.

### Is git-guard free?

Yes. MIT licensed, free forever. No pro tier, no API key, no cloud service.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup instructions, development workflow, and the PR process.

In particular:

- Check the issues for `help-wanted` labels.
- Follow the Contributor Covenant in [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).
- Report security issues privately — see [SECURITY.md](./SECURITY.md).

## License

MIT License — see [LICENSE](./LICENSE).

## Author

Maintained by [0xshaikh](https://github.com/0xshaikh) (Anas Shaikh).

For questions, feature requests, or support, open an issue on GitHub or reach out via Twitter/X at [@0xshaikh].
