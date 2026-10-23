# Security Policy

## Supported versions

Only the most recent minor version of `git-guard` is supported for security updates.

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

Older versions may not receive security patches. Upgrade to the latest release to receive fixes.

## Reporting a vulnerability

**Do not report security vulnerabilities in public GitHub issues.** Public issues are visible to everyone, including attackers.

To report a vulnerability privately:

1. Email the maintainer at **security@0xshaikh.dev**.
2. Include a description of the vulnerability.
3. Include steps to reproduce, if possible.
4. Include affected versions, if known.

A maintainer will acknowledge receipt within 3 business days and follow up with a plan.

### What to include

- A clear description of the issue.
- Steps to reproduce (do **not** paste real tokens — use a fake token in `ghp_XXXXX...` format).
- Affected version(s) of `git-guard`.
- Any impact assessment (e.g., does this expose tokens to attackers, or is it only a correctness issue?).

### What we won't accept

- Reports that are actually feature requests.
- Reports that require the use of real GitHub credentials to reproduce.
- Reports that include real tokens or secrets (these will be deleted for safety).

## Vulnerability response timeline

- **Acknowledgment:** within 3 business days.
- **Triage decision:** within 7 business days.
- **Patch release:** within 14 business days for confirmed critical vulnerabilities.

The exact timeline depends on the severity of the issue. If a fix requires breaking changes, a coordinated disclosure may be arranged.

## Scope

This policy applies to `git-guard` and its official GitHub repository. It does not apply to forks, third-party plugins, or unrelated projects that embed `git-guard`.

## Security model

`git-guard` is designed to be privacy-first by default:

- **No network access.** The tool makes no API calls. There is no surface for an attacker to exfiltrate tokens to a third party through `git-guard` itself.
- **No telemetry.** The tool does not collect usage data.
- **No runtime dependencies.** The tool is a single runtime implementation with no transitive dependencies, minimizing supply-chain attack surface.

These design choices mean the attack surface of `git-guard` is small. Reported vulnerabilities are typically about token-detection correctness (false positives, missed patterns) rather than data exfiltration.

## Bug bounty

`git-guard` is a solo, non-commercial project. We do not offer a bug bounty program, but we will respond to all private vulnerability reports in good faith.

## Acknowledgments

If you disclose a vulnerability in good faith, we will acknowledge your contribution in the release notes (unless you request otherwise).
