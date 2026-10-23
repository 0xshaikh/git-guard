# Changelog

All notable changes to `git-guard` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-23

### Added

- **Initial public release.**
- `git-guard scan --file <path>` — scan a single file for leaked GitHub tokens.
- `git-guard scan --dir <path>` — recursively scan a directory tree.
- `git-guard scan --pat <token>` — analyze the scopes of a PAT string directly.
- `git-guard audit --repo <url>` — clone and scan a remote repository, including history.
- `git-guard audit --shallow` — shallow-clone mode for faster audits of large repos.
- `git-guard report --format json|md|sarif` — generate reports in three formats.
- **Token detection** for all GitHub token types:
  - Classic PATs (`ghp_*`)
  - Fine-grained PATs (`github_pat_*`)
  - OAuth tokens (`gho_*`)
  - App user tokens (`ghu_*`)
  - App installation tokens (`ghs_*`)
  - Refresh tokens (`ghr_*`)
  - Server-to-server tokens (`ghb_*`)
- **Scope severity analysis** with HIGH / MEDIUM / LOW classification.
- **CI-friendly flags**: `--strict`, `--quiet`, `--ignore`, `--verbose`.
- **Zero dependencies** — single-runtime implementation, no transitive packages.
- **Privacy-first design** — no API calls, no telemetry, no network access.
- GitHub Actions CI workflow (`ci.yml`).
- Release automation via GitHub Actions (`release.yml`).
- Documentation: README, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, LICENSE.

### Notes

This is the first public release. The tool is feature-complete for its stated scope: detecting and analyzing leaked GitHub Personal Access Tokens. Future releases will focus on stability, performance, and incremental enhancements rather than new command surfaces.

[1.0.0]: https://github.com/0xshaikh/git-guard/releases/tag/v1.0.0
