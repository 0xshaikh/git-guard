# Contributing to git-guard

Thank you for considering a contribution! `git-guard` is a solo project maintained by [0xshaikh](https://github.com/0xshaikh), but it's open source and we'd love help from the community.

This guide covers how to set up the development environment, run the test suite, and submit a pull request.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](./CODE_OF_CONDUCT.md). Please read it carefully before opening an issue or submitting a PR.

## Before you start

### Choosing an issue

- Browse open issues labeled `help-wanted`, `good-first-issue`, or `enhancement`.
- Comment on an issue to claim it before starting — this avoids duplicate work.
- For larger changes, open an issue to discuss the design first.

### Asking questions

If you're not sure how to approach a problem, open a `question`-labeled issue or use the GitHub Discussions area. Better to ask than to guess.

## Development Setup

### Prerequisites

- **Node.js 18+** — LTS recommended
- **npm 9+** — bundled with modern Node.js

### Clone and install

```bash
git clone https://github.com/0xshaikh/git-guard.git
cd git-guard
npm install
```

### Build

```bash
npm run build
```

This compiles the TypeScript sources to `dist/`. Run this after any source change.

### Link globally (optional)

```bash
npm link
```

This puts the `git-guard` command on your PATH for local testing.

## Running Tests

```bash
# Run the full test suite
npm test

# Run tests in watch mode
npm test -- --watch

# Run a single test file
npm test -- path/to/test-file.test.js
```

Tests are written in Node.js's built-in `node:test` runner. We deliberately avoid heavy testing frameworks — the goal is a small, fast, dependency-free tool, and the tests should reflect that.

### Coverage

```bash
npm test -- --coverage
```

We aim for high coverage on the token-detection logic. If you add a new detector or scope rule, add a test for it.

## Linting

```bash
npm run lint
```

We use ESLint with a minimal, pragmatic config. The linter is not exhaustive — it catches common mistakes, not every stylistic preference. If the linter disagrees with a maintainer, the maintainer wins; please open an issue to discuss config changes.

## Coding Style

- **TypeScript** — strict mode, no `any` unless absolutely necessary (and a comment explaining why).
- **No runtime dependencies** — this is a hard rule. The tool must remain zero-dependency at runtime. Dev dependencies are fine for testing and linting.
- **Small functions** — prefer small, single-purpose functions over large ones.
- **Explicit error handling** — don't silently swallow errors. Surface them.
- **Documented regexes** — every token pattern gets a comment explaining what it matches.

## Submitting a Pull Request

### Checklist

Before opening a PR:

- [ ] Run `npm test` — all tests pass.
- [ ] Run `npm run lint` — no lint errors.
- [ ] Run `npm run build` — compiles cleanly.
- [ ] Add tests for any new functionality.
- [ ] Update documentation (README, examples) if behavior changed.
- [ ] Squash commits into a single, logical commit.

### PR template

A [PR template](./.github/PULL_REQUEST_TEMPLATE.md) is provided. Fill it in — it helps reviewers understand what you did and why.

### Scope of a PR

Keep PRs focused. One PR should address one issue or one logical change. If your PR touches unrelated files, split it.

### Review process

Maintainer review typically happens within a few days. For larger PRs, expect more back-and-forth. Be responsive to review comments — address them or explain your reasoning.

## Reporting Security Issues

**Do not report security vulnerabilities in public issues.** See [SECURITY.md](./SECURITY.md) for the private disclosure process.

## License

By contributing, you agree that your contributions will be licensed under the same MIT License as the project.
