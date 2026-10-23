// Minimal `it()` shim that mirrors node:test's API for our tests.
// Node 24's built-in `node:test` runner leaks ~2GB per test file in this
// environment, so we use a tiny shim that keeps `npm test` deterministic.
"use strict";

export function it(name: string, fn: () => void): void {
  tests.push({ name, fn });
}

export function run(): void {
  for (const { name, fn } of tests) {
    try {
      fn();
      passed++;
      process.stdout.write(`  \u2714 ${name}\n`);
    } catch (err) {
      failed++;
      failures.push(name);
      process.stdout.write(`  \u2716 ${name}\n`);
      process.stdout.write(
        `      ${err instanceof Error ? err.stack : String(err)}\n`
      );
    }
  }
  finish();
}

let passed = 0;
let failed = 0;
const failures: string[] = [];
const tests: { name: string; fn: () => void }[] = [];

function finish(): void {
  process.stdout.write(`\n${passed} passed, ${failed} failed, ${passed + failed} total\n`);
  if (failed > 0) {
    process.stdout.write("\nFailures:\n");
    for (const f of failures) process.stdout.write(`  - ${f}\n`);
    process.exitCode = 1;
  }
}
