// Unit tests for git-guard using Node's built-in `node:test` runner.
//
// Note: On Node 24 this environment, `node:test` exhibits a memory leak of
// ~2GB per `describe` block that eventually triggers V8 OOM. To keep the
// suite runnable we use `it()` at the top level (no describe) which avoids
// the leak while still exercising the built-in test runner.
// Node 24's built-in `node:test` runner leaks ~2GB per test file in this
// environment, so we use a tiny `it` shim that mirrors the same API.
import { it, run } from "./test_shim";
import assert from "node:assert/strict";
import {
  TOKEN_PATTERN_LABELS,
  classifyToken,
  detectTokensInContent,
  detectTokensInLine,
  maskToken,
} from "../scanner";
import { auditScopes } from "../auditor";
import { buildReport, renderReport } from "../reporter";

const CLASSIC_PAT = "ghp_" + "1".repeat(36);
const FINE_GRAINED_PAT =
  "github_pat_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
const GHO = "gho_" + "1".repeat(36);
const GHu = "ghu_" + "1".repeat(36);
const GHs = "ghs_" + "1".repeat(36);

it("classifyToken: classic PAT", () => {
  assert.equal(classifyToken(CLASSIC_PAT), "classic_pat");
});

it("classifyToken: fine-grained PAT", () => {
  assert.equal(classifyToken(FINE_GRAINED_PAT), "fine_grained_pat");
});

it("classifyToken: OAuth token", () => {
  assert.equal(classifyToken(GHO), "github_oauth");
});

it("classifyToken: App user token", () => {
  assert.equal(classifyToken(GHu), "app_token");
});

it("classifyToken: App installation token", () => {
  assert.equal(classifyToken(GHs), "app_installation");
});

it("classifyToken: unknown prefix returns null", () => {
  assert.equal(classifyToken("ghx_" + "1".repeat(36)), null);
  assert.equal(classifyToken("not-a-token"), null);
  assert.equal(classifyToken(""), null);
});

it("classifyToken: wrong length rejected", () => {
  assert.equal(classifyToken("ghp_" + "1".repeat(35)), null);
  assert.equal(classifyToken("ghp_" + "1".repeat(37)), null);
});

it("classifyToken: tolerates surrounding whitespace", () => {
  assert.equal(classifyToken(`  ${CLASSIC_PAT}  `), "classic_pat");
});

it("detectTokensInLine: classic PAT with correct column", () => {
  const m = detectTokensInLine(`GITHUB_TOKEN=${CLASSIC_PAT}`, 1);
  assert.equal(m.length, 1);
  assert.equal(m[0].type, "classic_pat");
  assert.equal(m[0].prefix, "ghp_");
  assert.equal(m[0].token, CLASSIC_PAT);
  assert.equal(m[0].length, CLASSIC_PAT.length);
  assert.equal(m[0].line, 1);
  assert.equal(m[0].column, 14);
});

it("detectTokensInLine: multiple tokens sorted by column", () => {
  const m = detectTokensInLine(`${CLASSIC_PAT} ${FINE_GRAINED_PAT}`, 3);
  assert.equal(m.length, 2);
  assert.equal(m[0].type, "classic_pat");
  assert.equal(m[1].type, "fine_grained_pat");
});

it("detectTokensInLine: returns empty for clean line", () => {
  assert.deepEqual(detectTokensInLine("hello world", 1), []);
});

it("detectTokensInLine: rejects too-long ghp_ token", () => {
  const m = detectTokensInLine("ghp_" + "1".repeat(37) + "x", 1);
  assert.equal(m.length, 0);
});

it("detectTokensInContent: 1-based line numbers", () => {
  const m = detectTokensInContent(`line one\nGITHUB_TOKEN=${CLASSIC_PAT}\nline three`);
  assert.equal(m.length, 1);
  assert.equal(m[0].line, 2);
});

it("detectTokensInContent: handles CRLF line endings", () => {
  const m = detectTokensInContent(`a\r\n${CLASSIC_PAT}\r\nb\r\n`);
  assert.equal(m.length, 1);
  assert.equal(m[0].line, 2);
});

it("detectTokensInContent: handles empty content", () => {
  assert.deepEqual(detectTokensInContent(""), []);
});

it("maskToken: keeps prefix and last 4 chars", () => {
  const masked = maskToken(CLASSIC_PAT);
  assert.ok(masked.startsWith("ghp_"));
  assert.ok(masked.includes("..."));
});

it("maskToken: returns stars for very short input", () => {
  assert.equal(maskToken("ghp_12"), "****");
});

it("auditScopes: high-risk scopes yield high overall severity", () => {
  const r = auditScopes(CLASSIC_PAT, ["admin:org", "repo"]);
  assert.equal(r.token_type, "classic_pat");
  assert.equal(r.overall_severity, "high");
  assert.equal(r.risks.length, 2);
  assert.ok(r.risks.some((x) => x.scope === "admin:org" && x.level === "high"));
  assert.ok(r.risks.some((x) => x.scope === "repo" && x.level === "medium"));
});

it("auditScopes: no scopes yields low severity", () => {
  const r = auditScopes(CLASSIC_PAT, []);
  assert.equal(r.overall_severity, "low");
  assert.equal(r.risks.length, 0);
});

it("auditScopes: unknown scopes are ignored", () => {
  const r = auditScopes(CLASSIC_PAT, ["not:real", "repo"]);
  assert.equal(r.risks.length, 1);
  assert.equal(r.risks[0].scope, "repo");
});

it("auditScopes: medium-only scopes yield medium severity", () => {
  const r = auditScopes(CLASSIC_PAT, ["gist", "user:email"]);
  assert.equal(r.overall_severity, "medium");
});

it("auditScopes: low-only scopes yield low severity", () => {
  const r = auditScopes(CLASSIC_PAT, ["read:org", "public_repo"]);
  assert.equal(r.overall_severity, "low");
});

it("auditScopes: masks the token in output", () => {
  const r = auditScopes(CLASSIC_PAT, ["repo"]);
  assert.ok(r.token_masked.includes("..."));
  assert.ok(!r.token_masked.includes(CLASSIC_PAT));
});

const sampleFindings = [
  {
    type: "token_detected" as const,
    severity: "high" as const,
    location: ".env:3",
    token_prefix: "ghp_",
    token_length: 40,
    message: "Classic PAT detected",
  },
  {
    type: "scope_risk" as const,
    severity: "medium" as const,
    location: "token",
    token_prefix: "ghp_",
    token_length: 40,
    message: "repo: access",
  },
  {
    type: "scope_risk" as const,
    severity: "low" as const,
    location: "token",
    token_prefix: "ghp_",
    token_length: 40,
    message: "read:org",
  },
];

it("buildReport: correct summary counts", () => {
  const r = buildReport(sampleFindings);
  assert.equal(r.summary.total_findings, 3);
  assert.equal(r.summary.high, 1);
  assert.equal(r.summary.medium, 1);
  assert.equal(r.summary.low, 1);
  assert.ok(typeof r.scan_timestamp === "string");
});

it("renderReport: JSON is valid and parseable", () => {
  const r = buildReport(sampleFindings);
  const parsed = JSON.parse(renderReport(r, "json")) as { findings: unknown[] };
  assert.equal(parsed.findings.length, 3);
});

it("renderReport: Markdown contains header and findings table", () => {
  const r = buildReport(sampleFindings);
  const md = renderReport(r, "md");
  assert.ok(md.startsWith("# git-guard Report"));
  assert.ok(md.includes("| Severity |"));
});

it("renderReport: SARIF 2.1.0 with one result per finding", () => {
  const r = buildReport(sampleFindings);
  const parsed = JSON.parse(renderReport(r, "sarif")) as {
    version: string;
    runs: { results: unknown[] }[];
  };
  assert.equal(parsed.version, "2.1.0");
  assert.equal(parsed.runs[0].results.length, 3);
});

it("renderReport: handles empty findings gracefully", () => {
  const r = buildReport([]);
  assert.equal(r.summary.total_findings, 0);
  assert.ok(renderReport(r, "md").includes("No findings."));
});

it("TOKEN_PATTERN_LABELS: all five token types are labelled", () => {
  assert.ok(Object.keys(TOKEN_PATTERN_LABELS).length >= 5);
  assert.ok(TOKEN_PATTERN_LABELS.classic_pat.includes("Classic"));
  assert.ok(TOKEN_PATTERN_LABELS.fine_grained_pat.includes("Fine-grained"));
});

run();
