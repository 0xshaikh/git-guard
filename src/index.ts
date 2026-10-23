#!/usr/bin/env node
import { spawnSync } from "child_process";
import { mkdirSync, readdirSync, readFileSync, statSync, existsSync, rmSync, writeFileSync } from "fs";
import { dirname, extname, join, relative, resolve } from "path";
import {
  auditScopes,
  describeAudit,
} from "./auditor";
import { buildReport, renderReport } from "./reporter";
import {
  TOKEN_PATTERN_LABELS,
  classifyToken,
  detectTokensInContent,
} from "./scanner";
import { Finding, Report, ReportFormat, Severity, TokenMatch } from "./types";

// ---------------------------------------------------------------------------
// CLI constants
// ---------------------------------------------------------------------------

const TOOL_VERSION = "1.0.0";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage"]);

const SKIP_EXTS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".pdf",
  ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar",
  ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
  ".woff", ".woff2", ".ttf", ".otf", ".eot",
  ".woff", ".mp3", ".mp4", ".mov", ".avi", ".mkv",
  ".class", ".jar", ".war",
]);

const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB per file

// ---------------------------------------------------------------------------
// ANSI colors (no deps)
// ---------------------------------------------------------------------------

const FORCE_COLOR = process.env.FORCE_COLOR !== "0" && process.env.NO_COLOR === undefined;
const ENABLE_COLORS = FORCE_COLOR && (process.stdout.isTTY || process.env.FORCE_COLOR === "1");

const color = (code: string, text: string): string =>
  ENABLE_COLORS ? `\x1b[${code}m${text}\x1b[0m` : text;

const bold = (t: string): string => color("1", t);
const dim = (t: string): string => color("2", t);
const red = (t: string): string => color("31", t);
const yellow = (t: string): string => color("33", t);
const green = (t: string): string => color("32", t);
const cyan = (t: string): string => color("36", t);
const gray = (t: string): string => color("90", t);

function severityLabel(severity: Severity): string {
  switch (severity) {
    case "high":
      return red(bold("HIGH"));
    case "medium":
      return yellow(bold("MED"));
    case "low":
      return green("LOW");
    default:
      return gray("INFO");
  }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

interface ParsedArgs {
  command: string;
  options: Record<string, string | boolean>;
  format: ReportFormat;
}

function parseArgs(argv: string[]): ParsedArgs {
  const [command, ...rest] = argv;
  const options: Record<string, string | boolean> = {};
  let format: ReportFormat = "json";

  for (let i = 0; i < rest.length; i++) {
    const token = rest[i];
    if (!token.startsWith("--")) continue;
    const key = token.slice(2);
    const next = rest[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      options[key] = next;
      i++;
    } else {
      options[key] = true;
    }
  }

  if (typeof options.format === "string") {
    const f = options.format as string;
    if (f === "json" || f === "md" || f === "sarif") format = f;
  }

  return { command: command ?? "", options, format };
}

function usage(): string {
  return `git-guard ${TOOL_VERSION}

Usage:
  git-guard scan --pat <token>            Audit a PAT for over-permissive scopes
  git-guard scan --file <path>            Scan a file for leaked GitHub tokens
  git-guard scan --dir <path>             Recursively scan a directory
  git-guard audit --repo <url>            Clone and audit a full repo for secrets
  git-guard report --format <json|md|sarif>   Render the last report (see --out for piping)

Global options:
  --format <json|md|sarif>   Report format (default: json)
  --out <path>               Write report to file instead of stdout
  --scopes <csv>             Comma-separated scopes to audit a classic PAT (with --pat)
  --no-color                 Disable ANSI colors

Examples:
  git-guard scan --pat ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX --scopes repo,admin:org
  git-guard scan --file .env --format md
  git-guard scan --dir ./src --format sarif --out report.sarif
  git-guard audit --repo https://github.com/owner/repo

Exit codes:
  0  success (no HIGH findings)
  1  HIGH risk detected
  2  usage or runtime error
`;
}

function die(message: string): never {
  process.stderr.write(red(`Error: ${message}\n`));
  process.exit(2);
}

function ok(message: string): void {
  process.stdout.write(green(message) + "\n");
}

function info(message: string): void {
  process.stdout.write(message + "\n");
}

// ---------------------------------------------------------------------------
// File scanning
// ---------------------------------------------------------------------------

function readTextFileSafely(path: string): string | null {
  try {
    const stat = statSync(path);
    if (stat.size > MAX_FILE_BYTES) return null;
    const buf = readFileSync(path);
    // Heuristic: skip likely binary files.
    const head = buf.subarray(0, 4096);
    for (let i = 0; i < head.length; i++) {
      if (head[i] === 0) return null;
    }
    return buf.toString("utf8");
  } catch {
    return null;
  }
}

function findFindingsInFile(absolutePath: string, displayPath: string): Finding[] {
  const content = readTextFileSafely(absolutePath);
  if (content === null) return [];
  const matches = detectTokensInContent(content);
  return matches.map((m) => tokenMatchToFinding(m, displayPath));
}

function tokenMatchToFinding(match: TokenMatch, location: string): Finding {
  const fullLocation = `${location}:${match.line}:${match.column}`;
  return {
    type: "token_detected",
    severity: "high",
    location: fullLocation,
    token_prefix: match.prefix,
    token_length: match.length,
    message: `${TOKEN_PATTERN_LABELS[match.type]} detected`,
  };
}

function walkDirectory(root: string, baseForDisplay: string): string[] {
  const results: string[] = [];
  const stack: string[] = [root];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(dir, entry);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(entry)) stack.push(full);
        continue;
      }
      if (!st.isFile()) continue;
      if (SKIP_EXTS.has(extname(entry).toLowerCase())) continue;
      results.push(join(baseForDisplay, relative(root, full)));
    }
  }
  return results;
}

function scanFileCommand(path: string): Finding[] {
  if (!existsSync(path)) die(`File not found: ${path}`);
  const st = statSync(path);
  if (st.isDirectory()) {
    die("Use --dir to scan a directory.");
  }
  return findFindingsInFile(resolve(path), path);
}

function scanDirCommand(path: string): Finding[] {
  if (!existsSync(path)) die(`Path not found: ${path}`);
  const st = statSync(path);
  if (st.isFile()) {
    die("Use --file to scan a single file.");
  }
  const resolved = resolve(path);
  const files = walkDirectory(resolved, path);
  const findings: Finding[] = [];
  for (const f of files) {
    findings.push(...findFindingsInFile(resolve(path, f), f));
  }
  return findings;
}

// ---------------------------------------------------------------------------
// PAT audit command
// ---------------------------------------------------------------------------

function scanPatCommand(token: string, scopesCsv?: string): { findings: Finding[]; auditText: string } {
  const type = classifyToken(token);
  if (type === null) {
    die(`Token does not match any known GitHub token pattern: ${token.slice(0, 10)}...`);
  }

  const scopes = scopesCsv
    ? scopesCsv.split(",").map((s) => s.trim()).filter((s) => s.length > 0)
    : [];

  const audit = auditScopes(token, scopes);

  // Emit scope-risk findings alongside the token-detection finding.
  const findings: Finding[] = [];

  if (type !== "classic_pat" && scopes.length > 0) {
    findings.push({
      type: "scope_risk",
      severity: "low",
      location: "token",
      token_prefix: audit.token_prefix,
      token_length: audit.token_length,
      message: `Scope audit is only meaningful for classic PATs; found scopes on a ${TOKEN_PATTERN_LABELS[type]} token.`,
    });
  }

  for (const risk of audit.risks) {
    findings.push({
      type: "scope_risk",
      severity: risk.level,
      location: "token",
      token_prefix: audit.token_prefix,
      token_length: audit.token_length,
      message: `${risk.scope}: ${risk.description}`,
    });
  }

  return {
    findings,
    auditText: describeAudit(audit),
  };
}

// ---------------------------------------------------------------------------
// Repo audit (clone + scan)
// ---------------------------------------------------------------------------

function auditRepo(repoUrl: string): Finding[] {
  if (!existsSync("/usr/bin/git")) {
    // Try a PATH lookup fallback; not fatal — spawnSync will surface errors.
  }
  const tmpBase = join(process.env.TMPDIR ?? "/tmp", `git-guard-${Date.now()}`);
  mkdirSync(tmpBase, { recursive: true });
  const cloneDir = join(tmpBase, "repo");

  try {
    const result = spawnSync(
      "git",
      ["clone", "--depth", "1", "--quiet", repoUrl, cloneDir],
      { encoding: "utf8", timeout: 120_000 }
    );
    if (result.status !== 0) {
      const stderr = (result.stderr ?? "").trim();
      die(`git clone failed: ${stderr || "unknown error"}`);
    }
    return scanDirCommand(cloneDir);
  } finally {
    try {
      rmSync(tmpBase, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  }
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

function printFindings(findings: Finding[]): void {
  if (findings.length === 0) {
    ok("No findings.");
    return;
  }
  const high = findings.filter((f) => f.severity === "high").length;
  const medium = findings.filter((f) => f.severity === "medium").length;
  const low = findings.filter((f) => f.severity === "low").length;
  info(`\n${bold("Findings:")} ${findings.length} total`);
  info(`  ${severityLabel("high")} ${high}`);
  info(`  ${severityLabel("medium")} ${medium}`);
  info(`  ${severityLabel("low")} ${low}`);
  info("");
  for (const f of findings) {
    info(`  ${severityLabel(f.severity)}  ${cyan(f.type)}`);
    info(`      ${dim(f.location)}`);
    info(`      ${f.message}`);
  }
}

function writeReport(report: Report, format: ReportFormat, out?: string): void {
  const rendered = renderReport(report, format);
  if (out) {
    const resolved = resolve(out);
    mkdirSync(dirname(resolved), { recursive: true });
    writeFileSync(resolved, rendered);
    info(dim(`Report written to ${resolved}`));
  } else {
    process.stdout.write(rendered);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main(): number {
  const argv = process.argv.slice(2);

  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    process.stdout.write(usage());
    return argv.length === 0 ? 0 : 0;
  }

  const parsed = parseArgs(argv);
  const { command, options, format } = parsed;
  const out = typeof options.out === "string" ? (options.out as string) : undefined;

  if (command === "report") {
    if (typeof options.file !== "string") {
      die("report requires --file <path> (a JSON findings file)");
    }
    const data = readFileSync(resolve(options.file as string), "utf8");
    const report = JSON.parse(data) as Report;
    process.stdout.write(renderReport(report, format));
    return 0;
  }

  let findings: Finding[];
  let exitCode = 0;

  switch (command) {
    case "scan": {
      if (typeof options.pat === "string") {
        const result = scanPatCommand(options.pat as string, typeof options.scopes === "string" ? options.scopes as string : undefined);
        findings = result.findings;
        info(`${bold("PAT Audit")}\n`);
        info(result.auditText);
      } else if (typeof options.file === "string") {
        findings = scanFileCommand(options.file as string);
        info(`${bold("File scan:")}\n  ${options.file as string}\n`);
      } else if (typeof options.dir === "string") {
        findings = scanDirCommand(options.dir as string);
        info(`${bold("Directory scan:")}\n  ${options.dir as string}\n`);
      } else {
        die("scan requires one of --pat, --file, or --dir");
      }
      break;
    }
    case "audit": {
      if (typeof options.repo !== "string") {
        die("audit requires --repo <url>");
      }
      info(dim(`Cloning ${options.repo as string}...\n`));
      findings = auditRepo(options.repo as string);
      info(`${bold("Repo audit:")}\n  ${options.repo as string}\n`);
      break;
    }
    default:
      process.stdout.write(usage());
      return 2;
  }

  // Build a report from findings and print in the requested format.
  const report = buildReport(findings);

  // If the user asked for machine-readable output, emit only the report.
  if (format !== "json" || out) {
    writeReport(report, format, out);
  } else if (!ENABLE_COLORS || !process.stdout.isTTY) {
    writeReport(report, "json", undefined);
  } else {
    // Human-friendly mode: print findings + JSON report on stdout.
    printFindings(findings);
    info("");
    writeReport(report, "json", undefined);
  }

  const highCount = findings.filter((f) => f.severity === "high").length;
  exitCode = highCount > 0 ? 1 : 0;
  return exitCode;
}

const code = main();
process.exit(code);
