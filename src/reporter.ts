import { Finding, Report, ReportFormat, Severity } from "./types";

const VERSION = "1.0.0";

export function buildReport(findings: Finding[]): Report {
  const summary = {
    total_findings: findings.length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
  };
  return {
    scan_timestamp: new Date().toISOString(),
    tool_version: VERSION,
    findings,
    summary,
  };
}

export function renderReport(report: Report, format: ReportFormat): string {
  switch (format) {
    case "json":
      return JSON.stringify(report, null, 2) + "\n";
    case "md":
      return renderMarkdown(report);
    case "sarif":
      return JSON.stringify(toSarif(report), null, 2) + "\n";
    default:
      throw new Error(`Unknown report format: ${format}`);
  }
}

function renderMarkdown(report: Report): string {
  const lines: string[] = [];
  lines.push("# git-guard Report");
  lines.push("");
  lines.push(`- **Scan timestamp:** ${report.scan_timestamp}`);
  lines.push(`- **Tool version:** ${report.tool_version}`);
  lines.push(
    `- **Findings:** ${report.summary.total_findings} (high: ${report.summary.high}, medium: ${report.summary.medium}, low: ${report.summary.low})`
  );
  lines.push("");
  if (report.findings.length === 0) {
    lines.push("No findings.");
    return lines.join("\n") + "\n";
  }
  lines.push("| Severity | Type | Location | Prefix | Length | Message |");
  lines.push("|----------|------|----------|--------|--------|---------|");
  for (const f of report.findings) {
    lines.push(
      `| ${severityEmoji(f.severity)} ${f.severity} | ${f.type} | \`${f.location}\` | ${f.token_prefix} | ${f.token_length} | ${escapeCell(f.message)} |`
    );
  }
  return lines.join("\n") + "\n";
}

function escapeCell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function severityEmoji(severity: Severity): string {
  switch (severity) {
    case "high":
      return "🔴";
    case "medium":
      return "🟡";
    case "low":
      return "🟢";
    default:
      return "⚪";
  }
}

interface SarifResult {
  level: string;
  ruleId: string;
  message: { text: string };
  locations: {
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number; startColumn: number };
    };
  }[];
}

interface SarifDocument {
  $schema: string;
  version: string;
  runs: {
    tool: {
      driver: {
        name: string;
        version: string;
        rules: unknown[];
      };
    };
    results: SarifResult[];
  }[];
}

function severityToSarifLevel(severity: Severity): string {
  switch (severity) {
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "note";
    default:
      return "none";
  }
}

function locationToSarif(location: string): { uri: string; line: number; column: number } {
  // Location format is "path:line" or "path:line:column".
  // Split from the right to correctly parse absolute paths (Windows drives,
  // /tmp paths with colons in directory names, etc.).
  const parts = location.split(":");
  if (parts.length === 1) {
    return { uri: parts[0], line: 1, column: 1 };
  }
  const last = parts.pop() as string;
  const column = Number.parseInt(last, 10) || 1;
  if (parts.length === 1) {
    return { uri: parts[0], line: 1, column };
  }
  const linePart = parts.pop() as string;
  const line = Number.parseInt(linePart, 10) || 1;
  return { uri: parts.join(":"), line, column };
}

function toSarif(report: Report): SarifDocument {
  const results: SarifResult[] = report.findings.map((f) => {
    const loc = locationToSarif(f.location);
    return {
      level: severityToSarifLevel(f.severity),
      ruleId: `git-guard/${f.type}/${f.severity}`,
      message: { text: f.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: loc.uri },
            region: { startLine: loc.line, startColumn: loc.column },
          },
        },
      ],
    };
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "git-guard",
            version: report.tool_version,
            rules: [],
          },
        },
        results,
      },
    ],
  };
}
