/**
 * Shared type definitions for git-guard.
 */

export type Severity = "high" | "medium" | "low";

export type TokenType =
  | "classic_pat"
  | "fine_grained_pat"
  | "github_oauth"
  | "app_token"
  | "app_installation";

export interface TokenMatch {
  type: TokenType;
  /** Raw matched token string. */
  token: string;
  /** Prefix only (e.g. "ghp_"). */
  prefix: string;
  /** Length of the matched token. */
  length: number;
  /** 1-based line number within the scanned file. */
  line: number;
  /** Column (1-based) of the match within the line. */
  column: number;
}

export interface Finding {
  type: "token_detected" | "scope_risk";
  severity: Severity;
  location: string;
  token_prefix: string;
  token_length: number;
  message: string;
  scopes?: string[];
}

export interface AuditResult {
  token_type: TokenType;
  token_prefix: string;
  token_length: number;
  token_masked: string;
  scopes: string[];
  risks: {
    scope: string;
    level: Severity;
    description: string;
  }[];
  overall_severity: Severity;
}

export interface Report {
  scan_timestamp: string;
  tool_version: string;
  findings: Finding[];
  summary: {
    total_findings: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface ScanOptions {
  file?: string;
  dir?: string;
  pat?: string;
}

export type ReportFormat = "json" | "md" | "sarif";
