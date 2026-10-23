import { AuditResult, Severity, TokenType } from "./types";
import { classifyToken, maskToken } from "./scanner";

interface ScopeRule {
  scope: string;
  level: Severity;
  description: string;
}

const SCOPE_RULES: ScopeRule[] = [
  // HIGH
  {
    scope: "admin:org",
    level: "high",
    description:
      "Full administrative control over organizations — can add/remove members, modify billing, manage team membership.",
  },
  {
    scope: "admin:repo_hook",
    level: "high",
    description:
      "Manage webhooks for any repository the token can access — can redirect outbound events to attacker-controlled servers.",
  },
  {
    scope: "write:packages",
    level: "high",
    description:
      "Publish, delete, and overwrite packages in the GitHub Container Registry — supply-chain risk.",
  },
  {
    scope: "admin:public_key",
    level: "high",
    description:
      "Modify SSH and GPG keys for the account — allows adding attacker SSH keys and bypassing 2FA on clone.",
  },
  // MEDIUM
  {
    scope: "repo",
    level: "medium",
    description:
      "Full read/write access to private repositories — code exfiltration and malicious commit risk.",
  },
  {
    scope: "gist",
    level: "medium",
    description: "Create and modify gists — can read private gists and write new ones.",
  },
  {
    scope: "user:email",
    level: "medium",
    description:
      "Read private email addresses associated with the account — privacy and phishing risk.",
  },
  {
    scope: "delete:packages",
    level: "medium",
    description: "Delete packages — can destroy shared artifacts and disrupt builds.",
  },
  // LOW
  {
    scope: "read:org",
    level: "low",
    description: "Read organization metadata and membership.",
  },
  {
    scope: "public_repo",
    level: "low",
    description: "Read/write access to public repositories only.",
  },
];

const SEVERITY_RANK: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
};

/**
 * Audit scopes of a classic PAT for over-permissive permissions.
 *
 * Only classic PATs (ghp_) have a meaningful scope string. Fine-grained
 * PATs (github_pat_) and short-lived app tokens (ghs_, gho_, ghu_) do not
 * carry a static scope list, so this function reports an empty risk list.
 *
 * @param token The raw token string.
 * @param scopes Scope strings as provided by the caller (parsed from token
 *  metadata). When empty, the auditor returns no risks.
 */
export function auditScopes(token: string, scopes: string[]): AuditResult {
  const tokenType = classifyToken(token) ?? "classic_pat";
  const risks = scopes
    .map((scope) => {
      const rule = SCOPE_RULES.find((r) => r.scope === scope);
      if (!rule) return null;
      return { scope, level: rule.level, description: rule.description };
    })
    .filter((r): r is NonNullable<typeof r> => r !== null);

  const overallSeverity = risks.reduce<Severity>(
    (max, r) => (SEVERITY_RANK[r.level] > SEVERITY_RANK[max] ? r.level : max),
    "low"
  );

  return {
    token_type: tokenType,
    token_prefix: token.slice(0, token.indexOf("_") + 1),
    token_length: token.length,
    token_masked: maskToken(token),
    scopes,
    risks,
    overall_severity: overallSeverity,
  };
}

/**
 * Produce a textual risk assessment from an AuditResult.
 */
export function describeAudit(result: AuditResult): string {
  const lines: string[] = [];
  lines.push(`Token: ${result.token_masked}`);
  lines.push(`Type: ${result.token_type}`);
  lines.push(`Scopes: ${result.scopes.length ? result.scopes.join(", ") : "(none reported)"}`);
  if (result.risks.length === 0) {
    lines.push("No scope risks detected.");
  } else {
    for (const risk of result.risks) {
      lines.push(`  [${risk.level.toUpperCase()}] ${risk.scope}: ${risk.description}`);
    }
  }
  lines.push(`Overall severity: ${result.overall_severity.toUpperCase()}`);
  return lines.join("\n");
}

/**
 * Helper: classify token types that do not have scope-based audits.
 */
export function tokenSupportsScopeAudit(type: TokenType): boolean {
  return type === "classic_pat";
}
