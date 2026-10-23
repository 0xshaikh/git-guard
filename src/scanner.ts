import { TokenMatch, TokenType } from "./types";

interface TokenPattern {
  type: TokenType;
  /** Regex used to match the token. Must not use the global flag (stateful). */
  regex: RegExp;
  prefix: string;
  label: string;
}

const TOKEN_PATTERNS: TokenPattern[] = [
  {
    type: "fine_grained_pat",
    regex: /\bgithub_pat_[A-Za-z0-9_]{50,}\b/,
    prefix: "github_pat_",
    label: "Fine-grained PAT",
  },
  {
    type: "classic_pat",
    regex: /\bghp_[A-Za-z0-9]{36}\b/,
    prefix: "ghp_",
    label: "Classic PAT",
  },
  {
    type: "github_oauth",
    regex: /\bgho_[A-Za-z0-9]{36}\b/,
    prefix: "gho_",
    label: "GitHub OAuth token",
  },
  {
    type: "app_token",
    regex: /\bghu_[A-Za-z0-9]{36}\b/,
    prefix: "ghu_",
    label: "GitHub App user token",
  },
  {
    type: "app_installation",
    regex: /\bghs_[A-Za-z0-9]{36}\b/,
    prefix: "ghs_",
    label: "GitHub App installation token",
  },
];

export const TOKEN_PATTERN_LABELS: Record<TokenType, string> = {
  classic_pat: "Classic PAT",
  fine_grained_pat: "Fine-grained PAT",
  github_oauth: "GitHub OAuth token",
  app_token: "GitHub App user token",
  app_installation: "GitHub App installation token",
};

/**
 * Detect all GitHub token patterns in a single line of text.
 *
 * @param line The line content to scan.
 * @param lineNumber 1-based line number for result attribution.
 *
 * Note: we use `matchAll` on a fresh global-flagged regex copy per pattern,
 * which is both memory-safe and correct for finding every occurrence.
 */
export function detectTokensInLine(
  line: string,
  lineNumber: number
): TokenMatch[] {
  const matches: TokenMatch[] = [];

  for (const pattern of TOKEN_PATTERNS) {
    // Build a stateless global copy so `matchAll` yields every occurrence.
    const globalRegex = new RegExp(pattern.regex.source, "g");
    for (const match of line.matchAll(globalRegex)) {
      matches.push({
        type: pattern.type,
        token: match[0],
        prefix: pattern.prefix,
        length: match[0].length,
        line: lineNumber,
        column: (match.index ?? 0) + 1,
      });
    }
  }

  // Sort by column so results are predictable.
  matches.sort((a, b) => a.column - b.column);
  return matches;
}

/**
 * Detect all GitHub token patterns in a full file's contents.
 *
 * @param content The full text of the file.
 */
export function detectTokensInContent(content: string): TokenMatch[] {
  // Split while preserving line numbers even on trailing newline.
  const lines = content.split(/\r?\n/);
  const all: TokenMatch[] = [];
  for (let i = 0; i < lines.length; i++) {
    all.push(...detectTokensInLine(lines[i], i + 1));
  }
  return all;
}

/**
 * Validate a raw PAT string against the known patterns.
 *
 * @param token The token to validate.
 * @returns The matching token type, or null if no pattern matched.
 */
export function classifyToken(token: string): TokenType | null {
  const trimmed = token.trim();
  for (const pattern of TOKEN_PATTERNS) {
    // Use a fresh regex so we match from the start of the string.
    const anchored = new RegExp(`^${pattern.regex.source}$`);
    if (anchored.test(trimmed)) {
      return pattern.type;
    }
  }
  return null;
}

/**
 * Mask a token for safe display: keep prefix and last 4 chars.
 */
export function maskToken(token: string): string {
  if (token.length <= 8) return "****";
  return `${token.slice(0, 7)}...${token.slice(-4)}`;
}
