/**
 * @git-fabric/cve — shared types
 *
 * All layers import from here. No circular dependencies.
 */

// ── Severity ────────────────────────────────────────────────────────────────

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE" | "UNKNOWN";

export const SEVERITY_ORDER: Severity[] = [
  "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN",
];

export function normalizeSeverity(s: string): Severity {
  const upper = s?.toUpperCase() as Severity;
  return (["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] as Severity[]).includes(upper)
    ? upper
    : "UNKNOWN";
}

export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER.indexOf(severity) <= SEVERITY_ORDER.indexOf(threshold);
}

// ── Queue entry — the canonical record that flows through all layers ────────

export interface CveQueueEntry {
  id: string;                // CVE ID (or GHSA ID if no CVE assigned)
  ghsaId?: string;           // GitHub Advisory ID
  repo: string;              // owner/repo
  ecosystem: string;         // npm, pip, go, cargo, maven, composer
  affectedPackage: string;   // package name
  affectedVersion: string;   // version found in repo
  patchedVersion: string;    // version to upgrade to
  severity: Severity;
  cvssScore: number | null;
  summary: string;
  nvdUrl: string;
  detectedAt: string;        // ISO timestamp
  status: "pending" | "pr_opened" | "skipped" | "error";
  prNumber?: number;
  prUrl?: string;
  processedAt?: string;
  skipReason?: string;
}

// ── NVD enrichment result ───────────────────────────────────────────────────

export interface CveEnrichment {
  id: string;
  status: string;            // NVD status: Received, Awaiting Analysis, Analyzed, etc.
  severity: Severity;
  score: number | null;
  description: string;
  published: string;
  references: string[];
  cwe: string | null;
}

// ── GHSA advisory (from GitHub GraphQL) ─────────────────────────────────────

export interface GhsaAdvisory {
  ghsaId: string;
  cveId: string | null;
  summary: string;
  severity: string;
  cvssScore: number | null;
  package: {
    ecosystem: string;
    name: string;
  };
  vulnerableVersionRange: string;
  firstPatchedVersion: string | null;
}

// ── Manifest ────────────────────────────────────────────────────────────────

export type Ecosystem = "npm" | "pip" | "go" | "maven" | "cargo" | "composer";

export interface ManifestFile {
  path: string;
  ecosystem: Ecosystem;
  content: string;
}

// ── Triage policy ───────────────────────────────────────────────────────────

export interface TriagePolicy {
  autoPrThreshold: Severity;
  draftThreshold: Severity;
  maxPrsPerRun: number;
  requirePatchedVersion: boolean;
}

// ── Action result ───────────────────────────────────────────────────────────

export interface PrResult {
  cveId: string;
  repo: string;
  action: "pr_opened" | "skipped" | "error";
  prNumber?: number;
  prUrl?: string;
  reason?: string;
}

// ── GitHub adapter — what the fabric needs from the consumer ────────────────

export interface GitHubAdapter {
  token: string;
  getFileContent(owner: string, repo: string, path: string): Promise<string | null>;
  createBranch(owner: string, repo: string, branch: string, fromBranch: string): Promise<void>;
  commitFiles(owner: string, repo: string, opts: {
    branch: string;
    message: string;
    files: { path: string; content: string }[];
  }): Promise<{ sha: string; url: string }>;
  createPullRequest(owner: string, repo: string, opts: {
    title: string;
    body: string;
    head: string;
    base: string;
    draft: boolean;
    labels: string[];
  }): Promise<{ number: number; html_url: string }>;
  getDefaultBranch(owner: string, repo: string): Promise<string>;
}

// ── State adapter — how the fabric persists queue data ──────────────────────

export interface StateAdapter {
  read(file: string): Promise<string | null>;
  write(file: string, content: string): Promise<void>;
  append(file: string, lines: string[]): Promise<void>;
}
