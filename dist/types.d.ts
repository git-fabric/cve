/**
 * @git-fabric/cve — shared types
 *
 * All layers import from here. No circular dependencies.
 */
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE" | "UNKNOWN";
export declare const SEVERITY_ORDER: Severity[];
export declare function normalizeSeverity(s: string): Severity;
export declare function meetsThreshold(severity: Severity, threshold: Severity): boolean;
export interface CveQueueEntry {
    id: string;
    ghsaId?: string;
    repo: string;
    ecosystem: string;
    affectedPackage: string;
    affectedVersion: string;
    patchedVersion: string;
    severity: Severity;
    cvssScore: number | null;
    summary: string;
    nvdUrl: string;
    detectedAt: string;
    status: "pending" | "pr_opened" | "skipped" | "error";
    prNumber?: number;
    prUrl?: string;
    processedAt?: string;
    skipReason?: string;
}
export interface CveEnrichment {
    id: string;
    status: string;
    severity: Severity;
    score: number | null;
    description: string;
    published: string;
    references: string[];
    cwe: string | null;
}
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
export type Ecosystem = "npm" | "pip" | "go" | "maven" | "cargo" | "composer";
export interface ManifestFile {
    path: string;
    ecosystem: Ecosystem;
    content: string;
}
export interface TriagePolicy {
    autoPrThreshold: Severity;
    draftThreshold: Severity;
    maxPrsPerRun: number;
    requirePatchedVersion: boolean;
}
export interface PrResult {
    cveId: string;
    repo: string;
    action: "pr_opened" | "skipped" | "error";
    prNumber?: number;
    prUrl?: string;
    reason?: string;
}
export interface GitHubAdapter {
    token: string;
    getFileContent(owner: string, repo: string, path: string): Promise<string | null>;
    createBranch(owner: string, repo: string, branch: string, fromBranch: string): Promise<void>;
    commitFiles(owner: string, repo: string, opts: {
        branch: string;
        message: string;
        files: {
            path: string;
            content: string;
        }[];
    }): Promise<{
        sha: string;
        url: string;
    }>;
    createPullRequest(owner: string, repo: string, opts: {
        title: string;
        body: string;
        head: string;
        base: string;
        draft: boolean;
        labels: string[];
    }): Promise<{
        number: number;
        html_url: string;
    }>;
    getDefaultBranch(owner: string, repo: string): Promise<string>;
}
export interface StateAdapter {
    read(file: string): Promise<string | null>;
    write(file: string, content: string): Promise<void>;
    append(file: string, lines: string[]): Promise<void>;
}
//# sourceMappingURL=types.d.ts.map