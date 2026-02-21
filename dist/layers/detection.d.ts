/**
 * Detection Layer
 *
 * Ingests dependency manifests from managed repos, queries the GitHub
 * Advisory Database (GHSA) via GraphQL, and produces CveQueueEntry
 * records for downstream layers.
 *
 * Inputs:  repo list + GitHub token
 * Outputs: CveQueueEntry[] (not yet persisted — that's the State layer's job)
 */
import type { CveQueueEntry, Severity, GitHubAdapter } from "../types.js";
export interface DetectionResult {
    reposScanned: number;
    findings: CveQueueEntry[];
    bySeverity: Record<string, number>;
}
export declare function detect(repos: string[], severityThreshold: Severity, github: GitHubAdapter): Promise<DetectionResult>;
//# sourceMappingURL=detection.d.ts.map