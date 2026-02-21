/**
 * State Layer
 *
 * Manages the CVE queue (state/cve-queue.jsonl) with append-only
 * semantics and last-write-wins deduplication.
 *
 * Also provides queue health stats for dashboards and digest reports.
 *
 * Inputs:  StateAdapter (provided by consumer — git-steer, Actions, etc.)
 * Outputs: Queue reads, writes, and stats
 */
import type { CveQueueEntry, Severity, StateAdapter } from "../types.js";
/**
 * Append new findings to the queue. Deduplicates by id+repo.
 */
export declare function enqueue(entries: CveQueueEntry[], state: StateAdapter): Promise<{
    added: number;
    duplicates: number;
}>;
/**
 * List queue entries with filtering.
 */
export declare function list(state: StateAdapter, opts?: {
    status?: CveQueueEntry["status"] | "all";
    severityMin?: Severity;
    repo?: string;
    limit?: number;
}): Promise<{
    total: number;
    entries: CveQueueEntry[];
}>;
/**
 * Update status of queue entries (after action layer executes).
 */
export declare function update(updates: {
    id: string;
    repo: string;
    status: CveQueueEntry["status"];
    prNumber?: number;
    prUrl?: string;
    skipReason?: string;
}[], state: StateAdapter): Promise<{
    updated: number;
    notFound: number;
}>;
/**
 * Get all pending entries (for the decision layer).
 */
export declare function pending(state: StateAdapter): Promise<CveQueueEntry[]>;
/**
 * Queue health stats.
 */
export declare function stats(state: StateAdapter): Promise<{
    total: number;
    byStatus: Record<string, number>;
    pendingBySeverity: Record<string, number>;
    oldestPending: {
        id: string;
        repo: string;
        severity: Severity;
        detectedAt: string;
    } | null;
    topRepos: {
        repo: string;
        pending: number;
    }[];
}>;
/**
 * Compact the queue by removing resolved entries older than the retention period.
 * Never removes pending entries.
 */
export declare function compact(state: StateAdapter, opts?: {
    retentionDays?: number;
}): Promise<{
    before: number;
    after: number;
    removed: number;
    byStatus: Record<string, number>;
}>;
//# sourceMappingURL=state.d.ts.map