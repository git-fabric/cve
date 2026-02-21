/**
 * Decision Layer
 *
 * Applies severity policy to pending queue entries and decides
 * what action to take: open PR, open draft PR, or skip.
 *
 * Pure logic — no GitHub API calls, no state writes.
 * Returns a plan that the Action layer executes.
 *
 * Inputs:  CveQueueEntry[] + TriagePolicy
 * Outputs: TriagePlan[] (what to do with each entry)
 */
import type { CveQueueEntry, TriagePolicy } from "../types.js";
export interface TriagePlan {
    entry: CveQueueEntry;
    action: "open_pr" | "open_draft" | "skip";
    reason: string;
}
export declare function triage(entries: CveQueueEntry[], policy: TriagePolicy): TriagePlan[];
/**
 * Default policy — can be overridden by config/policies.yaml
 */
export declare const DEFAULT_POLICY: TriagePolicy;
//# sourceMappingURL=decision.d.ts.map