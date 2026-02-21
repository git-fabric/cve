/**
 * Action Layer
 *
 * Executes triage plans: creates branches, commits dependency upgrades,
 * and opens PRs. This is the layer that actually touches GitHub.
 *
 * Fixes the "PR has no code" gap from the original design —
 * every PR gets a real branch with a real commit.
 *
 * Inputs:  TriagePlan[] + GitHubAdapter
 * Outputs: PrResult[]
 */
import type { GitHubAdapter, PrResult } from "../types.js";
import type { TriagePlan } from "./decision.js";
export declare function execute(plans: TriagePlan[], github: GitHubAdapter, dryRun?: boolean): Promise<PrResult[]>;
//# sourceMappingURL=action.d.ts.map