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

import type { CveQueueEntry, TriagePolicy, Severity } from "../types.js";
import { SEVERITY_ORDER, meetsThreshold } from "../types.js";

// ── Plan types ──────────────────────────────────────────────────────────────

export interface TriagePlan {
  entry: CveQueueEntry;
  action: "open_pr" | "open_draft" | "skip";
  reason: string;
}

// ── Public API ──────────────────────────────────────────────────────────────

export function triage(
  entries: CveQueueEntry[],
  policy: TriagePolicy,
): TriagePlan[] {
  // Sort by severity (CRITICAL first), then by score descending
  const sorted = [...entries]
    .filter((e) => e.status === "pending")
    .sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
        (b.cvssScore ?? 0) - (a.cvssScore ?? 0),
    );

  const plans: TriagePlan[] = [];
  let prCount = 0;

  for (const entry of sorted) {
    // Cap check
    if (prCount >= policy.maxPrsPerRun && meetsThreshold(entry.severity, policy.autoPrThreshold)) {
      plans.push({
        entry,
        action: "skip",
        reason: `PR cap reached (${policy.maxPrsPerRun} per run)`,
      });
      continue;
    }

    // No patched version
    if (policy.requirePatchedVersion && (!entry.patchedVersion || entry.patchedVersion === "unknown")) {
      plans.push({
        entry,
        action: "skip",
        reason: "No patched version available yet",
      });
      continue;
    }

    // Below auto-PR threshold
    if (!meetsThreshold(entry.severity, policy.autoPrThreshold)) {
      plans.push({
        entry,
        action: "skip",
        reason: `Severity ${entry.severity} below auto-PR threshold ${policy.autoPrThreshold}`,
      });
      continue;
    }

    // CRITICAL → confirmed PR, everything else at threshold → draft
    if (entry.severity === "CRITICAL") {
      plans.push({ entry, action: "open_pr", reason: "CRITICAL — immediate confirmed PR" });
      prCount++;
    } else {
      plans.push({ entry, action: "open_draft", reason: `${entry.severity} — draft PR for review` });
      prCount++;
    }
  }

  return plans;
}

/**
 * Default policy — can be overridden by config/policies.yaml
 */
export const DEFAULT_POLICY: TriagePolicy = {
  autoPrThreshold: "HIGH",
  draftThreshold: "HIGH",
  maxPrsPerRun: 5,
  requirePatchedVersion: true,
};
