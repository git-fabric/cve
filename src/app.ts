/**
 * @git-fabric/cve — App factory
 *
 * Creates a FabricApp for gateway consumption.
 * The gateway calls createApp() to register this app.
 */

import { createAdaptersFromEnv } from "./adapters/env.js";
import { detection, intelligence, decision, action, state } from "./layers/index.js";
import { DEFAULT_POLICY } from "./layers/decision.js";
import type { Severity, GitHubAdapter, StateAdapter } from "./types.js";

interface FabricTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  execute: (args: Record<string, unknown>) => Promise<unknown>;
}

interface FabricApp {
  name: string;
  version: string;
  description: string;
  tools: FabricTool[];
  health: () => Promise<{ app: string; status: "healthy" | "degraded" | "unavailable"; details?: Record<string, unknown> }>;
}

export async function createApp(): Promise<FabricApp> {
  const { github, state: stateAdapter, repos: managedRepos } = await createAdaptersFromEnv();

  function buildTools(gh: GitHubAdapter, sa: StateAdapter, defaultRepos: string[]): FabricTool[] {
    return [
      {
        name: "cve_scan",
        description: "Scan managed repos for vulnerable dependencies via GitHub Advisory Database. Appends findings to the CVE queue.",
        inputSchema: {
          type: "object",
          properties: {
            repos: { type: "array", items: { type: "string" }, description: "Repos to scan (owner/repo). Defaults to all managed repos." },
            severity_threshold: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default: "HIGH" },
            dry_run: { type: "boolean", default: false },
          },
        },
        async execute(args) {
          const repos = (args.repos as string[]) ?? defaultRepos;
          const threshold = (args.severity_threshold as Severity) ?? "HIGH";
          const dryRun = (args.dry_run as boolean) ?? false;

          const result = await detection.detect(repos, threshold, gh);

          if (!dryRun && result.findings.length > 0) {
            const { added, duplicates } = await state.enqueue(result.findings, sa);
            return JSON.stringify({ ...result, queued: added, duplicates }, null, 2);
          }
          return JSON.stringify({ ...result, dry_run: dryRun }, null, 2);
        },
      },
      {
        name: "cve_enrich",
        description: "Fetch enriched vulnerability details for a CVE ID from NVD.",
        inputSchema: {
          type: "object",
          properties: { cve_id: { type: "string", description: "CVE ID (e.g. CVE-2024-12345)" } },
          required: ["cve_id"],
        },
        async execute(args) {
          const cveId = (args.cve_id as string).toUpperCase();
          const result = await intelligence.enrich(cveId, process.env.NVD_API_KEY);
          return JSON.stringify(result, null, 2);
        },
      },
      {
        name: "cve_batch",
        description: "Batch enrich and rank multiple CVEs by severity.",
        inputSchema: {
          type: "object",
          properties: { cve_ids: { type: "array", items: { type: "string" }, description: "Up to 20 CVE IDs" } },
          required: ["cve_ids"],
        },
        async execute(args) {
          const results = await intelligence.enrichBatch(args.cve_ids as string[], process.env.NVD_API_KEY);
          return JSON.stringify({ total: results.length, triage: results }, null, 2);
        },
      },
      {
        name: "cve_triage",
        description: "Process pending CVE queue entries: apply severity policy and open PRs.",
        inputSchema: {
          type: "object",
          properties: {
            auto_pr_threshold: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default: "HIGH" },
            max_prs_per_run: { type: "number", default: 5 },
            require_patched_version: { type: "boolean", default: true },
            dry_run: { type: "boolean", default: false },
          },
        },
        async execute(args) {
          const dryRun = (args.dry_run as boolean) ?? false;
          const policy = {
            ...DEFAULT_POLICY,
            autoPrThreshold: (args.auto_pr_threshold as Severity) ?? DEFAULT_POLICY.autoPrThreshold,
            maxPrsPerRun: (args.max_prs_per_run as number) ?? DEFAULT_POLICY.maxPrsPerRun,
            requirePatchedVersion: (args.require_patched_version as boolean) ?? DEFAULT_POLICY.requirePatchedVersion,
          };

          const pendingEntries = await state.pending(sa);
          const plans = decision.triage(pendingEntries, policy);
          const results = await action.execute(plans, gh, dryRun);

          if (!dryRun) {
            const updates = results.map((r) => ({
              id: r.cveId,
              repo: r.repo,
              status: r.action === "pr_opened" ? "pr_opened" as const : r.action === "error" ? "error" as const : "skipped" as const,
              prNumber: r.prNumber,
              prUrl: r.prUrl,
              skipReason: r.reason,
            }));
            await state.update(updates, sa);
          }

          return JSON.stringify({
            processed: results.length,
            prs_opened: results.filter((r) => r.action === "pr_opened").length,
            skipped: results.filter((r) => r.action === "skipped").length,
            errors: results.filter((r) => r.action === "error").length,
            dry_run: dryRun,
            results,
          }, null, 2);
        },
      },
      {
        name: "cve_queue_list",
        description: "List CVE queue entries filtered by status and severity.",
        inputSchema: {
          type: "object",
          properties: {
            status: { type: "string", enum: ["pending", "pr_opened", "skipped", "error", "all"], default: "pending" },
            severity_min: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default: "LOW" },
            repo: { type: "string", description: "Filter to a specific repo" },
            limit: { type: "number", default: 50 },
          },
        },
        async execute(args) {
          const result = await state.list(sa, {
            status: (args.status as string) === "all" ? "all" : (args.status as "pending") ?? "pending",
            severityMin: (args.severity_min as Severity) ?? "LOW",
            repo: args.repo as string | undefined,
            limit: (args.limit as number) ?? 50,
          });
          return JSON.stringify(result, null, 2);
        },
      },
      {
        name: "cve_queue_stats",
        description: "Queue health dashboard: totals by status and severity, oldest pending, top repos.",
        inputSchema: { type: "object", properties: {} },
        async execute() {
          return JSON.stringify(await state.stats(sa), null, 2);
        },
      },
      {
        name: "cve_queue_update",
        description: "Manually update status of a CVE queue entry.",
        inputSchema: {
          type: "object",
          properties: {
            id: { type: "string", description: "CVE or GHSA ID" },
            repo: { type: "string", description: "owner/repo" },
            status: { type: "string", enum: ["pending", "pr_opened", "skipped", "error"] },
            skip_reason: { type: "string" },
          },
          required: ["id", "repo", "status"],
        },
        async execute(args) {
          const result = await state.update(
            [{ id: args.id as string, repo: args.repo as string, status: args.status as "pending" | "pr_opened" | "skipped" | "error", skipReason: args.skip_reason as string | undefined }],
            sa,
          );
          return JSON.stringify(result, null, 2);
        },
      },
      {
        name: "cve_compact",
        description: "Compact the CVE queue by removing resolved entries older than the retention period.",
        inputSchema: {
          type: "object",
          properties: {
            retention_days: { type: "number", description: "Days to retain resolved entries (default: 30)", default: 30 },
          },
        },
        async execute(args) {
          const result = await state.compact(sa, { retentionDays: (args.retention_days as number) ?? 30 });
          return JSON.stringify(result, null, 2);
        },
      },
    ];
  }

  return {
    name: "@git-fabric/cve",
    version: "0.1.0",
    description: "CVE detection-to-remediation fabric app. Scan, enrich, triage, and fix vulnerabilities across managed repos.",
    tools: buildTools(github, stateAdapter, managedRepos),
    async health() {
      try {
        // Validate token by checking rate limit
        const res = await fetch("https://api.github.com/rate_limit", {
          headers: { Authorization: `bearer ${github.token}`, "User-Agent": "git-fabric-cve/0.1.0" },
        });
        if (!res.ok) return { app: "@git-fabric/cve", status: "unavailable" as const, details: { error: "Token invalid" } };

        // Validate state repo access
        const content = await stateAdapter.read("state/cve-queue.jsonl");
        return {
          app: "@git-fabric/cve",
          status: "healthy" as const,
          details: { stateRepo: process.env.STATE_REPO, queueExists: content !== null },
        };
      } catch (err: unknown) {
        return { app: "@git-fabric/cve", status: "degraded" as const, details: { error: (err as Error).message } };
      }
    },
  };
}
