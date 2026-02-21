/**
 * @git-fabric/cve — MCP Server
 *
 * Exposes the five fabric layers as MCP tools that Claude Desktop,
 * git-steer, or any MCP client can call.
 *
 * Tools:
 *   cve_scan       — Detection layer: scan repos for vulnerable deps
 *   cve_enrich     — Intelligence layer: fetch NVD details for a CVE
 *   cve_batch      — Intelligence layer: batch enrich + rank multiple CVEs
 *   cve_triage     — Decision + Action layers: process queue and open PRs
 *   cve_queue_list — State layer: list queue entries
 *   cve_queue_stats— State layer: queue health dashboard
 *   cve_queue_update— State layer: manually update entry status
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, } from "@modelcontextprotocol/sdk/types.js";
import { detection, intelligence, decision, action, state } from "../layers/index.js";
import { DEFAULT_POLICY } from "../layers/decision.js";
// ── Tool definitions ────────────────────────────────────────────────────────
const TOOLS = [
    {
        name: "cve_scan",
        description: "Scan managed repos for vulnerable dependencies via GitHub Advisory Database. " +
            "Appends findings to the CVE queue.",
        inputSchema: {
            type: "object",
            properties: {
                repos: { type: "array", items: { type: "string" }, description: "Repos to scan (owner/repo). Defaults to all managed repos." },
                severity_threshold: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default: "HIGH" },
                dry_run: { type: "boolean", default: false },
            },
        },
    },
    {
        name: "cve_enrich",
        description: "Fetch enriched vulnerability details for a CVE ID from NVD. " +
            "Returns severity, CVSS score, NVD status, CWE, and references.",
        inputSchema: {
            type: "object",
            properties: {
                cve_id: { type: "string", description: "CVE ID (e.g. CVE-2024-12345)" },
            },
            required: ["cve_id"],
        },
    },
    {
        name: "cve_batch",
        description: "Batch enrich and rank multiple CVEs by severity. " +
            "Returns a triage table sorted CRITICAL to LOW.",
        inputSchema: {
            type: "object",
            properties: {
                cve_ids: { type: "array", items: { type: "string" }, description: "Up to 20 CVE IDs" },
            },
            required: ["cve_ids"],
        },
    },
    {
        name: "cve_triage",
        description: "Process pending CVE queue entries: apply severity policy and open PRs. " +
            "CRITICAL = confirmed PR, HIGH = draft PR, MEDIUM/LOW = skip.",
        inputSchema: {
            type: "object",
            properties: {
                auto_pr_threshold: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default: "HIGH" },
                max_prs_per_run: { type: "number", default: 5 },
                require_patched_version: { type: "boolean", default: true },
                dry_run: { type: "boolean", default: false },
            },
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
    },
    {
        name: "cve_queue_stats",
        description: "Queue health dashboard: totals by status and severity, oldest pending, top repos.",
        inputSchema: {
            type: "object",
            properties: {},
        },
    },
    {
        name: "cve_queue_update",
        description: "Manually update status of a CVE queue entry (e.g. skip with reason).",
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
    },
];
// ── Server ──────────────────────────────────────────────────────────────────
export async function startServer(github, stateAdapter, managedRepos) {
    const server = new Server({ name: "@git-fabric/cve", version: "0.1.0" }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: TOOLS,
    }));
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
        const { name, arguments: args } = request.params;
        switch (name) {
            case "cve_scan": {
                const repos = args?.repos ?? managedRepos;
                const threshold = args?.severity_threshold ?? "HIGH";
                const dryRun = args?.dry_run ?? false;
                const result = await detection.detect(repos, threshold, github);
                if (!dryRun && result.findings.length > 0) {
                    const { added, duplicates } = await state.enqueue(result.findings, stateAdapter);
                    return { content: [{ type: "text", text: JSON.stringify({ ...result, queued: added, duplicates }, null, 2) }] };
                }
                return { content: [{ type: "text", text: JSON.stringify({ ...result, dry_run: dryRun }, null, 2) }] };
            }
            case "cve_enrich": {
                const cveId = args?.cve_id;
                const nvdKey = process.env.NVD_API_KEY;
                const result = await intelligence.enrich(cveId.toUpperCase(), nvdKey);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "cve_batch": {
                const cveIds = args?.cve_ids;
                const nvdKey = process.env.NVD_API_KEY;
                const results = await intelligence.enrichBatch(cveIds, nvdKey);
                return { content: [{ type: "text", text: JSON.stringify({ total: results.length, triage: results }, null, 2) }] };
            }
            case "cve_triage": {
                const dryRun = args?.dry_run ?? false;
                const policy = {
                    ...DEFAULT_POLICY,
                    autoPrThreshold: args?.auto_pr_threshold ?? DEFAULT_POLICY.autoPrThreshold,
                    maxPrsPerRun: args?.max_prs_per_run ?? DEFAULT_POLICY.maxPrsPerRun,
                    requirePatchedVersion: args?.require_patched_version ?? DEFAULT_POLICY.requirePatchedVersion,
                };
                const pendingEntries = await state.pending(stateAdapter);
                const plans = decision.triage(pendingEntries, policy);
                const results = await action.execute(plans, github, dryRun);
                // Update queue state
                if (!dryRun) {
                    const updates = results
                        .filter((r) => r.action !== "skipped" || plans.find((p) => p.entry.id === r.cveId)?.action === "skip")
                        .map((r) => ({
                        id: r.cveId,
                        repo: r.repo,
                        status: r.action === "pr_opened" ? "pr_opened" : r.action === "error" ? "error" : "skipped",
                        prNumber: r.prNumber,
                        prUrl: r.prUrl,
                        skipReason: r.reason,
                    }));
                    await state.update(updates, stateAdapter);
                }
                return {
                    content: [{
                            type: "text",
                            text: JSON.stringify({
                                processed: results.length,
                                prs_opened: results.filter((r) => r.action === "pr_opened").length,
                                skipped: results.filter((r) => r.action === "skipped").length,
                                errors: results.filter((r) => r.action === "error").length,
                                dry_run: dryRun,
                                results,
                            }, null, 2),
                        }],
                };
            }
            case "cve_queue_list": {
                const result = await state.list(stateAdapter, {
                    status: args?.status === "all" ? "all" : args?.status ?? "pending",
                    severityMin: args?.severity_min ?? "LOW",
                    repo: args?.repo,
                    limit: args?.limit ?? 50,
                });
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "cve_queue_stats": {
                const result = await state.stats(stateAdapter);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            case "cve_queue_update": {
                const result = await state.update([{
                        id: args?.id,
                        repo: args?.repo,
                        status: args?.status,
                        skipReason: args?.skip_reason,
                    }], stateAdapter);
                return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
            }
            default:
                throw new Error(`Unknown tool: ${name}`);
        }
    });
    const transport = new StdioServerTransport();
    await server.connect(transport);
}
//# sourceMappingURL=server.js.map