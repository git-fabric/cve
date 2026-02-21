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
import type { GitHubAdapter, StateAdapter } from "../types.js";
export declare function startServer(github: GitHubAdapter, stateAdapter: StateAdapter, managedRepos: string[]): Promise<void>;
//# sourceMappingURL=server.d.ts.map