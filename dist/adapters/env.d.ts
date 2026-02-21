/**
 * Environment adapter
 *
 * Creates GitHubAdapter and StateAdapter from environment variables.
 * Used by the CLI and Actions workflows.
 *
 * Required env vars:
 *   GITHUB_TOKEN or GIT_STEER_TOKEN  — GitHub API access
 *   STATE_REPO                        — owner/repo for state storage (e.g. ry-ops/git-steer-state)
 *   MANAGED_REPOS                     — comma-separated list of repos to manage
 *
 * Optional:
 *   NVD_API_KEY — raises NVD rate limit from 5 to 50 req/30s
 */
import type { GitHubAdapter, StateAdapter } from "../types.js";
export declare function createAdaptersFromEnv(): Promise<{
    github: GitHubAdapter;
    state: StateAdapter;
    repos: string[];
}>;
//# sourceMappingURL=env.d.ts.map