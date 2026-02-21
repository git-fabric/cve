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

import { Octokit } from "octokit";
import { throttling } from "@octokit/plugin-throttling";
import { retry } from "@octokit/plugin-retry";
import type { GitHubAdapter, StateAdapter } from "../types.js";

const HardenedOctokit = Octokit.plugin(throttling, retry);

export async function createAdaptersFromEnv(): Promise<{
  github: GitHubAdapter;
  state: StateAdapter;
  repos: string[];
}> {
  const token = process.env.GITHUB_TOKEN ?? process.env.GIT_STEER_TOKEN;
  if (!token) throw new Error("GITHUB_TOKEN or GIT_STEER_TOKEN required");

  const stateRepo = process.env.STATE_REPO;
  if (!stateRepo) throw new Error("STATE_REPO required (e.g. ry-ops/git-steer-state)");

  const repos = (process.env.MANAGED_REPOS ?? "")
    .split(",")
    .map((r) => r.trim())
    .filter(Boolean);

  const [stateOwner, stateRepoName] = stateRepo.split("/");
  const octokit = new HardenedOctokit({
    auth: token,
    throttle: {
      onRateLimit: (retryAfter: number, options: any, _octokit: any, retryCount: number) => {
        console.warn(`[git-fabric/cve] Rate limit hit for ${options.method} ${options.url} — retry ${retryCount + 1}/4 after ${retryAfter}s`);
        return retryCount < 4;
      },
      onSecondaryRateLimit: (retryAfter: number, options: any) => {
        console.warn(`[git-fabric/cve] Secondary rate limit for ${options.method} ${options.url} — backoff ${retryAfter}s`);
        return true;
      },
    },
    retry: { doNotRetry: ["429"] },
  });

  // ── GitHub adapter ──────────────────────────────────────────────────────

  const github: GitHubAdapter = {
    token,

    async getFileContent(owner, repo, path) {
      try {
        const { data } = await octokit.rest.repos.getContent({ owner, repo, path });
        if ("content" in data && data.content) {
          return Buffer.from(data.content, "base64").toString("utf-8");
        }
        return null;
      } catch {
        return null;
      }
    },

    async createBranch(owner, repo, branch, fromBranch) {
      const { data: ref } = await octokit.rest.git.getRef({
        owner, repo, ref: `heads/${fromBranch}`,
      });
      await octokit.rest.git.createRef({
        owner, repo, ref: `refs/heads/${branch}`, sha: ref.object.sha,
      });
    },

    async commitFiles(owner, repo, opts) {
      // Get current commit SHA on the branch
      const { data: ref } = await octokit.rest.git.getRef({
        owner, repo, ref: `heads/${opts.branch}`,
      });
      const parentSha = ref.object.sha;

      // Get the tree of the parent commit
      const { data: parentCommit } = await octokit.rest.git.getCommit({
        owner, repo, commit_sha: parentSha,
      });

      // Create blobs for each file
      const treeItems = await Promise.all(
        opts.files.map(async (f) => {
          const { data: blob } = await octokit.rest.git.createBlob({
            owner, repo, content: Buffer.from(f.content).toString("base64"), encoding: "base64",
          });
          return { path: f.path, mode: "100644" as const, type: "blob" as const, sha: blob.sha };
        }),
      );

      // Create tree
      const { data: tree } = await octokit.rest.git.createTree({
        owner, repo, base_tree: parentCommit.tree.sha, tree: treeItems,
      });

      // Create commit
      const { data: commit } = await octokit.rest.git.createCommit({
        owner, repo, message: opts.message, tree: tree.sha, parents: [parentSha],
      });

      // Update branch ref
      await octokit.rest.git.updateRef({
        owner, repo, ref: `heads/${opts.branch}`, sha: commit.sha,
      });

      return { sha: commit.sha, url: commit.html_url };
    },

    async createPullRequest(owner, repo, opts) {
      // Ensure labels exist
      for (const label of opts.labels) {
        try {
          await octokit.rest.issues.createLabel({
            owner, repo, name: label,
            color: label.startsWith("severity:critical") ? "B60205"
              : label.startsWith("severity:high") ? "D93F0B"
              : label.startsWith("severity:medium") ? "FBCA04"
              : label.startsWith("severity:low") ? "0E8A16"
              : "1D76DB",
          });
        } catch {
          // label already exists
        }
      }

      const { data: pr } = await octokit.rest.pulls.create({
        owner, repo, title: opts.title, body: opts.body,
        head: opts.head, base: opts.base, draft: opts.draft,
      });

      // Add labels
      await octokit.rest.issues.addLabels({
        owner, repo, issue_number: pr.number, labels: opts.labels,
      });

      return { number: pr.number, html_url: pr.html_url };
    },

    async getDefaultBranch(owner, repo) {
      const { data } = await octokit.rest.repos.get({ owner, repo });
      return data.default_branch;
    },
  };

  // ── State adapter (reads/writes to state repo via GitHub API) ───────────

  const stateAdapter: StateAdapter = {
    async read(file) {
      return github.getFileContent(stateOwner, stateRepoName, file);
    },

    async write(file, content) {
      // Get current SHA if file exists
      let sha: string | undefined;
      try {
        const { data } = await octokit.rest.repos.getContent({
          owner: stateOwner, repo: stateRepoName, path: file,
        });
        if ("sha" in data) sha = data.sha;
      } catch {
        // file doesn't exist yet
      }

      await octokit.rest.repos.createOrUpdateFileContents({
        owner: stateOwner,
        repo: stateRepoName,
        path: file,
        message: `chore(cve): update ${file}`,
        content: Buffer.from(content).toString("base64"),
        ...(sha ? { sha } : {}),
      });
    },

    async append(file, lines) {
      const existing = await this.read(file);
      const newContent = existing
        ? existing + "\n" + lines.join("\n")
        : lines.join("\n");
      await this.write(file, newContent);
    },
  };

  return { github, state: stateAdapter, repos };
}
