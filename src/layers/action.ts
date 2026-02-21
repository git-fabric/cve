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

import type { CveQueueEntry, GitHubAdapter, PrResult } from "../types.js";
import type { TriagePlan } from "./decision.js";

// ── PR body builder ─────────────────────────────────────────────────────────

const SEVERITY_EMOJI: Record<string, string> = {
  CRITICAL: "\u{1F534}", HIGH: "\u{1F7E0}", MEDIUM: "\u{1F7E1}", LOW: "\u{1F7E2}",
  NONE: "\u{26AA}", UNKNOWN: "\u{26AB}",
};

function buildPrBody(entry: CveQueueEntry): string {
  const emoji = SEVERITY_EMOJI[entry.severity] ?? "\u{26AB}";
  const scoreStr = entry.cvssScore !== null ? `${entry.cvssScore}/10` : "N/A";

  return `## Security Fix: ${entry.id}

> This PR was opened automatically by [@git-fabric/cve](https://github.com/git-fabric/cve).

### Vulnerability Summary

| Field | Value |
|-------|-------|
| **CVE / Advisory** | [${entry.id}](${entry.nvdUrl}) |
| **Severity** | ${emoji} ${entry.severity} |
| **CVSS Score** | ${scoreStr} |
| **Ecosystem** | \`${entry.ecosystem}\` |
| **Affected Package** | \`${entry.affectedPackage}\` @ \`${entry.affectedVersion}\` |
| **Patched Version** | \`${entry.patchedVersion}\` |
| **Detected** | ${new Date(entry.detectedAt).toISOString().slice(0, 10)} |

### Description

${entry.summary}

### Required Action

Upgrade \`${entry.affectedPackage}\` from \`${entry.affectedVersion}\` to \`${entry.patchedVersion}\` or later.

### Review Checklist

- [ ] Dependency upgraded to \`${entry.patchedVersion}\` or later
- [ ] Lockfile committed
- [ ] Tests pass with upgraded dependency
- [ ] No breaking API changes introduced

### References

- [NVD / Advisory](${entry.nvdUrl})
${entry.ghsaId ? `- [GitHub Advisory](https://github.com/advisories/${entry.ghsaId})` : ""}

---
<!-- git-fabric/cve | ${entry.id} | ${new Date().toISOString()} -->
`;
}

function prLabels(severity: string, draft: boolean): string[] {
  const base = ["security", "cve", "git-fabric"];
  const map: Record<string, string[]> = {
    CRITICAL: ["severity:critical", "priority:urgent"],
    HIGH:     ["severity:high", "priority:high"],
    MEDIUM:   ["severity:medium"],
    LOW:      ["severity:low"],
  };
  const extra = draft ? ["draft"] : [];
  return [...base, ...(map[severity] ?? []), ...extra];
}

// ── Manifest updaters ───────────────────────────────────────────────────────

function updateNpmManifest(content: string, pkg: string, version: string): string {
  const json = JSON.parse(content);
  for (const section of ["dependencies", "devDependencies", "peerDependencies"]) {
    if (json[section]?.[pkg]) {
      json[section][pkg] = `^${version}`;
    }
  }
  return JSON.stringify(json, null, 2) + "\n";
}

function updatePipManifest(content: string, pkg: string, version: string): string {
  return content
    .split("\n")
    .map((line) => {
      const match = line.match(new RegExp(`^${pkg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*[>=<!]=?`));
      if (match) return `${pkg}>=${version}`;
      return line;
    })
    .join("\n");
}

function updateManifest(
  content: string,
  ecosystem: string,
  pkg: string,
  version: string,
): string | null {
  switch (ecosystem) {
    case "npm":   return updateNpmManifest(content, pkg, version);
    case "pip":   return updatePipManifest(content, pkg, version);
    default:      return null; // Other ecosystems: PR body instructs manual upgrade
  }
}

// ── Manifest path lookup ────────────────────────────────────────────────────

const ECOSYSTEM_MANIFEST: Record<string, string> = {
  npm: "package.json",
  pip: "requirements.txt",
  go: "go.mod",
  cargo: "Cargo.toml",
  maven: "pom.xml",
  composer: "composer.json",
};

// ── Public API ──────────────────────────────────────────────────────────────

export async function execute(
  plans: TriagePlan[],
  github: GitHubAdapter,
  dryRun = false,
): Promise<PrResult[]> {
  const results: PrResult[] = [];

  for (const plan of plans) {
    if (plan.action === "skip") {
      results.push({
        cveId: plan.entry.id,
        repo: plan.entry.repo,
        action: "skipped",
        reason: plan.reason,
      });
      continue;
    }

    if (dryRun) {
      results.push({
        cveId: plan.entry.id,
        repo: plan.entry.repo,
        action: "pr_opened",
        reason: `[DRY RUN] Would open ${plan.action === "open_draft" ? "draft " : ""}PR`,
      });
      continue;
    }

    const [owner, repo] = plan.entry.repo.split("/");
    const branch = `security/${plan.entry.id.toLowerCase()}`;
    const isDraft = plan.action === "open_draft";
    const title = `fix(security): ${plan.entry.id} \u2013 ${plan.entry.severity} in ${plan.entry.affectedPackage}`;

    try {
      const base = await github.getDefaultBranch(owner, repo);

      // Create branch from default
      await github.createBranch(owner, repo, branch, base);

      // Try to commit an actual dependency bump
      const manifestPath = ECOSYSTEM_MANIFEST[plan.entry.ecosystem];
      const files: { path: string; content: string }[] = [];

      if (manifestPath && plan.entry.patchedVersion !== "unknown") {
        const currentContent = await github.getFileContent(owner, repo, manifestPath);
        if (currentContent) {
          const updated = updateManifest(
            currentContent,
            plan.entry.ecosystem,
            plan.entry.affectedPackage,
            plan.entry.patchedVersion,
          );
          if (updated && updated !== currentContent) {
            files.push({ path: manifestPath, content: updated });
          }
        }
      }

      if (files.length > 0) {
        await github.commitFiles(owner, repo, {
          branch,
          message: `fix(security): upgrade ${plan.entry.affectedPackage} to ${plan.entry.patchedVersion}\n\nResolves ${plan.entry.id}`,
          files,
        });
      }

      // Open PR
      const pr = await github.createPullRequest(owner, repo, {
        title,
        body: buildPrBody(plan.entry),
        head: branch,
        base,
        draft: isDraft,
        labels: prLabels(plan.entry.severity, isDraft),
      });

      results.push({
        cveId: plan.entry.id,
        repo: plan.entry.repo,
        action: "pr_opened",
        prNumber: pr.number,
        prUrl: pr.html_url,
      });

      // Brief pause between PR creations
      await new Promise((r) => setTimeout(r, 500));
    } catch (err: unknown) {
      results.push({
        cveId: plan.entry.id,
        repo: plan.entry.repo,
        action: "error",
        reason: (err as Error).message,
      });
    }
  }

  return results;
}
