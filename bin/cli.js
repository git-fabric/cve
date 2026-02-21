#!/usr/bin/env node

/**
 * @git-fabric/cve CLI
 *
 * Usage:
 *   fabric-cve start              # Start MCP server (stdio)
 *   fabric-cve scan [options]     # Run CVE scan
 *   fabric-cve triage [options]   # Run CVE triage
 *   fabric-cve queue [subcommand] # Queue operations
 *   fabric-cve enrich <cve-id>    # Enrich a single CVE from NVD
 */

import { Command } from "commander";

const program = new Command();

program
  .name("fabric-cve")
  .description("CVE detection-to-remediation fabric app")
  .version("0.1.0");

// ── start ───────────────────────────────────────────────────────────────────

program
  .command("start")
  .description("Start the MCP server (stdio transport)")
  .action(async () => {
    // Dynamic import to avoid loading everything for --help
    const { startServer } = await import("../dist/mcp/server.js");
    const { createAdaptersFromEnv } = await import("../dist/adapters/env.js");
    const { github, state, repos } = await createAdaptersFromEnv();
    await startServer(github, state, repos);
  });

// ── scan ────────────────────────────────────────────────────────────────────

program
  .command("scan")
  .description("Scan managed repos for vulnerable dependencies")
  .option("--severity-threshold <level>", "Minimum severity (CRITICAL/HIGH/MEDIUM/LOW)", "HIGH")
  .option("--repos <repos>", "Comma-separated repos to scan")
  .option("--dry-run <bool>", "Report without writing to queue", "false")
  .action(async (opts) => {
    const { detection, state: stateLayer } = await import("../dist/layers/index.js");
    const { createAdaptersFromEnv } = await import("../dist/adapters/env.js");
    const { github, state, repos: managedRepos } = await createAdaptersFromEnv();

    const repos = opts.repos ? opts.repos.split(",").map((r) => r.trim()) : managedRepos;
    const dryRun = opts.dryRun === "true";

    console.log(`Scanning ${repos.length} repos at ${opts.severityThreshold} threshold...`);
    const result = await detection.detect(repos, opts.severityThreshold, github);

    if (!dryRun && result.findings.length > 0) {
      const { added, duplicates } = await stateLayer.enqueue(result.findings, state);
      console.log(`Findings: ${result.findings.length} | Queued: ${added} | Duplicates: ${duplicates}`);
    } else {
      console.log(`Findings: ${result.findings.length} (dry run: ${dryRun})`);
    }

    console.log(`By severity:`, result.bySeverity);
  });

// ── triage ──────────────────────────────────────────────────────────────────

program
  .command("triage")
  .description("Process pending CVE queue entries and open PRs")
  .option("--auto-pr-threshold <level>", "Auto-PR severity threshold", "HIGH")
  .option("--draft-threshold <level>", "Draft PR threshold", "HIGH")
  .option("--max-prs-per-run <n>", "Max PRs per run", "5")
  .option("--require-patched-version <bool>", "Skip if no patch available", "true")
  .option("--dry-run <bool>", "Simulate without opening PRs", "false")
  .action(async (opts) => {
    const { decision, action, state: stateLayer } = await import("../dist/layers/index.js");
    const { DEFAULT_POLICY } = await import("../dist/layers/decision.js");
    const { createAdaptersFromEnv } = await import("../dist/adapters/env.js");
    const { github, state } = await createAdaptersFromEnv();

    const dryRun = opts.dryRun === "true";
    const policy = {
      ...DEFAULT_POLICY,
      autoPrThreshold: opts.autoPrThreshold,
      maxPrsPerRun: parseInt(opts.maxPrsPerRun, 10),
      requirePatchedVersion: opts.requirePatchedVersion === "true",
    };

    const pending = await stateLayer.pending(state);
    console.log(`Pending entries: ${pending.length}`);

    const plans = decision.triage(pending, policy);
    const results = await action.execute(plans, github, dryRun);

    if (!dryRun) {
      const updates = results.map((r) => ({
        id: r.cveId,
        repo: r.repo,
        status: r.action === "pr_opened" ? "pr_opened" : r.action === "error" ? "error" : "skipped",
        prNumber: r.prNumber,
        prUrl: r.prUrl,
        skipReason: r.reason,
      }));
      await stateLayer.update(updates, state);
    }

    const opened = results.filter((r) => r.action === "pr_opened").length;
    const skipped = results.filter((r) => r.action === "skipped").length;
    const errors = results.filter((r) => r.action === "error").length;
    console.log(`PRs opened: ${opened} | Skipped: ${skipped} | Errors: ${errors}`);
  });

// ── queue ───────────────────────────────────────────────────────────────────

const queue = program
  .command("queue")
  .description("CVE queue operations");

queue
  .command("list")
  .description("List queue entries")
  .option("--status <status>", "Filter by status", "pending")
  .option("--severity <level>", "Minimum severity", "LOW")
  .option("--repo <repo>", "Filter to a specific repo")
  .action(async (opts) => {
    const { state: stateLayer } = await import("../dist/layers/index.js");
    const { createAdaptersFromEnv } = await import("../dist/adapters/env.js");
    const { state } = await createAdaptersFromEnv();

    const result = await stateLayer.list(state, {
      status: opts.status,
      severityMin: opts.severity,
      repo: opts.repo,
    });
    console.log(JSON.stringify(result, null, 2));
  });

queue
  .command("stats")
  .description("Queue health dashboard")
  .action(async () => {
    const { state: stateLayer } = await import("../dist/layers/index.js");
    const { createAdaptersFromEnv } = await import("../dist/adapters/env.js");
    const { state } = await createAdaptersFromEnv();

    const result = await stateLayer.stats(state);
    console.log(JSON.stringify(result, null, 2));
  });

// ── enrich ──────────────────────────────────────────────────────────────────

program
  .command("enrich <cveId>")
  .description("Fetch enriched details for a CVE from NVD")
  .action(async (cveId) => {
    const { intelligence } = await import("../dist/layers/index.js");
    const result = await intelligence.enrich(cveId.toUpperCase(), process.env.NVD_API_KEY);
    console.log(JSON.stringify(result, null, 2));
  });

program.parse();
