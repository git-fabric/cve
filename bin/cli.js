#!/usr/bin/env node

/**
 * @git-fabric/cve CLI
 *
 * Usage:
 *   fabric-cve start              # Start MCP server (stdio or HTTP)
 *   fabric-cve scan [options]     # Run CVE scan
 *   fabric-cve triage [options]   # Run CVE triage
 *   fabric-cve queue [subcommand] # Queue operations
 *   fabric-cve enrich <cve-id>    # Enrich a single CVE from NVD
 *
 * Environment:
 *   MCP_HTTP_PORT    — If set, start HTTP server instead of stdio
 *   GATEWAY_URL      — Gateway registration endpoint
 *   POD_IP           — Pod IP for gateway mcp_endpoint (default: 0.0.0.0)
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
  .description("Start the MCP server (stdio or HTTP with gateway registration)")
  .action(async () => {
    const { createApp } = await import("../dist/app.js");
    const { Library } = await import("../dist/library.js");
    const { Server } = await import("@modelcontextprotocol/sdk/server/index.js");
    const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
    const { StreamableHTTPServerTransport } = await import("@modelcontextprotocol/sdk/server/streamableHttp.js");
    const { ListToolsRequestSchema, CallToolRequestSchema } = await import("@modelcontextprotocol/sdk/types.js");
    const { createServer } = await import("node:http");

    const app = await createApp();
    const library = new Library();

    function buildServer() {
      const server = new Server({ name: app.name, version: app.version }, { capabilities: { tools: {} } });
      server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: app.tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
      }));
      server.setRequestHandler(CallToolRequestSchema, async (req) => {
        const tool = app.tools.find((t) => t.name === req.params.name);
        if (!tool) return { content: [{ type: "text", text: `Unknown tool: ${req.params.name}` }], isError: true };
        try {
          const result = await tool.execute(req.params.arguments ?? {});
          return { content: [{ type: "text", text: typeof result === "string" ? result : JSON.stringify(result, null, 2) }] };
        } catch (e) {
          return { content: [{ type: "text", text: String(e) }], isError: true };
        }
      });
      return server;
    }

    // ── Gateway registration ──────────────────────────────────────────────

    const GATEWAY_URL = process.env.GATEWAY_URL;
    const MCP_HTTP_PORT = process.env.MCP_HTTP_PORT ? Number(process.env.MCP_HTTP_PORT) : null;
    const POD_IP = process.env.POD_IP || "0.0.0.0";

    let sessionToken = null;

    async function registerWithGateway() {
      if (!GATEWAY_URL) return;
      const mcpEndpoint = `http://${POD_IP}:${MCP_HTTP_PORT || 8200}/mcp`;
      const body = {
        fabric_id: "fabric-cve",
        as_number: 65009,
        version: app.version,
        mcp_endpoint: mcpEndpoint,
        ollama_endpoint: process.env.OLLAMA_ENDPOINT || "http://ollama.fabric-sdk:11434",
        ollama_model: process.env.OLLAMA_MODEL || "qwen2.5-coder:3b",
        supervisor: "standalone",
        tailscale_node: "fabric-cve",
        worker_pool: { total: 0, healthy: 0, workers: [] },
        routes: [
          { prefix: "fabric.cve", local_pref: 100, description: "CVE detection, enrichment, triage, and remediation" },
          { prefix: "fabric.cve.scan", local_pref: 100, description: "Vulnerability scanning — repo dependency analysis via GHSA" },
          { prefix: "fabric.cve.enrich", local_pref: 100, description: "CVE enrichment — NVD details, CVSS, CWE, references" },
          { prefix: "fabric.cve.triage", local_pref: 100, description: "Triage — severity policy, auto-PR, queue processing" },
          { prefix: "fabric.cve.queue", local_pref: 100, description: "Queue management — list, stats, update, compact" },
          { prefix: "fabric.security.vulnerabilities", local_pref: 100, description: "Vulnerability intelligence across managed repos" },
        ],
      };
      try {
        const res = await fetch(`${GATEWAY_URL}/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        const data = await res.json();
        if (data.ok) { sessionToken = data.session_token; console.log(`[fabric-cve] Registered with gateway: ${sessionToken} (${data.routes_accepted} routes)`); }
        else console.warn(`[fabric-cve] Registration rejected: ${JSON.stringify(data)}`);
      } catch (err) { console.warn(`[fabric-cve] Gateway registration failed (standalone mode): ${err.message}`); }
    }

    async function sendKeepalive() {
      if (!GATEWAY_URL || !sessionToken) return;
      try {
        const res = await fetch(`${GATEWAY_URL}/keepalive`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ fabric_id: "fabric-cve", session_token: sessionToken, worker_pool: { total: 0, healthy: 0, workers: [] }, timestamp: Math.floor(Date.now() / 1000) }) });
        if (res.status === 401) { console.log("[fabric-cve] Session expired — re-registering"); sessionToken = null; await registerWithGateway(); }
      } catch {}
    }

    // ── Server startup ────────────────────────────────────────────────────

    const httpPort = MCP_HTTP_PORT;

    if (httpPort) {
      const httpServer = createServer(async (req, res) => {
        if (req.url === "/healthz" || req.url === "/health") {
          const h = await app.health();
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(h));
          return;
        }
        if (req.url === "/tools") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(app.tools.map((t) => ({ name: t.name, description: t.description }))));
          return;
        }
        if ((req.url === "/mcp/tools/call" || req.url === "/tools/call") && req.method === "POST") {
          const chunks = [];
          for await (const chunk of req) chunks.push(chunk);
          const body = JSON.parse(Buffer.concat(chunks).toString());

          // Handle aiana_query — gateway DNS resolver asks for context
          //
          // Two knowledge sources, checked in order:
          //   1. Live CVE tools (deterministic) — real-time queue state, scan results
          //   2. Library (reference) — NVD docs, GHSA format, OSV schema
          //
          // Live tools answer "what IS the CVE state" — library answers "how to" and "why"
          if (body.name === "aiana_query") {
            const queryText = (body.arguments?.query_text || "").toLowerCase();
            try {
              let context = "";
              let confidence = 0;
              let source = "cve-api";

              // ── Live CVE queries (real-time state) ──────────────────
              if (/\b(active|pending|open|current)\b.*\b(cve|vulnerabilit|alert|finding)s?\b/.test(queryText) ||
                  /\b(cve|vulnerabilit|alert|finding)s?\b.*\b(active|pending|open|current)\b/.test(queryText)) {
                const stats = await app.tools.find(t => t.name === "cve_queue_stats")?.execute({});
                const pending = await app.tools.find(t => t.name === "cve_queue_list")?.execute({ status: "pending", limit: 20 });
                context = `Queue Stats:\n${stats}\n\nPending Entries:\n${pending}`;
                confidence = 0.95;
              } else if (/\b(triage|status|queue|dashboard)\b/.test(queryText) && !queryText.includes("how")) {
                const stats = await app.tools.find(t => t.name === "cve_queue_stats")?.execute({});
                context = typeof stats === "string" ? stats : JSON.stringify(stats, null, 2);
                confidence = 0.9;
              } else if (/\b(scan|detect|check)\b.*\b(result|finding|vuln)s?\b/.test(queryText) && !queryText.includes("how")) {
                const list = await app.tools.find(t => t.name === "cve_queue_list")?.execute({ status: "all", limit: 30 });
                context = typeof list === "string" ? list : JSON.stringify(list, null, 2);
                confidence = 0.85;
              } else if (/\b(critical|high|severe)\b.*\b(cve|vulnerabilit|issue)s?\b/.test(queryText)) {
                const list = await app.tools.find(t => t.name === "cve_queue_list")?.execute({ severity_min: "CRITICAL", status: "all", limit: 20 });
                context = typeof list === "string" ? list : JSON.stringify(list, null, 2);
                confidence = 0.9;
              } else if (/\b(pr|pull request|fix|remediat|patch)\b/.test(queryText) && !queryText.includes("how")) {
                const list = await app.tools.find(t => t.name === "cve_queue_list")?.execute({ status: "pr_opened", limit: 20 });
                context = typeof list === "string" ? list : JSON.stringify(list, null, 2);
                confidence = 0.85;
              } else if (/\b(error|fail|broken)\b/.test(queryText)) {
                const list = await app.tools.find(t => t.name === "cve_queue_list")?.execute({ status: "error", limit: 20 });
                context = typeof list === "string" ? list : JSON.stringify(list, null, 2);
                confidence = 0.85;
              } else if (/\b(health|connectivity|api)\b/.test(queryText) && !queryText.includes("how")) {
                const health = await app.health();
                context = JSON.stringify(health, null, 2);
                confidence = 0.9;
              } else {
                // ── Library queries (reference docs) ──────────────────────
                const libraryResult = await library.query(queryText);
                if (libraryResult && libraryResult.context) {
                  context = libraryResult.context;
                  confidence = libraryResult.confidence;
                  source = "library";
                  console.log(`[fabric-cve] Library hit: ${libraryResult.sources.join(", ")}`);
                } else {
                  // Nothing in library — return queue stats as fallback
                  const stats = await app.tools.find(t => t.name === "cve_queue_stats")?.execute({});
                  context = typeof stats === "string" ? stats : JSON.stringify(stats, null, 2);
                  confidence = 0.5;
                }
              }

              res.writeHead(200, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ context, confidence, source }));
            } catch (err) {
              res.writeHead(200, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ context: `Error querying CVE: ${err.message}`, confidence: 0 }));
            }
            return;
          }

          const tool = app.tools.find((t) => t.name === body.name);
          if (!tool) { res.writeHead(404, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: `Tool not found: ${body.name}` })); return; }
          try {
            const result = await tool.execute(body.arguments ?? {});
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(typeof result === "string" ? result : JSON.stringify(result));
          } catch (err) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err.message }));
          }
          return;
        }
        if (req.url === "/mcp" || req.url === "/") {
          const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
          const server = buildServer();
          await server.connect(transport);
          await transport.handleRequest(req, res, undefined);
          return;
        }
        res.writeHead(404).end("not found");
      });

      httpServer.listen(httpPort, () => {
        console.log(`[fabric-cve] ${app.name} v${app.version} — ${app.tools.length} tools`);
        console.log(`[fabric-cve] MCP server listening on :${httpPort}`);
        console.log(`[fabric-cve] Endpoints: /health /tools /tools/call /mcp/tools/call /mcp`);
      });

      await registerWithGateway();
      if (GATEWAY_URL) setInterval(sendKeepalive, 30_000);
    } else {
      // stdio mode — original behavior
      const transport = new StdioServerTransport();
      const server = buildServer();
      await server.connect(transport);
    }
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
