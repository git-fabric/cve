/**
 * State Layer
 *
 * Manages the CVE queue (state/cve-queue.jsonl) with append-only
 * semantics and last-write-wins deduplication.
 *
 * Also provides queue health stats for dashboards and digest reports.
 *
 * Inputs:  StateAdapter (provided by consumer — git-steer, Actions, etc.)
 * Outputs: Queue reads, writes, and stats
 */
import { SEVERITY_ORDER } from "../types.js";
const QUEUE_FILE = "state/cve-queue.jsonl";
// ── Queue parsing ───────────────────────────────────────────────────────────
function parseQueue(raw) {
    const map = new Map();
    for (const line of raw.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed)
            continue;
        try {
            const entry = JSON.parse(trimmed);
            map.set(`${entry.id}::${entry.repo}`, entry);
        }
        catch {
            // skip malformed lines
        }
    }
    return map;
}
function serialize(map) {
    return Array.from(map.values())
        .map((e) => JSON.stringify(e))
        .join("\n");
}
// ── Public API ──────────────────────────────────────────────────────────────
/**
 * Append new findings to the queue. Deduplicates by id+repo.
 */
export async function enqueue(entries, state) {
    const raw = await state.read(QUEUE_FILE);
    const existing = parseQueue(raw ?? "");
    let added = 0;
    let duplicates = 0;
    for (const entry of entries) {
        const key = `${entry.id}::${entry.repo}`;
        if (existing.has(key)) {
            duplicates++;
        }
        else {
            existing.set(key, entry);
            added++;
        }
    }
    await state.write(QUEUE_FILE, serialize(existing));
    return { added, duplicates };
}
/**
 * List queue entries with filtering.
 */
export async function list(state, opts = {}) {
    const raw = await state.read(QUEUE_FILE);
    if (!raw)
        return { total: 0, entries: [] };
    const queue = parseQueue(raw);
    const status = opts.status ?? "pending";
    const thresholdIdx = SEVERITY_ORDER.indexOf(opts.severityMin ?? "LOW");
    const limit = opts.limit ?? 50;
    let entries = Array.from(queue.values()).filter((e) => {
        if (status !== "all" && e.status !== status)
            return false;
        if (opts.repo && e.repo !== opts.repo)
            return false;
        if (SEVERITY_ORDER.indexOf(e.severity) > thresholdIdx)
            return false;
        return true;
    });
    entries.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
        (b.cvssScore ?? 0) - (a.cvssScore ?? 0));
    return { total: entries.length, entries: entries.slice(0, limit) };
}
/**
 * Update status of queue entries (after action layer executes).
 */
export async function update(updates, state) {
    const raw = await state.read(QUEUE_FILE);
    const queue = parseQueue(raw ?? "");
    const processedAt = new Date().toISOString();
    let updated = 0;
    let notFound = 0;
    for (const u of updates) {
        const key = `${u.id}::${u.repo}`;
        const existing = queue.get(key);
        if (!existing) {
            notFound++;
            continue;
        }
        queue.set(key, {
            ...existing,
            status: u.status,
            prNumber: u.prNumber ?? existing.prNumber,
            prUrl: u.prUrl ?? existing.prUrl,
            skipReason: u.skipReason ?? existing.skipReason,
            processedAt,
        });
        updated++;
    }
    await state.write(QUEUE_FILE, serialize(queue));
    return { updated, notFound };
}
/**
 * Get all pending entries (for the decision layer).
 */
export async function pending(state) {
    const { entries } = await list(state, { status: "pending", limit: 1000 });
    return entries;
}
/**
 * Queue health stats.
 */
export async function stats(state) {
    const raw = await state.read(QUEUE_FILE);
    if (!raw)
        return { total: 0, byStatus: {}, pendingBySeverity: {}, oldestPending: null, topRepos: [] };
    const entries = Array.from(parseQueue(raw).values());
    const byStatus = entries.reduce((acc, e) => ({ ...acc, [e.status]: (acc[e.status] ?? 0) + 1 }), {});
    const pendingEntries = entries.filter((e) => e.status === "pending");
    const pendingBySeverity = {};
    for (const s of SEVERITY_ORDER) {
        pendingBySeverity[s] = pendingEntries.filter((e) => e.severity === s).length;
    }
    const oldest = pendingEntries
        .sort((a, b) => new Date(a.detectedAt).getTime() - new Date(b.detectedAt).getTime())[0];
    const byRepo = pendingEntries.reduce((acc, e) => ({ ...acc, [e.repo]: (acc[e.repo] ?? 0) + 1 }), {});
    const topRepos = Object.entries(byRepo)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 10)
        .map(([repo, count]) => ({ repo, pending: count }));
    return {
        total: entries.length,
        byStatus,
        pendingBySeverity,
        oldestPending: oldest
            ? { id: oldest.id, repo: oldest.repo, severity: oldest.severity, detectedAt: oldest.detectedAt }
            : null,
        topRepos,
    };
}
/**
 * Compact the queue by removing resolved entries older than the retention period.
 * Never removes pending entries.
 */
export async function compact(state, opts = {}) {
    const raw = await state.read(QUEUE_FILE);
    if (!raw)
        return { before: 0, after: 0, removed: 0, byStatus: {} };
    const queue = parseQueue(raw);
    const before = queue.size;
    const retentionMs = (opts.retentionDays ?? 30) * 86400000;
    const cutoff = Date.now() - retentionMs;
    const removedByStatus = {};
    for (const [key, entry] of queue) {
        if (entry.status === "pending")
            continue;
        const ts = entry.processedAt ?? entry.detectedAt;
        if (ts && new Date(ts).getTime() < cutoff) {
            removedByStatus[entry.status] = (removedByStatus[entry.status] ?? 0) + 1;
            queue.delete(key);
        }
    }
    const removed = before - queue.size;
    if (removed > 0) {
        await state.write(QUEUE_FILE, serialize(queue));
    }
    return { before, after: queue.size, removed, byStatus: removedByStatus };
}
//# sourceMappingURL=state.js.map