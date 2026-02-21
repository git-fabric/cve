/**
 * Intelligence Layer
 *
 * Enriches CVE data from the NVD API. Pure data transformation —
 * no side effects, no state mutations.
 *
 * Inputs:  CVE ID(s) + optional NVD API key
 * Outputs: CveEnrichment records with CVSS, NVD status, CWE, references
 */
// ── NVD API ─────────────────────────────────────────────────────────────────
const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
function extractCvss(item) {
    const v31 = item.metrics?.cvssMetricV31?.[0]?.cvssData;
    const v30 = item.metrics?.cvssMetricV30?.[0]?.cvssData;
    const v2 = item.metrics?.cvssMetricV2?.[0];
    if (v31)
        return { score: v31.baseScore, severity: v31.baseSeverity };
    if (v30)
        return { score: v30.baseScore, severity: v30.baseSeverity };
    if (v2)
        return { score: v2.cvssData.baseScore, severity: v2.baseSeverity };
    return { score: null, severity: "UNKNOWN" };
}
// ── Public API ──────────────────────────────────────────────────────────────
/**
 * Fetch and enrich a single CVE from the NVD.
 */
export async function enrich(cveId, nvdApiKey) {
    const headers = { "User-Agent": "git-fabric-cve/0.1" };
    if (nvdApiKey)
        headers["apiKey"] = nvdApiKey;
    const url = `${NVD_API}?cveId=${encodeURIComponent(cveId)}`;
    const res = await fetch(url, { headers });
    if (res.status === 404)
        throw new Error(`CVE ${cveId} not found in NVD`);
    if (res.status === 403)
        throw new Error("NVD rate limited — provide an API key or wait");
    if (!res.ok)
        throw new Error(`NVD API error: ${res.status}`);
    const data = await res.json();
    const item = data.vulnerabilities?.[0]?.cve;
    if (!item)
        throw new Error(`No data returned for ${cveId}`);
    const { score, severity } = extractCvss(item);
    return {
        id: item.id,
        status: item.vulnStatus,
        severity: severity,
        score,
        description: item.descriptions.find((d) => d.lang === "en")?.value ?? "No description available.",
        published: item.published,
        references: item.references.slice(0, 5).map((r) => r.url),
        cwe: item.weaknesses?.[0]?.description?.find((d) => d.lang === "en")?.value ?? null,
    };
}
/**
 * Batch enrich multiple CVEs with rate-limit-aware staggering.
 * Returns results sorted CRITICAL → LOW by score.
 */
export async function enrichBatch(cveIds, nvdApiKey) {
    const delay = nvdApiKey ? 100 : 700;
    const results = [];
    for (const id of cveIds) {
        try {
            results.push(await enrich(id.toUpperCase(), nvdApiKey));
        }
        catch (e) {
            results.push({
                id: id.toUpperCase(),
                status: "ERROR",
                severity: "UNKNOWN",
                score: null,
                description: e.message,
                published: "",
                references: [],
                cwe: null,
                error: e.message,
            });
        }
        if (cveIds.indexOf(id) < cveIds.length - 1) {
            await new Promise((r) => setTimeout(r, delay));
        }
    }
    const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"];
    results.sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity) ||
        (b.score ?? 0) - (a.score ?? 0));
    return results;
}
//# sourceMappingURL=intelligence.js.map