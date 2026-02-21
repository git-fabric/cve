/**
 * Intelligence Layer
 *
 * Enriches CVE data from the NVD API. Pure data transformation —
 * no side effects, no state mutations.
 *
 * Inputs:  CVE ID(s) + optional NVD API key
 * Outputs: CveEnrichment records with CVSS, NVD status, CWE, references
 */
import type { CveEnrichment } from "../types.js";
/**
 * Fetch and enrich a single CVE from the NVD.
 */
export declare function enrich(cveId: string, nvdApiKey?: string): Promise<CveEnrichment>;
/**
 * Batch enrich multiple CVEs with rate-limit-aware staggering.
 * Returns results sorted CRITICAL → LOW by score.
 */
export declare function enrichBatch(cveIds: string[], nvdApiKey?: string): Promise<(CveEnrichment & {
    error?: string;
})[]>;
//# sourceMappingURL=intelligence.d.ts.map