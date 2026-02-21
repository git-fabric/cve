/**
 * Detection Layer
 *
 * Ingests dependency manifests from managed repos, queries the GitHub
 * Advisory Database (GHSA) via GraphQL, and produces CveQueueEntry
 * records for downstream layers.
 *
 * Inputs:  repo list + GitHub token
 * Outputs: CveQueueEntry[] (not yet persisted — that's the State layer's job)
 */
import { normalizeSeverity, SEVERITY_ORDER } from "../types.js";
// ── Manifest parsers ────────────────────────────────────────────────────────
function parseNpm(content) {
    try {
        const pkg = JSON.parse(content);
        return { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies };
    }
    catch {
        return {};
    }
}
function parsePip(content) {
    const deps = {};
    for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#"))
            continue;
        const match = trimmed.match(/^([A-Za-z0-9_\-.]+)\s*[>=<!]=?\s*(.+?)(?:\s*#.*)?$/);
        if (match)
            deps[match[1]] = match[2].trim();
        else {
            const nameOnly = trimmed.match(/^([A-Za-z0-9_\-.]+)/);
            if (nameOnly)
                deps[nameOnly[1]] = "unknown";
        }
    }
    return deps;
}
function parseGo(content) {
    const deps = {};
    for (const line of content.split("\n")) {
        const match = line.trim().match(/^require\s+(\S+)\s+(\S+)/) ||
            line.trim().match(/^\s+(\S+)\s+(v[\d.]+)/);
        if (match)
            deps[match[1]] = match[2];
    }
    return deps;
}
function parseCargo(content) {
    const deps = {};
    let inDeps = false;
    for (const line of content.split("\n")) {
        if (line.match(/^\[(?:dev-)?dependencies\]/)) {
            inDeps = true;
            continue;
        }
        if (line.startsWith("[") && !line.match(/^\[(?:dev-)?dependencies\]/)) {
            inDeps = false;
        }
        if (!inDeps)
            continue;
        const match = line.match(/^(\S+)\s*=\s*"([^"]+)"/);
        if (match)
            deps[match[1]] = match[2];
    }
    return deps;
}
function parseManifest(manifest) {
    switch (manifest.ecosystem) {
        case "npm": return parseNpm(manifest.content);
        case "pip": return parsePip(manifest.content);
        case "go": return parseGo(manifest.content);
        case "cargo": return parseCargo(manifest.content);
        default: return {};
    }
}
// ── GHSA GraphQL query ──────────────────────────────────────────────────────
const ECOSYSTEM_MAP = {
    npm: "NPM", pip: "PIP", go: "GO", maven: "MAVEN", cargo: "RUST", composer: "COMPOSER",
};
async function queryGhsa(ecosystem, packageName, token) {
    const query = `
    query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
      securityVulnerabilities(
        ecosystem: $ecosystem, package: $package,
        first: 10, orderBy: { field: UPDATED_AT, direction: DESC }
      ) {
        nodes {
          advisory { ghsaId cveId summary severity cvss { score } }
          package { ecosystem name }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
  `;
    const res = await fetch("https://api.github.com/graphql", {
        method: "POST",
        headers: {
            Authorization: `bearer ${token}`,
            "Content-Type": "application/json",
            "User-Agent": "git-fabric-cve/0.1",
        },
        body: JSON.stringify({
            query,
            variables: {
                ecosystem: ECOSYSTEM_MAP[ecosystem] ?? ecosystem.toUpperCase(),
                package: packageName,
            },
        }),
    });
    if (!res.ok)
        return [];
    const data = await res.json();
    const nodes = data?.data?.securityVulnerabilities?.nodes ?? [];
    return nodes.map((n) => ({
        ghsaId: n.advisory.ghsaId,
        cveId: n.advisory.cveId ?? null,
        summary: n.advisory.summary,
        severity: n.advisory.severity,
        cvssScore: n.advisory.cvss?.score ?? null,
        package: n.package,
        vulnerableVersionRange: n.vulnerableVersionRange,
        firstPatchedVersion: n.firstPatchedVersion?.identifier ?? null,
    }));
}
// ── Manifest discovery ──────────────────────────────────────────────────────
const MANIFEST_PATHS = [
    { path: "package.json", ecosystem: "npm" },
    { path: "requirements.txt", ecosystem: "pip" },
    { path: "go.mod", ecosystem: "go" },
    { path: "Cargo.toml", ecosystem: "cargo" },
    { path: "pom.xml", ecosystem: "maven" },
    { path: "composer.json", ecosystem: "composer" },
];
export async function detect(repos, severityThreshold, github) {
    const thresholdIdx = SEVERITY_ORDER.indexOf(severityThreshold);
    const allFindings = [];
    const seen = new Set();
    for (const repoFull of repos) {
        const [owner, repo] = repoFull.split("/");
        const manifests = [];
        for (const { path, ecosystem } of MANIFEST_PATHS) {
            const content = await github.getFileContent(owner, repo, path);
            if (content)
                manifests.push({ path, ecosystem, content });
        }
        if (manifests.length === 0)
            continue;
        for (const manifest of manifests) {
            const deps = parseManifest(manifest);
            for (const [pkgName, pkgVersion] of Object.entries(deps)) {
                if (!pkgName || pkgName.startsWith("//"))
                    continue;
                const advisories = await queryGhsa(manifest.ecosystem, pkgName, github.token);
                await new Promise((r) => setTimeout(r, 150));
                for (const adv of advisories) {
                    const severity = normalizeSeverity(adv.severity);
                    if (SEVERITY_ORDER.indexOf(severity) > thresholdIdx)
                        continue;
                    const dedupeKey = `${adv.cveId ?? adv.ghsaId}::${repoFull}`;
                    if (seen.has(dedupeKey))
                        continue;
                    seen.add(dedupeKey);
                    allFindings.push({
                        id: adv.cveId ?? adv.ghsaId,
                        ghsaId: adv.ghsaId,
                        repo: repoFull,
                        ecosystem: manifest.ecosystem,
                        affectedPackage: pkgName,
                        affectedVersion: pkgVersion,
                        patchedVersion: adv.firstPatchedVersion ?? "unknown",
                        severity,
                        cvssScore: adv.cvssScore,
                        summary: adv.summary,
                        nvdUrl: adv.cveId
                            ? `https://nvd.nist.gov/vuln/detail/${adv.cveId}`
                            : `https://github.com/advisories/${adv.ghsaId}`,
                        detectedAt: new Date().toISOString(),
                        status: "pending",
                    });
                }
            }
        }
    }
    const bySeverity = {};
    for (const s of SEVERITY_ORDER) {
        bySeverity[s] = allFindings.filter((f) => f.severity === s).length;
    }
    return { reposScanned: repos.length, findings: allFindings, bySeverity };
}
//# sourceMappingURL=detection.js.map