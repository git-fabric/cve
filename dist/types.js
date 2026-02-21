/**
 * @git-fabric/cve — shared types
 *
 * All layers import from here. No circular dependencies.
 */
export const SEVERITY_ORDER = [
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN",
];
export function normalizeSeverity(s) {
    const upper = s?.toUpperCase();
    return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"].includes(upper)
        ? upper
        : "UNKNOWN";
}
export function meetsThreshold(severity, threshold) {
    return SEVERITY_ORDER.indexOf(severity) <= SEVERITY_ORDER.indexOf(threshold);
}
//# sourceMappingURL=types.js.map