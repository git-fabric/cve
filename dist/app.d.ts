/**
 * @git-fabric/cve — App factory
 *
 * Creates a FabricApp for gateway consumption.
 * The gateway calls createApp() to register this app.
 */
interface FabricTool {
    name: string;
    description: string;
    inputSchema: Record<string, unknown>;
    execute: (args: Record<string, unknown>) => Promise<unknown>;
}
interface FabricApp {
    name: string;
    version: string;
    description: string;
    tools: FabricTool[];
    health: () => Promise<{
        app: string;
        status: "healthy" | "degraded" | "unavailable";
        details?: Record<string, unknown>;
    }>;
}
export declare function createApp(): Promise<FabricApp>;
export {};
//# sourceMappingURL=app.d.ts.map