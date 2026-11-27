import type http from 'node:http';

export declare const DEFAULT_DIST_DIR: string;
export declare const SECURITY_HEADERS: Record<string, string>;
export declare function resolveStaticFile(
  distDir: string,
  decodedPath: string,
): Promise<{ status: number; filePath: string | null }>;
export declare function createAppServer(options?: {
  distDir?: string;
  enableRequestLogs?: boolean;
}): http.Server;
