import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const brotliCompressAsync = promisify(zlib.brotliCompress);
const gzipAsync = promisify(zlib.gzip);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_DIST_DIR = path.resolve(__dirname, 'dist');
const DEFAULT_PORT = Number(process.env.PORT) || 8080;
const MAX_COMPRESSED_CACHE_ENTRIES = 128;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.ico': 'image/x-icon',
};

const COMPRESSIBLE_EXTS = new Set(['.html', '.js', '.css', '.svg', '.json', '.txt']);

/**
 * Production security response headers matching vercel.json CSP and OWASP baseline.
 */
export const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "font-src 'self' data:",
    "img-src 'self' data:",
    "connect-src 'self' https://generativelanguage.googleapis.com",
    "worker-src 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-src 'none'",
    "frame-ancestors 'none'",
  ].join('; '),
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), geolocation=(), microphone=(), payment=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

function logCloudJson(severity, message, extra = {}) {
  process.stdout.write(
    `${JSON.stringify({ severity, message, service: 'ciphershield', timestamp: new Date().toISOString(), ...extra })}\n`,
  );
}

function sendText(res, statusCode, body) {
  res.writeHead(statusCode, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(body);
}

function sendHealthz(res, method) {
  res.writeHead(200, {
    ...SECURITY_HEADERS,
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  const payload = JSON.stringify({ status: 'ok', service: 'ciphershield', egress: 'client-side-redaction' });
  res.end(method === 'HEAD' ? undefined : payload);
}

/**
 * Resolves a requested URL path safely within distDir, enforcing genuine 404s for missing assets.
 */
export async function resolveStaticFile(distDir, decodedPath) {
  const normalized = decodedPath.replace(/^\/+/, '');
  const candidate = normalized === '' ? 'index.html' : normalized;
  let filePath = path.resolve(distDir, candidate);
  const rel = path.relative(distDir, filePath);

  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    return { status: 403, filePath: null };
  }

  try {
    const stat = await fs.promises.stat(filePath);
    if (stat.isDirectory()) {
      filePath = path.join(distDir, 'index.html');
    }
    return { status: 200, filePath };
  } catch {
    if (decodedPath.startsWith('/assets/') || path.extname(decodedPath) !== '' || decodedPath.includes('/.')) {
      return { status: 404, filePath: null };
    }
    return { status: 200, filePath: path.join(distDir, 'index.html') };
  }
}

function selectPreferredEncoding(acceptEncHeader, ext, contentLength) {
  if (!COMPRESSIBLE_EXTS.has(ext) || contentLength <= 512) {
    return null;
  }
  const acceptEnc = String(acceptEncHeader || '');
  if (acceptEnc.includes('br') && !acceptEnc.includes('br;q=0')) return 'br';
  if (acceptEnc.includes('gzip') && !acceptEnc.includes('gzip;q=0')) return 'gzip';
  return null;
}

/**
 * Compresses asset buffers once with a bounded in-memory LRU cache to keep static delivery flat-latency.
 */
async function getCompressedBody(cache, filePath, rawBuffer, encoding) {
  const cacheKey = `${filePath}:${encoding}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  const compressed =
    encoding === 'br'
      ? await brotliCompressAsync(rawBuffer, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } })
      : await gzipAsync(rawBuffer);

  if (cache.size >= MAX_COMPRESSED_CACHE_ENTRIES) {
    const oldestKey = cache.keys().next().value;
    if (oldestKey !== undefined) cache.delete(oldestKey);
  }
  cache.set(cacheKey, compressed);
  return compressed;
}

async function serveAssetResponse({
  req,
  res,
  resolvedFilePath,
  compressedCache,
}) {
  const ext = path.extname(resolvedFilePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';
  const cacheControl = ext === '.html' ? 'no-cache' : 'public, max-age=31536000, immutable';
  const rawContent = await fs.promises.readFile(resolvedFilePath);
  const encoding = selectPreferredEncoding(req.headers['accept-encoding'], ext, rawContent.length);
  const body = encoding ? await getCompressedBody(compressedCache, resolvedFilePath, rawContent, encoding) : rawContent;

  res.writeHead(200, {
    ...SECURITY_HEADERS,
    'Content-Type': contentType,
    'Cache-Control': cacheControl,
    ...(encoding ? { 'Content-Encoding': encoding, Vary: 'Accept-Encoding' } : {}),
  });
  res.end(req.method === 'HEAD' ? undefined : body);
}

function decodeSafeRequestPath(rawUrl) {
  try {
    return decodeURIComponent((rawUrl.split('?')[0] ?? '/'));
  } catch {
    return null;
  }
}

function logHttpRequestIfNeeded({ enableRequestLogs, decodedPath, method, statusCode, startedAt, traceId }) {
  if (!enableRequestLogs || (decodedPath !== '/' && statusCode < 400)) return;
  logCloudJson('INFO', 'HTTP request served', {
    httpRequest: {
      requestMethod: method,
      requestUrl: decodedPath,
      status: statusCode,
      latency: `${((Date.now() - startedAt) / 1000).toFixed(3)}s`,
    },
    ...(traceId ? { 'logging.googleapis.com/trace': traceId } : {}),
  });
}

async function handleIncomingRequest({ req, res, distDir, compressedCache, enableRequestLogs }) {
  const startedAt = Date.now();
  const traceHeader = req.headers['x-cloud-trace-context'];
  const traceId = typeof traceHeader === 'string' ? traceHeader.split('/')[0] : undefined;

  if (!req.url || (req.method !== 'GET' && req.method !== 'HEAD')) {
    sendText(res, 405, 'Method Not Allowed');
    return;
  }

  const decodedPath = decodeSafeRequestPath(req.url);
  if (decodedPath === null) {
    sendText(res, 400, 'Bad Request');
    return;
  }
  if (decodedPath === '/healthz') {
    sendHealthz(res, req.method);
    return;
  }

  const resolved = await resolveStaticFile(distDir, decodedPath);
  if (resolved.status === 403 || !resolved.filePath) {
    sendText(res, resolved.status === 403 ? 403 : 404, resolved.status === 403 ? 'Forbidden' : 'Not Found');
    return;
  }

  try {
    await serveAssetResponse({ req, res, resolvedFilePath: resolved.filePath, compressedCache });
  } catch (err) {
    if (enableRequestLogs) {
      logCloudJson('ERROR', 'Static asset read failure', {
        error: String(err),
        ...(traceId ? { 'logging.googleapis.com/trace': traceId } : {}),
      });
    }
    sendText(res, 500, 'Internal Server Error');
  } finally {
    logHttpRequestIfNeeded({
      enableRequestLogs,
      decodedPath,
      method: req.method,
      statusCode: res.statusCode,
      startedAt,
      traceId,
    });
  }
}

/**
 * Creates a stateless HTTP server serving prebuilt Vite assets for Cloud Run or Node production.
 */
export function createAppServer({ distDir = DEFAULT_DIST_DIR, enableRequestLogs = true } = {}) {
  const compressedCache = new Map();
  const server = http.createServer((req, res) =>
    handleIncomingRequest({ req, res, distDir, compressedCache, enableRequestLogs }),
  );

  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 65_000;
  return server;
}

const isMainEntrypoint =
  Boolean(process.argv[1]) && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMainEntrypoint) {
  const server = createAppServer();
  server.listen(DEFAULT_PORT, '0.0.0.0', () => {
    logCloudJson('INFO', `CipherShield listening on http://0.0.0.0:${DEFAULT_PORT}`, { port: DEFAULT_PORT });
  });

  process.on('SIGTERM', () => {
    logCloudJson('INFO', 'Received SIGTERM, shutting down gracefully');
    server.close(() => {
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 8000).unref();
  });
}
