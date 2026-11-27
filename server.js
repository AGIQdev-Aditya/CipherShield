import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const brotliCompressAsync = promisify(zlib.brotliCompress);
const gzipAsync = promisify(zlib.gzip);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIST_DIR = path.resolve(__dirname, 'dist');
const PORT = Number(process.env.PORT) || 8080;

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
const compressedCache = new Map();

const SECURITY_HEADERS = {
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

async function getCompressedBody(filePath, rawBuffer, encoding) {
  const cacheKey = `${filePath}:${encoding}`;
  if (compressedCache.has(cacheKey)) {
    return compressedCache.get(cacheKey);
  }
  const out =
    encoding === 'br'
      ? await brotliCompressAsync(rawBuffer, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } })
      : await gzipAsync(rawBuffer);
  compressedCache.set(cacheKey, out);
  return out;
}

const server = http.createServer(async (req, res) => {
  const startedAt = Date.now();
  const traceHeader = req.headers['x-cloud-trace-context'];
  const traceId = typeof traceHeader === 'string' ? traceHeader.split('/')[0] : undefined;

  if (!req.url || (req.method !== 'GET' && req.method !== 'HEAD')) {
    res.writeHead(405, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain' });
    res.end('Method Not Allowed');
    return;
  }

  let decodedPath;
  try {
    decodedPath = decodeURIComponent(req.url.split('?')[0]);
  } catch {
    res.writeHead(400, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain' });
    res.end('Bad Request');
    return;
  }

  if (decodedPath === '/healthz') {
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    });
    res.end(JSON.stringify({ status: 'ok', service: 'ciphershield', egress: 'client-side-redaction' }));
    return;
  }

  const normalized = decodedPath.replace(/^\/+/, '');
  const candidate = normalized === '' ? 'index.html' : normalized;
  let filePath = path.resolve(DIST_DIR, candidate);
  const rel = path.relative(DIST_DIR, filePath);

  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    res.writeHead(403, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
  }

  let exists = true;
  try {
    const stat = await fs.promises.stat(filePath);
    if (stat.isDirectory()) {
      filePath = path.join(DIST_DIR, 'index.html');
    }
  } catch {
    exists = false;
  }

  if (!exists) {
    // Return genuine 404 for missing assets, dotfiles, or explicit extensions; SPA fallback only for client routes
    if (decodedPath.startsWith('/assets/') || path.extname(decodedPath) !== '' || decodedPath.includes('/.')) {
      res.writeHead(404, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }
    filePath = path.join(DIST_DIR, 'index.html');
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';
  const cacheControl = ext === '.html' ? 'no-cache' : 'public, max-age=31536000, immutable';
  const acceptEnc = String(req.headers['accept-encoding'] || '');

  try {
    const content = await fs.promises.readFile(filePath);

    if (COMPRESSIBLE_EXTS.has(ext) && content.length > 512) {
      if (acceptEnc.includes('br') && !acceptEnc.includes('br;q=0')) {
        const compressed = await getCompressedBody(filePath, content, 'br');
        res.writeHead(200, {
          ...SECURITY_HEADERS,
          'Content-Type': contentType,
          'Content-Encoding': 'br',
          Vary: 'Accept-Encoding',
          'Cache-Control': cacheControl,
        });
        res.end(req.method === 'HEAD' ? undefined : compressed);
        return;
      }

      if (acceptEnc.includes('gzip') && !acceptEnc.includes('gzip;q=0')) {
        const zipped = await getCompressedBody(filePath, content, 'gzip');
        res.writeHead(200, {
          ...SECURITY_HEADERS,
          'Content-Type': contentType,
          'Content-Encoding': 'gzip',
          Vary: 'Accept-Encoding',
          'Cache-Control': cacheControl,
        });
        res.end(req.method === 'HEAD' ? undefined : zipped);
        return;
      }
    }

    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'Content-Type': contentType,
      'Cache-Control': cacheControl,
    });
    res.end(req.method === 'HEAD' ? undefined : content);
  } catch (err) {
    logCloudJson('ERROR', 'Static asset read failure', {
      error: String(err),
      ...(traceId ? { 'logging.googleapis.com/trace': traceId } : {}),
    });
    res.writeHead(500, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain' });
    res.end('Internal Server Error');
  } finally {
    if (decodedPath === '/' || res.statusCode >= 400) {
      logCloudJson('INFO', 'HTTP request served', {
        httpRequest: {
          requestMethod: req.method,
          requestUrl: decodedPath,
          status: res.statusCode,
          latency: `${((Date.now() - startedAt) / 1000).toFixed(3)}s`,
        },
        ...(traceId ? { 'logging.googleapis.com/trace': traceId } : {}),
      });
    }
  }
});

server.headersTimeout = 10_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 65_000;

server.listen(PORT, '0.0.0.0', () => {
  logCloudJson('INFO', `CipherShield listening on http://0.0.0.0:${PORT}`, { port: PORT });
});

process.on('SIGTERM', () => {
  logCloudJson('INFO', 'Received SIGTERM, shutting down gracefully');
  server.close(() => {
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 8000).unref();
});
