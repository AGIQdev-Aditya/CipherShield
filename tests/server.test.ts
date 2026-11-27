// @vitest-environment node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createAppServer, SECURITY_HEADERS } from '../server.js';

describe('Cloud Run Production Static Server (server.js)', () => {
  let tmpDist = '';
  let baseUrl = '';
  let server: ReturnType<typeof createAppServer>;

  beforeAll(async () => {
    tmpDist = fs.mkdtempSync(path.join(os.tmpdir(), 'ciphershield-srv-'));
    fs.mkdirSync(path.join(tmpDist, 'assets'), { recursive: true });
    fs.writeFileSync(path.join(tmpDist, 'index.html'), '<!doctype html><html><body>CipherShield</body></html>');
    fs.writeFileSync(
      path.join(tmpDist, 'assets', 'app.js'),
      `console.log("ok");\n${'// padded compressible content\n'.repeat(30)}`,
    );

    server = createAppServer({ distDir: tmpDist, enableRequestLogs: false });
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const address = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(tmpDist, { recursive: true, force: true });
  });

  it('responds to /healthz with 200 OK and strict OWASP / CSP security headers', async () => {
    const res = await fetch(`${baseUrl}/healthz`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-security-policy')).toBe(SECURITY_HEADERS['Content-Security-Policy']);
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('cross-origin-opener-policy')).toBe('same-origin');
    const json = (await res.json()) as { status: string; service: string };
    expect(json.status).toBe('ok');
    expect(json.service).toBe('ciphershield');
  });

  it('serves immutable hashed assets with gzip/brotli negotiation and returns 404 for missing assets', async () => {
    const hit = await fetch(`${baseUrl}/assets/app.js`, { headers: { 'Accept-Encoding': 'br, gzip' } });
    expect(hit.status).toBe(200);
    expect(hit.headers.get('cache-control')).toContain('immutable');
    expect(hit.headers.get('content-encoding')).toBe('br');

    const miss = await fetch(`${baseUrl}/assets/does-not-exist.js`);
    expect(miss.status).toBe(404);
  });

  it('blocks path traversal attempts with 403 and rejects POST with 405 Method Not Allowed', async () => {
    const traversal = await fetch(`${baseUrl}/..%2fpackage.json`);
    expect(traversal.status).toBe(403);

    const postRes = await fetch(`${baseUrl}/healthz`, { method: 'POST' });
    expect(postRes.status).toBe(405);
  });
});
