import assert from 'assert';
import { test, describe, before, after } from 'node:test';
import express from 'express';
import http from 'http';
import { authRouter } from '../routes/authRoutes.js';
import { assetRouter } from '../routes/assetRoutes.js';
import { platformRouter } from '../routes/platformRoutes.js';
import { siemRouter } from '../routes/siemRoutes.js';
import { threatRouter } from '../routes/threatRoutes.js';
import { authenticateJwt } from '../middleware/auth.js';

describe('SOC Platform End-to-End HTTP API Integration Suite', () => {
  let server: http.Server;
  let baseUrl: string;
  let adminToken: string;
  let viewerToken: string;

  before(async () => {
    process.env.JWT_SECRET = 'cybermind_test_secret_for_unit_tests_12345';
    process.env.PLATFORM_MODE = 'DEMO';

    const app = express();
    app.use(express.json());

    // Health Probes
    app.get('/health/live', (_req, res) => {
      res.status(200).json({ status: 'UP', uptimeSeconds: 42 });
    });
    app.get('/health/ready', (_req, res) => {
      res.status(200).json({ status: 'READY' });
    });

    // Routers
    app.use('/api/auth', authRouter);
    app.use('/api/platform', platformRouter);
    app.use('/api/assets', authenticateJwt, assetRouter);
    app.use('/api/siem', authenticateJwt, siemRouter);
    app.use('/api/threats', authenticateJwt, threatRouter);

    await new Promise<void>((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        const addr = server.address() as any;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  describe('1. Health & Liveness Probes', () => {
    test('GET /health/live returns HTTP 200 and UP status', async () => {
      const res = await fetch(`${baseUrl}/health/live`);
      assert.strictEqual(res.status, 200);
      const data = (await res.json()) as any;
      assert.strictEqual(data.status, 'UP');
    });

    test('GET /health/ready returns HTTP 200 and READY status', async () => {
      const res = await fetch(`${baseUrl}/health/ready`);
      assert.strictEqual(res.status, 200);
      const data = (await res.json()) as any;
      assert.strictEqual(data.status, 'READY');
    });
  });

  describe('2. Authentication & Identity Store Flow', () => {
    test('POST /api/auth/login with invalid credentials fails with 401', async () => {
      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'WrongPassword123!' }),
      });
      assert.strictEqual(res.status, 401);
      const data = (await res.json()) as any;
      assert.strictEqual(data.code, 'AUTH_INVALID_CREDENTIALS');
    });

    test('POST /api/auth/login with missing fields fails with 400', async () => {
      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin' }),
      });
      assert.strictEqual(res.status, 400);
    });

    test('POST /api/auth/login succeeds for Admin and returns verifiable JWT', async () => {
      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'Admin@CyberMind2026!' }),
      });
      assert.strictEqual(res.status, 200);
      const data = (await res.json()) as any;
      assert.ok(data.token && typeof data.token === 'string');
      assert.strictEqual(data.user.role, 'Admin');
      adminToken = data.token;
    });

    test('POST /api/auth/login succeeds for Viewer', async () => {
      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'viewer', password: 'Viewer@CyberMind2026!' }),
      });
      assert.strictEqual(res.status, 200);
      const data = (await res.json()) as any;
      assert.strictEqual(data.user.role, 'Viewer');
      viewerToken = data.token;
    });
  });

  describe('3. Protected Endpoints & RBAC Enforcement', () => {
    test('GET /api/assets rejects request without Authorization header (401)', async () => {
      const res = await fetch(`${baseUrl}/api/assets`);
      assert.strictEqual(res.status, 401);
    });

    test('GET /api/assets rejects invalid Bearer token (401)', async () => {
      const res = await fetch(`${baseUrl}/api/assets`, {
        headers: { Authorization: 'Bearer forged.or.malformed.token' },
      });
      assert.strictEqual(res.status, 401);
    });

    test('GET /api/assets permits authenticated Admin request (200)', async () => {
      const res = await fetch(`${baseUrl}/api/assets`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.strictEqual(res.status, 200);
      const data = (await res.json()) as any;
      assert.ok(Array.isArray(data.assets));
    });

    test('POST /api/assets rejects Viewer with 403 Forbidden', async () => {
      const res = await fetch(`${baseUrl}/api/assets`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${viewerToken}`,
        },
        body: JSON.stringify({ hostname: 'test-host', ip_address: '10.0.0.99' }),
      });
      assert.strictEqual(res.status, 403);
    });

    test('POST /api/assets allows Admin to register asset (201)', async () => {
      const res = await fetch(`${baseUrl}/api/assets`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${adminToken}`,
        },
        body: JSON.stringify({ hostname: 'corp-e2e-node', ip_address: '10.0.0.105' }),
      });
      assert.strictEqual(res.status, 201);
      const data = (await res.json()) as any;
      assert.strictEqual(data.asset.hostname, 'corp-e2e-node');
    });
  });

  describe('4. SIEM Event Query & Pagination API', () => {
    test('GET /api/siem/events returns unpaginated collection by default', async () => {
      const res = await fetch(`${baseUrl}/api/siem/events`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.strictEqual(res.status, 200);
      const data = (await res.json()) as any;
      assert.ok(Array.isArray(data.events));
    });

    test('GET /api/siem/events?page=1&limit=2 returns paginated metadata', async () => {
      const res = await fetch(`${baseUrl}/api/siem/events?page=1&limit=2`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.strictEqual(res.status, 200);
      const data = (await res.json()) as any;
      assert.strictEqual(data.page, 1);
      assert.strictEqual(data.limit, 2);
      assert.ok(typeof data.total === 'number');
      assert.ok(typeof data.totalPages === 'number');
      assert.ok(Array.isArray(data.events));
      assert.ok(data.events.length <= 2);
    });
  });

  describe('5. Threat Scanner Network Boundary Defense', () => {
    test('GET /api/threats/scan rejects public IP target with 403 Scope Violation', async () => {
      const res = await fetch(`${baseUrl}/api/threats/scan?target=8.8.8.8`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.strictEqual(res.status, 403);
      const data = (await res.json()) as any;
      assert.ok(data.error?.includes('outside authorized scope whitelist'));
    });

    test('GET /api/threats/scan permits local loopback target (200)', async () => {
      const res = await fetch(`${baseUrl}/api/threats/scan?target=127.0.0.1`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.strictEqual(res.status, 200);
      const data = (await res.json()) as any;
      assert.strictEqual(data.host, '127.0.0.1');
      assert.ok(Array.isArray(data.openPorts));
    });
  });

  describe('6. Platform Status & Mode Switching Security', () => {
    test('GET /api/platform/status is accessible without authentication', async () => {
      const res = await fetch(`${baseUrl}/api/platform/status`);
      assert.strictEqual(res.status, 200);
      const data = (await res.json()) as any;
      assert.ok(data.platformMode);
    });

    test('POST /api/platform/mode rejects Viewer role with 403', async () => {
      const res = await fetch(`${baseUrl}/api/platform/mode`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${viewerToken}`,
        },
        body: JSON.stringify({ targetMode: 'LIVE' }),
      });
      assert.strictEqual(res.status, 403);
    });
  });
});
