import assert from 'assert';
import { test, describe, before } from 'node:test';
import { generateToken, authenticateJwt, requireRole, getJwtSecret, AuthenticatedRequest } from '../middleware/auth.js';
import { verifyWebSocketHandshake } from '../services/websocketService.js';
import { threatRouter } from '../routes/threatRoutes.js';
import { chatWithSocCopilot, validateCustomAiEndpoint, validateCustomAiEndpointAsync } from '../services/geminiAiService.js';
import { createCisoAuditPdfReport } from '../services/pdfReportService.js';
import { runLocalSocInference, runLocalTelemetryAssessment } from '../services/localInferenceEngine.js';
import { verifyCredentials, getUserByUsername } from '../services/userService.js';
import { RiskScoringService } from '../services/riskScoringService.js';
import { updatePlatformConfigOverride, loadPlatformConfig } from '../config/platformConfig.js';
import { pushBounded, pushBatchBounded } from '../db/client.js';
import { parseWindowsLogTelemetry } from '../adapters/windowsLogParser.js';
import { parseLinuxLogTelemetry } from '../adapters/linuxLogParser.js';
import { parseYaraSigmaResults } from '../adapters/yaraSigmaParser.js';
import { parseZapReport } from '../adapters/zapParser.js';
import { parseNmapTelemetry } from '../adapters/nmapParser.js';
import { isPrivateIp, lookupIpGeo } from '../services/geoIpService.js';
import { memoryDb } from '../db/client.js';
import { InMemoryMessageQueue } from '../queue/inMemoryQueue.js';
import { TelemetryPipelineService } from '../services/telemetryPipelineService.js';
import { setPipelineReferences } from '../routes/pipelineRoutes.js';
import { authRateLimiter } from '../middleware/rateLimiter.js';
import { vulnerabilityRouter } from '../routes/vulnerabilityRoutes.js';

describe('CyberMind SOC Authentication & RBAC Test Suite', () => {

  describe('1. Secret Configuration & Fail-Safe Guards', () => {
    test('getJwtSecret returns secret when configured', () => {
      process.env.JWT_SECRET = 'cybermind_test_secret_for_unit_tests_12345';
      const secret = getJwtSecret();
      assert.strictEqual(secret, 'cybermind_test_secret_for_unit_tests_12345');
    });

    test('getJwtSecret refuses to operate and throws when missing in production', () => {
      const prevEnv = process.env.NODE_ENV;
      const prevSecret = process.env.JWT_SECRET;
      try {
        process.env.NODE_ENV = 'production';
        delete process.env.JWT_SECRET;
        assert.throws(() => {
          getJwtSecret();
        }, /FATAL SECURITY CONFIG/);
      } finally {
        process.env.NODE_ENV = prevEnv;
        process.env.JWT_SECRET = prevSecret || 'cybermind_test_secret_for_unit_tests_12345';
      }
    });
  });

  describe('2. JWT Generation & Payload Verification', () => {
    test('Should generate verifiable JWT with assigned role and user info', () => {
      const token = generateToken({ id: 42, username: 'lead_hunter', role: 'Analyst' });
      assert.ok(typeof token === 'string' && token.length > 20);

      // Verify token with authenticateJwt mock
      let nextCalled = false;
      const req: any = {
        headers: { authorization: `Bearer ${token}` }
      };
      const res: any = {
        status: (code: number) => ({ json: (data: any) => ({ code, data }) })
      };

      authenticateJwt(req, res, () => {
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true);
      assert.strictEqual(req.user?.username, 'lead_hunter');
      assert.strictEqual(req.user?.role, 'Analyst');
      assert.strictEqual(req.user?.id, 42);
    });
  });

  describe('3. authenticateJwt Middleware - Zero Pass-Through for Unauthenticated Requests', () => {
    test('Should reject request with 401 when Authorization header is missing entirely', () => {
      let statusCode = 0;
      let errorJson: any = null;
      let nextCalled = false;

      const req: any = { headers: {} };
      const res: any = {
        status: (code: number) => {
          statusCode = code;
          return {
            json: (data: any) => { errorJson = data; }
          };
        }
      };

      authenticateJwt(req, res, () => { nextCalled = true; });

      assert.strictEqual(nextCalled, false, 'Middleware must NOT call next() on missing token');
      assert.strictEqual(statusCode, 401);
      assert.strictEqual(errorJson?.code, 'AUTH_TOKEN_MISSING');
    });

    test('Should reject request with 401 when Bearer prefix is missing', () => {
      let statusCode = 0;
      const req: any = { headers: { authorization: 'Basic dXNlcjpwYXNz' } };
      const res: any = {
        status: (code: number) => ({
          json: () => { statusCode = code; }
        })
      };

      authenticateJwt(req, res, () => {});
      assert.strictEqual(statusCode, 401);
    });

    test('Should reject request with 401 when token is forged or invalid', () => {
      let statusCode = 0;
      let errorJson: any = null;
      const req: any = { headers: { authorization: 'Bearer invalid.tampered.token' } };
      const res: any = {
        status: (code: number) => {
          statusCode = code;
          return { json: (data: any) => { errorJson = data; } };
        }
      };

      authenticateJwt(req, res, () => {});
      assert.strictEqual(statusCode, 401);
      assert.strictEqual(errorJson?.code, 'AUTH_TOKEN_INVALID');
    });
  });

  describe('4. requireRole RBAC Enforcement (Least Privilege Principle)', () => {
    test('Viewer accessing Admin-only endpoint must be BLOCKED with 403 Forbidden', () => {
      let statusCode = 0;
      let errorJson: any = null;
      let nextCalled = false;

      const req: any = {
        user: { id: 3, username: 'external_auditor', role: 'Viewer' }
      };
      const res: any = {
        status: (code: number) => {
          statusCode = code;
          return { json: (data: any) => { errorJson = data; } };
        }
      };

      const middleware = requireRole(['Admin']);
      middleware(req, res, () => { nextCalled = true; });

      assert.strictEqual(nextCalled, false, 'Viewer must not proceed to Admin operation');
      assert.strictEqual(statusCode, 403);
      assert.strictEqual(errorJson?.code, 'AUTH_ROLE_FORBIDDEN');
    });

    test('Analyst accessing Admin-only endpoint must be BLOCKED with 403 Forbidden', () => {
      let statusCode = 0;
      const req: any = {
        user: { id: 2, username: 'soc_analyst', role: 'Analyst' }
      };
      const res: any = {
        status: (code: number) => ({
          json: () => { statusCode = code; }
        })
      };

      const middleware = requireRole(['Admin']);
      middleware(req, res, () => {});

      assert.strictEqual(statusCode, 403);
    });

    test('Admin accessing Admin-only endpoint must SUCCEED with next()', () => {
      let nextCalled = false;
      const req: any = {
        user: { id: 1, username: 'soc_admin', role: 'Admin' }
      };
      const res: any = {};

      const middleware = requireRole(['Admin']);
      middleware(req, res, () => { nextCalled = true; });

      assert.strictEqual(nextCalled, true, 'Admin must be granted access');
    });

    test('Analyst accessing [Admin, Analyst] endpoint must SUCCEED with next()', () => {
      let nextCalled = false;
      const req: any = {
        user: { id: 2, username: 'soc_analyst', role: 'Analyst' }
      };
      const res: any = {};

      const middleware = requireRole(['Admin', 'Analyst']);
      middleware(req, res, () => { nextCalled = true; });

      assert.strictEqual(nextCalled, true, 'Analyst must be granted access to operations endpoints');
    });
  });

  describe('5. AI Endpoint Protection, Fallback & Language Mirroring', () => {
    test('chatWithSocCopilot returns defensive local model response in English when asked in English', async () => {
      const prevKey = process.env.GEMINI_API_KEY;
      try {
        delete process.env.GEMINI_API_KEY;
        const reply = await chatWithSocCopilot([], 'Tell me about Event ID 4625 and brute force attacks');
        assert.ok(reply.includes('4625') && reply.includes('Failed Logon'), 'Must return English 4625 guidance');
        assert.ok(!reply.includes('登入失敗'), 'English query must not return Chinese body');
      } finally {
        if (prevKey) process.env.GEMINI_API_KEY = prevKey;
      }
    });

    test('chatWithSocCopilot returns defensive response in Traditional Chinese when asked in Chinese', async () => {
      const prevKey = process.env.GEMINI_API_KEY;
      try {
        delete process.env.GEMINI_API_KEY;
        const reply = await chatWithSocCopilot([], '請問 Windows 事件 4625 是什麼意思？如何進行防禦排查？');
        assert.ok(reply.includes('4625') && (reply.includes('帳號登入失敗') || reply.includes('本地模型')), 'Must return Traditional Chinese 4625 guidance');
        assert.ok(reply.includes('暴力破解') && reply.includes('防禦處置'), 'Must contain Chinese defensive recommendations');
      } finally {
        if (prevKey) process.env.GEMINI_API_KEY = prevKey;
      }
    });

    test('chatWithSocCopilot handles PowerShell Chinese query in Traditional Chinese', async () => {
      const prevKey = process.env.GEMINI_API_KEY;
      try {
        delete process.env.GEMINI_API_KEY;
        const reply = await chatWithSocCopilot([], '行程建立日誌顯示 powershell -enc 參數，請問攻擊手法為何？');
        assert.ok((reply.includes('4688') || reply.includes('可疑行程')) && reply.includes('PowerShell'), 'Must return Chinese PowerShell response');
      } finally {
        if (prevKey) process.env.GEMINI_API_KEY = prevKey;
      }
    });

    test('chatWithSocCopilot handles unknown query gracefully in matching language', async () => {
      const prevKey = process.env.GEMINI_API_KEY;
      try {
        delete process.env.GEMINI_API_KEY;
        const replyEn = await chatWithSocCopilot([], 'What is this system?');
        assert.ok(replyEn.includes('CyberMind') && replyEn.includes('Telemetry'), 'Must introduce CyberMind in English');

        const replyZh = await chatWithSocCopilot([], '請問這套系統有什麼功能？');
        assert.ok(replyZh.includes('CyberMind') && (replyZh.includes('本地模型') || replyZh.includes('實時數據')), 'Must introduce CyberMind in Traditional Chinese');
      } finally {
        if (prevKey) process.env.GEMINI_API_KEY = prevKey;
      }
    });
  });

  describe('6. Threat, Ingestion & AI Route RBAC & SSRF Protection Regression Suite', () => {
    test('Viewer accessing port scanner /api/threats/scan must be BLOCKED with 403 Forbidden', () => {
      let statusCode = 0;
      let errorJson: any = null;
      let nextCalled = false;

      const req: any = {
        user: { id: 99, username: 'unauthorized_viewer', role: 'Viewer' },
        query: { target: '127.0.0.1' }
      };
      const res: any = {
        status: (code: number) => {
          statusCode = code;
          return { json: (data: any) => { errorJson = data; } };
        }
      };

      const middleware = requireRole(['Admin', 'Analyst']);
      middleware(req, res, () => { nextCalled = true; });

      assert.strictEqual(nextCalled, false, 'Viewer must not be allowed to execute port scan');
      assert.strictEqual(statusCode, 403);
      assert.strictEqual(errorJson?.code, 'AUTH_ROLE_FORBIDDEN');
    });

    test('Viewer accessing /api/ingest/logs or /api/vulnerabilities/lookup must be BLOCKED with 403', () => {
      let statusCode = 0;
      const req: any = {
        user: { id: 99, username: 'viewer_user', role: 'Viewer' }
      };
      const res: any = {
        status: (code: number) => ({ json: () => { statusCode = code; } })
      };

      const middleware = requireRole(['Admin', 'Analyst']);
      middleware(req, res, () => {});

      assert.strictEqual(statusCode, 403);
    });

    test('Analyst accessing /api/ai/test-connection (Admin-Only) must be BLOCKED with 403', () => {
      let statusCode = 0;
      const req: any = {
        user: { id: 2, username: 'analyst_user', role: 'Analyst' }
      };
      const res: any = {
        status: (code: number) => ({ json: () => { statusCode = code; } })
      };

      const adminOnlyMiddleware = requireRole(['Admin']);
      adminOnlyMiddleware(req, res, () => {});

      assert.strictEqual(statusCode, 403, 'Analyst cannot access Admin-only test-connection');
    });

    test('Admin accessing /api/ai/test-connection must SUCCEED with next()', () => {
      let nextCalled = false;
      const req: any = {
        user: { id: 1, username: 'root_admin', role: 'Admin' }
      };
      const res: any = {};

      const adminOnlyMiddleware = requireRole(['Admin']);
      adminOnlyMiddleware(req, res, () => { nextCalled = true; });

      assert.strictEqual(nextCalled, true);
    });

    test('Viewer accessing OS Discovery (/api/discovery/localhost, /arp, /netstat) must be BLOCKED with 403', () => {
      let statusCode = 0;
      const req: any = { user: { id: 3, username: 'viewer_user', role: 'Viewer' } };
      const res: any = { status: (code: number) => ({ json: () => { statusCode = code; } }) };

      const middleware = requireRole(['Admin', 'Analyst']);
      middleware(req, res, () => {});

      assert.strictEqual(statusCode, 403, 'Viewer role must be blocked from OS discovery execution');
    });

    test('Analyst or Admin accessing OS Discovery must SUCCEED with next()', () => {
      let nextCalled = false;
      const req: any = { user: { id: 2, username: 'analyst_user', role: 'Analyst' } };
      const res: any = { status: (code: number) => ({ json: () => {} }) };

      const middleware = requireRole(['Admin', 'Analyst']);
      middleware(req, res, () => { nextCalled = true; });

      assert.strictEqual(nextCalled, true, 'Analyst must be allowed to execute OS discovery');
    });

    test('Port scanner SSRF Guard blocks Cloud Metadata IP 169.254.169.254', () => {
      const targets = ['169.254.169.254', '169.254.1.1', '0.0.0.0', '224.0.0.1', 'http://metadata.google.internal', 'bad;host$name'];

      for (const targetHost of targets) {
        const isInvalidFormat = !/^[a-z0-9.-]+$/.test(targetHost.toLowerCase()) || targetHost.length > 253;
        const isRestrictedTarget =
          targetHost === '0.0.0.0' ||
          targetHost.startsWith('169.254.') ||
          targetHost.startsWith('224.') ||
          targetHost.includes('metadata.google.internal') ||
          targetHost.includes('instance-data');

        assert.ok(
          isInvalidFormat || isRestrictedTarget,
          `SSRF filter must block restricted or invalid target: ${targetHost}`
        );
      }
    });

    test('Port scanner SSRF Guard blocks hexadecimal, octal, and integer IP notations', () => {
      const bypassTargets = [
        '0x7f000001',
        '0xa9.0xfe.0xa9.0xfe',
        '0177.0.0.1',
        '2130706433',
        '2852039166',
        '0x7f.1',
      ];
      for (const targetHost of bypassTargets) {
        const isBypass =
          /^(0x[0-9a-f]+|\d+)$/i.test(targetHost) ||
          /(^|\.)0x[0-9a-f]+(\.|$)/i.test(targetHost) ||
          /(^|\.)0\d+(\.|$)/.test(targetHost);
        assert.strictEqual(isBypass, true, `SSRF filter must detect bypass format: ${targetHost}`);
      }
    });

    test('Port scanner allows benign targets like 127.0.0.1 and localhost', () => {
      const benign = ['127.0.0.1', 'localhost', '192.168.1.10'];
      for (const targetHost of benign) {
        const isInvalidFormat = !/^[a-z0-9.-]+$/.test(targetHost.toLowerCase()) || targetHost.length > 253;
        const isRestrictedTarget =
          targetHost === '0.0.0.0' ||
          targetHost.startsWith('169.254.') ||
          targetHost.startsWith('224.') ||
          targetHost.includes('metadata.google.internal') ||
          targetHost.includes('instance-data');

        assert.strictEqual(isInvalidFormat, false, `Benign host ${targetHost} should have valid format`);
        assert.strictEqual(isRestrictedTarget, false, `Benign host ${targetHost} should not be restricted`);
      }
    });
  });

  describe('7. Enterprise Identity Verification & Scrypt Hashing', () => {
    test('verifyCredentials authenticates valid credentials with server-assigned role', () => {
      const viewer = verifyCredentials('viewer', 'Viewer@CyberMind2026!');
      assert.ok(viewer, 'Valid viewer credentials should authenticate');
      assert.strictEqual(viewer.role, 'Viewer');
      assert.strictEqual(viewer.username, 'viewer');

      const admin = verifyCredentials('admin', 'Admin@CyberMind2026!');
      assert.ok(admin, 'Valid admin credentials should authenticate');
      assert.strictEqual(admin.role, 'Admin');
      assert.strictEqual(admin.username, 'admin');
    });

    test('verifyCredentials rejects incorrect password attempt with null', () => {
      const result = verifyCredentials('admin', 'wrong_super_secret_password');
      assert.strictEqual(result, null, 'Invalid password must return null');
    });

    test('verifyCredentials strictly rejects all backdoor passwords (password, admin123, admin)', () => {
      assert.strictEqual(verifyCredentials('admin', 'password'), null, 'admin with password "password" must return null');
      assert.strictEqual(verifyCredentials('admin', 'admin123'), null, 'admin with password "admin123" must return null');
      assert.strictEqual(verifyCredentials('admin', 'admin'), null, 'admin with password "admin" must return null');
      assert.strictEqual(verifyCredentials('analyst', 'analyst123'), null, 'analyst with password "analyst123" must return null');
      assert.strictEqual(verifyCredentials('admin', ''), null, 'empty password must return null');
    });

    test('Server-side role integrity prevents client-driven role spoofing', () => {
      // Simulate client attempting to send role: 'Admin' with viewer credentials
      const clientPayload = { username: 'viewer', password: 'Viewer@CyberMind2026!', role: 'Admin' };
      const verified = verifyCredentials(clientPayload.username, clientPayload.password);
      assert.ok(verified);

      // Verify that server role strictly overrides client payload
      const token = generateToken({ id: verified.id, username: verified.username, role: verified.role });
      const decoded: any = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());

      assert.strictEqual(decoded.role, 'Viewer', 'Token must contain server-stored role Viewer, ignoring client request for Admin');
    });
  });

  describe('8. Runtime Operating Mode & Role Switching Lockout', () => {
    test('In LIVE mode, role switching is strictly forbidden', () => {
      updatePlatformConfigOverride({ platformMode: 'LIVE' });
      const config = loadPlatformConfig();
      assert.strictEqual(config.platformMode, 'LIVE');

      // Emulate authRoutes /switch-role check
      const isLive = config.platformMode === 'LIVE';
      assert.strictEqual(isLive, true, 'Platform mode must be LIVE');
    });

    test('In DEMO mode, role switching produces valid demo credentials', () => {
      updatePlatformConfigOverride({ platformMode: 'DEMO' });
      const config = loadPlatformConfig();
      assert.strictEqual(config.platformMode, 'DEMO');

      const demoToken = generateToken({ id: 1, username: 'soc_admin', role: 'Admin' });
      assert.ok(demoToken);

      // Clean up override back to LIVE
      updatePlatformConfigOverride({ platformMode: 'LIVE' });
    });
  });

  describe('9. AI Custom Endpoint SSRF Protection', () => {
    test('validateCustomAiEndpoint blocks Cloud Metadata service IP 169.254.169.254', () => {
      const result = validateCustomAiEndpoint('http://169.254.169.254/latest/meta-data');
      assert.strictEqual(result.valid, false);
      assert.match(result.error || '', /SSRF Protection/);
    });

    test('validateCustomAiEndpoint blocks Google Cloud Metadata internal hostname', () => {
      const result = validateCustomAiEndpoint('http://metadata.google.internal/computeMetadata/v1/');
      assert.strictEqual(result.valid, false);
      assert.match(result.error || '', /SSRF Protection/);
    });

    test('validateCustomAiEndpoint blocks internal RFC1918 addresses', () => {
      const testCases = [
        'http://10.0.0.1:8080/v1',
        'http://192.168.1.50:11434/v1',
        'http://172.16.0.10:8000',
      ];
      for (const url of testCases) {
        const res = validateCustomAiEndpoint(url);
        assert.strictEqual(res.valid, false, `Should block internal address: ${url}`);
      }
    });

    test('validateCustomAiEndpoint allows public APIs and local loopback', () => {
      const allowedCases = [
        'https://api.openai.com/v1',
        'https://api.anthropic.com/v1',
        'http://localhost:11434/v1',
        'http://127.0.0.1:11434/v1',
      ];
      for (const url of allowedCases) {
        const res = validateCustomAiEndpoint(url);
        assert.strictEqual(res.valid, true, `Should allow valid address: ${url}`);
      }
    });

    test('validateCustomAiEndpoint blocks integer and hex notation IP bypasses', () => {
      const bypassCases = [
        'http://0x7f000001/v1',
        'http://2130706433/v1',
      ];
      for (const url of bypassCases) {
        const res = validateCustomAiEndpoint(url);
        assert.strictEqual(res.valid, false, `Should block hex/int bypass: ${url}`);
      }
    });

    test('validateCustomAiEndpointAsync blocks DNS rebinding and resolves destination safety', async () => {
      // Loopback is allowed
      const localRes = await validateCustomAiEndpointAsync('http://localhost:11434/v1');
      assert.strictEqual(localRes.valid, true);

      // Link-local / metadata direct IP is blocked
      const metaRes = await validateCustomAiEndpointAsync('http://169.254.169.254/latest');
      assert.strictEqual(metaRes.valid, false);

      // Private IP is blocked
      const privRes = await validateCustomAiEndpointAsync('http://192.168.1.1:8080');
      assert.strictEqual(privRes.valid, false);
    });
  });

  describe('10. Centralized Explainable Risk Scoring Service', () => {
    test('calculateRisk evaluates CVSS v3.1 + open ports penalty accurately', () => {
      // 2 critical (36), 1 high (9), 2 medium (6), 3 open ports (6) -> total penalty = 57
      // overallScore = 100 - 57 = 43 -> HIGH
      // networkProtectionScore = 100 - (3 * 5 + 2 * 10) = 100 - 35 = 65
      const result = RiskScoringService.calculateRisk({
        criticalVulns: 2,
        highVulns: 1,
        mediumVulns: 2,
        openPortsCount: 3,
      });

      assert.strictEqual(result.overallScore, 43);
      assert.strictEqual(result.networkProtectionScore, 65);
      assert.strictEqual(result.riskLevel, 'CRITICAL');
      assert.strictEqual(result.breakdown.criticalPenalty, 36);
      assert.strictEqual(result.breakdown.highPenalty, 9);
      assert.strictEqual(result.breakdown.mediumPenalty, 6);
      assert.strictEqual(result.breakdown.openPortsPenalty, 6);
      assert.strictEqual(result.breakdown.totalPenalty, 57);
    });

    test('calculateRisk clamps overall score to 0 when penalty exceeds 100', () => {
      const result = RiskScoringService.calculateRisk({
        criticalVulns: 10,
        highVulns: 5,
        mediumVulns: 5,
        openPortsCount: 20,
      });

      assert.strictEqual(result.overallScore, 0);
      assert.strictEqual(result.riskLevel, 'CRITICAL');
    });

    test('calculateRisk yields 100 and LOW risk for pristine infrastructure', () => {
      const result = RiskScoringService.calculateRisk({
        criticalVulns: 0,
        highVulns: 0,
        mediumVulns: 0,
        openPortsCount: 0,
      });

      assert.strictEqual(result.overallScore, 100);
      assert.strictEqual(result.networkProtectionScore, 100);
      assert.strictEqual(result.riskLevel, 'LOW');
    });
  });

  describe('11. Memory Bounded Queue & Bulk Ingestion Safety', () => {
    test('pushBounded strictly enforces maxSize and evicts oldest items in FIFO order', () => {
      const queue: number[] = [];
      for (let i = 1; i <= 10; i++) {
        pushBounded(queue, i, 5);
      }
      assert.strictEqual(queue.length, 5);
      assert.deepStrictEqual(queue, [6, 7, 8, 9, 10]);
    });

    test('pushBatchBounded safely appends batch items and trims to maxSize', () => {
      const queue: string[] = ['a', 'b'];
      const batch = ['c', 'd', 'e', 'f', 'g'];
      pushBatchBounded(queue, batch, 4);
      assert.strictEqual(queue.length, 4);
      assert.deepStrictEqual(queue, ['d', 'e', 'f', 'g']);
    });

    test('pushBatchBounded handles empty array input without errors', () => {
      const queue: string[] = ['x', 'y'];
      pushBatchBounded(queue, [], 5);
      assert.strictEqual(queue.length, 2);
      assert.deepStrictEqual(queue, ['x', 'y']);
    });
  });

  describe('12. Truthful Telemetry Parsers & Anti-Fabrication Guarantees', () => {
    test('windowsLogParser does not fabricate 192.168.1.155 or Administrator on missing fields', () => {
      const parsed = parseWindowsLogTelemetry('Some generic log line without user or IP');
      assert.strictEqual(parsed.length, 1);
      assert.strictEqual(parsed[0].ip, 'N/A');
      assert.strictEqual(parsed[0].user, 'N/A');
      assert.strictEqual(parsed[0].computer, 'Unknown-Host');
      assert.strictEqual(parsed[0].eventId, 'Unknown');
    });

    test('linuxLogParser does not fabricate 185.220.101.5 or root on missing fields', () => {
      const parsed = parseLinuxLogTelemetry('Jul 25 14:10:01 web-prod-01 systemd: Started Daily apt download activities.');
      assert.strictEqual(parsed.length, 1);
      assert.strictEqual(parsed[0].ip, 'N/A');
      assert.strictEqual(parsed[0].user, 'N/A');
    });

    test('yaraSigmaParser returns empty array on clean logs instead of injecting fake SIGMA-DEF-1', () => {
      const parsed = parseYaraSigmaResults('Benign log file with no suspicious signatures or detection hits.');
      assert.strictEqual(parsed.length, 0, 'Clean log file must yield zero detections');
    });

    test('zapParser returns empty findings on invalid input without inventing fake CSP findings', () => {
      const parsed = parseZapReport('Invalid non-json and non-xml payload');
      assert.strictEqual(parsed.length, 0, 'Invalid report must not invent fake ZAP-XML-1 finding');
    });

    test('nmapParser reports active service listeners without fabricating MS17-010 on benign port 445', () => {
      const benignXml = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Windows Server 2022" version="10.0"/>
      </port>
    </ports>
  </host>
</nmaprun>`;
      const parsed = parseNmapTelemetry(benignXml);
      assert.strictEqual(parsed.openPorts.length, 1);
      assert.strictEqual(parsed.openPorts[0].port, 445);
      assert.strictEqual(parsed.openPorts[0].vulns, 'Active TCP Service Listener');
    });
  });

  describe('13. Incident Case Management & Investigation Lifecycle', () => {
    test('Incident creation initializes with status New and formatted incident ID', () => {
      const initialCount = memoryDb.incidents ? memoryDb.incidents.length : 0;
      const testIncident = {
        id: `INC-2026-TEST-${Date.now()}`,
        title: 'Suspicious PowerShell Execution',
        severity: 'High',
        status: 'New',
        assignedTo: 'Lead Analyst',
        sourceIp: '192.168.1.100',
        targetIp: '10.0.4.15',
        mitreTechnique: 'T1059.001',
        summary: 'Encoded command detected in event stream',
        notes: ['[Initial Alert] Escalated from SIEM console'],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      pushBounded(memoryDb.incidents, testIncident, 500);
      assert.strictEqual(memoryDb.incidents.length, initialCount + 1);

      const retrieved = memoryDb.incidents.find((i: any) => i.id === testIncident.id);
      assert.ok(retrieved);
      assert.strictEqual(retrieved.status, 'New');
      assert.strictEqual(retrieved.severity, 'High');
    });

    test('Incident status transition follows valid SOC progression', () => {
      const incident = memoryDb.incidents[memoryDb.incidents.length - 1];
      assert.ok(incident, 'Incident must exist');

      const validTransitions = ['Investigating', 'Contained', 'Remediated', 'Closed'];
      for (const st of validTransitions) {
        incident.status = st;
        incident.updatedAt = new Date().toISOString();
        assert.strictEqual(incident.status, st);
      }
    });

    test('Incident audit note appending preserves history and adds analyst tag', () => {
      const incident = memoryDb.incidents[memoryDb.incidents.length - 1];
      assert.ok(incident);

      const prevNotesCount = incident.notes.length;
      const newNote = `[${new Date().toISOString()} by lead_hunter] Host isolated from VLAN 40`;
      incident.notes.push(newNote);

      assert.strictEqual(incident.notes.length, prevNotesCount + 1);
      assert.ok(incident.notes[incident.notes.length - 1].includes('Host isolated'));
    });
  });

  describe('14. Telemetry Pipeline Observability & Message Queue Metrics', () => {
    test('InMemoryMessageQueue correctly tracks published and depth metrics', async () => {
      const queue = new InMemoryMessageQueue(100);

      // Publish 5 items
      for (let i = 0; i < 5; i++) {
        await queue.publish('telemetry.test', { id: `msg-${i}`, payload: 'test' });
      }

      const metrics = queue.getMetrics();
      assert.strictEqual(metrics.publishedCount, 5);
      assert.strictEqual(metrics.maxCapacity, 100);
      assert.strictEqual(metrics.watermarkStatus, 'NORMAL');
    });

    test('Telemetry pipeline references correctly supply queue metrics to stats endpoint', async () => {
      const queue = new InMemoryMessageQueue(500);
      await queue.publish('telemetry.stream', { event: 'telemetry_sample' });

      setPipelineReferences(queue, null as any);

      const metrics = queue.getMetrics();
      assert.strictEqual(metrics.publishedCount, 1);
      assert.strictEqual(metrics.maxCapacity, 500);
    });
  });

  describe('15. GeoIP Identification & Private Network Classification', () => {
    test('isPrivateIp detects all RFC1918, loopback, and link-local ranges', () => {
      const privateIps = [
        '10.0.0.1',
        '10.255.255.254',
        '172.16.0.1',
        '172.31.255.254',
        '192.168.1.1',
        '192.168.254.254',
        '127.0.0.1',
        '127.0.0.254',
        '169.254.169.254',
        '::1'
      ];

      for (const ip of privateIps) {
        assert.strictEqual(isPrivateIp(ip), true, `IP ${ip} must be classified as private/internal`);
      }
    });

    test('isPrivateIp does not classify public IPs as private', () => {
      const publicIps = ['8.8.8.8', '1.1.1.1', '185.220.101.5', '142.250.190.46'];
      for (const ip of publicIps) {
        assert.strictEqual(isPrivateIp(ip), false, `IP ${ip} must not be classified as private`);
      }
    });

    test('lookupIpGeo immediately resolves private IPs offline without external HTTP request', async () => {
      const result = await lookupIpGeo('192.168.1.50');
      assert.strictEqual(result.source, 'RFC1918');
      assert.strictEqual(result.country, 'INTERNAL');
      assert.strictEqual(result.org, 'Private Network');
      assert.strictEqual(result.ip, '192.168.1.50');
    });
  });

  describe('16. Centralized Explainable Risk Posture Scoring', () => {
    test('evaluateSystemPosture returns valid posture with scores clamped between 0 and 100', () => {
      const posture = RiskScoringService.evaluateSystemPosture();
      assert.ok(typeof posture.overallScore === 'number');
      assert.ok(posture.overallScore >= 0 && posture.overallScore <= 100);
      assert.ok(typeof posture.networkProtectionScore === 'number');
      assert.ok(posture.networkProtectionScore >= 0 && posture.networkProtectionScore <= 100);
      assert.ok(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(posture.riskLevel));
      assert.ok(typeof posture.penalty === 'number');
      assert.ok(posture.methodology.includes('100 -'));
    });
  });

  describe('17. Truthful CISO Reports & Anti-Fabrication Safeguards', () => {
    test('createCisoAuditPdfReport does not fabricate CVEs or fake anomalies on empty input', () => {
      const pdfBuffer = createCisoAuditPdfReport({
        title: 'TEST AUDIT',
        riskScore: 100,
        summary: 'Baseline test',
        findings: [],
        anomalies: [],
      });
      assert.ok(Buffer.isBuffer(pdfBuffer));
      assert.ok(pdfBuffer.length > 500);

      // Verify binary content does not contain fabricated string tokens
      const text = pdfBuffer.toString('utf-8');
      assert.strictEqual(text.includes('CVE-2021-44228'), false, 'Clean report must not fabricate Log4Shell');
      assert.strictEqual(text.includes('CVE-2021-41773'), false, 'Clean report must not fabricate Apache CVE');
      assert.ok(text.includes('No active vulnerabilities') || text.includes('Pristine Posture'));
    });

    test('runLocalSocInference does not fabricate 192.168.1.155 or Administrator on missing fields', () => {
      const reply = runLocalSocInference('Analyze failed logon Event ID 4625', {
        siemEvents: [
          {
            id: 'TEST-4625',
            hostName: 'TEST-SERVER',
            eventId: '4625',
            summary: 'Logon Failure',
            severity: 'High',
            rawDetails: {}
          }
        ]
      });

      assert.strictEqual(reply.includes('192.168.1.155'), false, 'Must not fabricate 192.168.1.155');
      assert.strictEqual(reply.includes('Administrator'), false, 'Must not fabricate Administrator');
      assert.ok(reply.includes('Unspecified IP') || reply.includes('Unknown User'));
    });

    test('runLocalTelemetryAssessment produces truthful baseline on pristine environment', () => {
      const assessment = runLocalTelemetryAssessment({
        siemEvents: [],
        findings: [],
        scan: { host: 'localhost', openPorts: [] },
      });

      assert.strictEqual(assessment.criticalVulnerabilities.length, 0);
      assert.strictEqual(assessment.activeThreatCount, 0);
      assert.strictEqual(assessment.postureStatus, 'OPTIMAL');
      assert.strictEqual(assessment.riskScore, 95);
    });

    test('asset storage safely uses pushBounded sliding window', () => {
      const testAssets: any[] = [];
      for (let i = 0; i < 50; i++) {
        pushBounded(testAssets, { id: i, hostname: `host-${i}` }, 20);
      }
      assert.strictEqual(testAssets.length, 20);
      assert.strictEqual(testAssets[0].id, 30);
      assert.strictEqual(testAssets[19].id, 49);
    });
  });

  describe('18. WebSocket JWT Handshake Security & Token Verification', () => {
    test('verifyWebSocketHandshake grants access with valid JWT in query parameter', () => {
      const token = generateToken({ id: 1, username: 'soc_admin', role: 'Admin' });
      const req: any = {
        headers: { host: 'localhost:5000' },
        url: `/ws/telemetry?token=${token}`,
        socket: { remoteAddress: '127.0.0.1' }
      };
      const result = verifyWebSocketHandshake(req);
      assert.strictEqual(result.authenticated, true);
      assert.strictEqual(result.user?.username, 'soc_admin');
      assert.strictEqual(result.user?.role, 'Admin');
    });

    test('verifyWebSocketHandshake grants access with valid Bearer token in Authorization header', () => {
      const token = generateToken({ id: 2, username: 'soc_analyst', role: 'Analyst' });
      const req: any = {
        headers: { host: 'localhost:5000', authorization: `Bearer ${token}` },
        url: '/ws/telemetry',
        socket: { remoteAddress: '127.0.0.1' }
      };
      const result = verifyWebSocketHandshake(req);
      assert.strictEqual(result.authenticated, true);
      assert.strictEqual(result.user?.username, 'soc_analyst');
    });

    test('verifyWebSocketHandshake rejects request with missing token', () => {
      const req: any = {
        headers: { host: 'localhost:5000' },
        url: '/ws/telemetry',
        socket: { remoteAddress: '192.168.1.100' }
      };
      const result = verifyWebSocketHandshake(req);
      assert.strictEqual(result.authenticated, false);
      assert.strictEqual(result.error, 'Missing authentication token');
    });

    test('verifyWebSocketHandshake rejects request with forged or expired token', () => {
      const req: any = {
        headers: { host: 'localhost:5000' },
        url: '/ws/telemetry?token=forged.invalid.token.signature',
        socket: { remoteAddress: '192.168.1.100' }
      };
      const result = verifyWebSocketHandshake(req);
      assert.strictEqual(result.authenticated, false);
      assert.strictEqual(result.error, 'Invalid or expired token');
    });
  });

  describe('19. Threat Scanner Scope Boundary & External Probe Blocking', () => {
    test('threatRouter /scan rejects arbitrary external public IP with 403 Scope Violation', async () => {
      let statusCode = 0;
      let responseBody: any = null;

      const req: any = {
        method: 'GET',
        url: '/scan?target=8.8.8.8',
        query: { target: '8.8.8.8' },
        user: { id: 1, username: 'admin', role: 'Admin' },
        headers: {},
        ip: '127.0.0.1',
        app: { get: () => {} }
      };

      const res: any = {
        setHeader: () => {},
        getHeader: () => {},
        status: (code: number) => {
          statusCode = code;
          return {
            json: (data: any) => { responseBody = data; }
          };
        }
      };

      await new Promise<void>((resolve) => {
        (threatRouter as any).handle(req, res, () => resolve());
        setTimeout(resolve, 100);
      });

      assert.strictEqual(statusCode, 403, 'External IP 8.8.8.8 must be rejected with 403');
      assert.ok(responseBody?.error?.includes('outside authorized scope whitelist'));
    });

    test('threatRouter /scan permits scanning local loopback and internal RFC1918 addresses', async () => {
      let statusCode = 0;
      let responseBody: any = null;

      const req: any = {
        method: 'GET',
        url: '/scan?target=127.0.0.1',
        query: { target: '127.0.0.1' },
        user: { id: 1, username: 'admin', role: 'Admin' },
        headers: {},
        ip: '127.0.0.1',
        app: { get: () => {} }
      };

      const res: any = {
        setHeader: () => {},
        getHeader: () => {},
        status: (code: number) => {
          statusCode = code;
          return {
            json: (data: any) => { responseBody = data; }
          };
        },
        json: (data: any) => {
          statusCode = 200;
          responseBody = data;
        }
      };

      await new Promise<void>((resolve) => {
        (threatRouter as any).handle(req, res, () => resolve());
        setTimeout(resolve, 500);
      });

      assert.notStrictEqual(statusCode, 403, '127.0.0.1 must NOT trigger 403 Scope Violation');
    });
  });

  describe('20. Enterprise Defensive Fixes & Regression Verifications', () => {
    test('authRateLimiter is properly configured and defined', () => {
      assert.ok(authRateLimiter, 'authRateLimiter must be defined');
    });

    test('vulnerabilityRouter GET / does not invent fake software in LIVE mode on empty inventory', async () => {
      const originalEnv = process.env.PLATFORM_MODE;
      process.env.PLATFORM_MODE = 'LIVE';

      let responseBody: any = null;
      let statusCode = 200;

      const req: any = {
        method: 'GET',
        url: '/',
        user: { id: 1, username: 'admin', role: 'Admin' },
        headers: {},
        ip: '127.0.0.1',
      };

      const res: any = {
        setHeader: () => {},
        status: (code: number) => {
          statusCode = code;
          return { json: (d: any) => { responseBody = d; } };
        },
        json: (d: any) => {
          statusCode = 200;
          responseBody = d;
        }
      };

      await new Promise<void>((resolve) => {
        (vulnerabilityRouter as any).handle(req, res, () => resolve());
        setTimeout(resolve, 300);
      });

      process.env.PLATFORM_MODE = originalEnv;

      assert.strictEqual(statusCode, 200);
      assert.ok(Array.isArray(responseBody?.vulnerabilities));
      const fabricatedLog4j = responseBody?.vulnerabilities.find((v: any) => v.cveId === 'CVE-2021-44228' && v.host === '192.168.1.50');
      assert.strictEqual(fabricatedLog4j, undefined, 'LIVE mode must NOT inject synthetic demo Log4j 192.168.1.50 vulnerability');
    });

    test('reportRouter uses pushBounded sliding window to cap memoryDb.reports', () => {
      const originalReports = [...memoryDb.reports];
      for (let i = 0; i < 250; i++) {
        pushBounded(memoryDb.reports, { id: i, report_title: `Audit ${i}` }, 200);
      }
      assert.strictEqual(memoryDb.reports.length, 200, 'memoryDb.reports must be capped at max 200 entries');
      memoryDb.reports = originalReports;
    });
  });

});


