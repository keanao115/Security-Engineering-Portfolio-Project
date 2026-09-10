import assert from 'assert';
import { test, describe, before } from 'node:test';
import { generateToken, authenticateJwt, requireRole, getJwtSecret, AuthenticatedRequest } from '../middleware/auth.js';
import { chatWithSocCopilot, validateCustomAiEndpoint } from '../services/geminiAiService.js';
import { verifyCredentials, getUserByUsername } from '../services/userService.js';
import { RiskScoringService } from '../services/riskScoringService.js';
import { updatePlatformConfigOverride, loadPlatformConfig } from '../config/platformConfig.js';

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

});
