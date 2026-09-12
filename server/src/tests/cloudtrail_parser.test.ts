import assert from 'assert';
import { test, describe, before, after } from 'node:test';
import express from 'express';
import http from 'http';
import jwt from 'jsonwebtoken';
import { parseCloudTrailTelemetry, classifyCloudTrailEvent, parseS3ServerAccessLog } from '../adapters/cloudTrailParser.js';
import { ingestRouter } from '../routes/ingestRoutes.js';
import { authenticateJwt } from '../middleware/auth.js';

describe('AWS CloudTrail & S3 Access Log Telemetry Parser Suite', () => {
  let server: http.Server;
  let baseUrl: string;
  let analystToken: string;
  const JWT_SECRET = 'ci_test_jwt_secret_github_actions_pipeline_key';

  before(async () => {
    process.env.JWT_SECRET = JWT_SECRET;
    analystToken = jwt.sign({ id: 'u-analyst', username: 'cloud-analyst', role: 'Analyst' }, JWT_SECRET, { expiresIn: '1h' });

    const app = express();
    app.use(express.json());
    app.use('/api/ingest', authenticateJwt, ingestRouter);

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

  describe('1. CloudTrail Record Event Classification & MITRE Tagging', () => {
    test('Classifies StopLogging as Critical Defense Evasion (T1562.001)', () => {
      const record = {
        eventVersion: '1.08',
        userIdentity: {
          type: 'IAMUser',
          principalId: 'AIDA1234567890',
          arn: 'arn:aws:iam::123456789012:user/attacker',
          userName: 'attacker',
        },
        eventTime: '2024-03-15T12:00:00Z',
        eventSource: 'cloudtrail.amazonaws.com',
        eventName: 'StopLogging',
        awsRegion: 'us-east-1',
        sourceIPAddress: '198.51.100.99',
        requestParameters: { name: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/corp-audit-trail' },
      };

      const result = classifyCloudTrailEvent(record);
      assert.strictEqual(result.severity, 'Critical');
      assert.ok(result.mitreTechnique.includes('T1562.001'));
      assert.strictEqual(result.mitreTactic, 'Defense Evasion');
      assert.ok(result.summary.includes('disable/tamper'));
    });

    test('Classifies CreateAccessKey / AttachUserPolicy as High Persistence (T1098)', () => {
      const record = {
        userIdentity: { userName: 'compromised-admin' },
        eventSource: 'iam.amazonaws.com',
        eventName: 'CreateAccessKey',
        sourceIPAddress: '203.0.113.15',
        requestParameters: { userName: 'backdoor-user' },
      };

      const result = classifyCloudTrailEvent(record);
      assert.strictEqual(result.severity, 'High');
      assert.ok(result.mitreTechnique.includes('T1098'));
      assert.strictEqual(result.mitreTactic, 'Persistence');
      assert.ok(result.summary.includes('backdoor-user'));
    });

    test('Classifies ConsoleLogin without MFA as High Initial Access (T1078.004)', () => {
      const record = {
        userIdentity: { userName: 'bob' },
        eventSource: 'signin.amazonaws.com',
        eventName: 'ConsoleLogin',
        sourceIPAddress: '192.0.2.77',
        additionalEventData: { MFAUsed: 'No' },
      };

      const result = classifyCloudTrailEvent(record);
      assert.strictEqual(result.severity, 'High');
      assert.ok(result.mitreTechnique.includes('T1078.004'));
      assert.ok(result.summary.includes('without MFA'));
    });

    test('Classifies S3 GetObject and Public Bucket Policy as Exfiltration (T1530)', () => {
      const record = {
        userIdentity: { userName: 'data-exfil' },
        eventSource: 's3.amazonaws.com',
        eventName: 'PutBucketPolicy',
        sourceIPAddress: '198.51.100.22',
        requestParameters: {
          bucketName: 'customer-ssn-records',
          bucketPolicy: '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}',
        },
      };

      const result = classifyCloudTrailEvent(record);
      assert.strictEqual(result.severity, 'Critical');
      assert.ok(result.mitreTechnique.includes('T1530'));
      assert.strictEqual(result.mitreTactic, 'Exfiltration');
    });

    test('Classifies AuthorizeSecurityGroupIngress with 0.0.0.0/0 as High (T1578.002)', () => {
      const record = {
        userIdentity: { userName: 'devops' },
        eventSource: 'ec2.amazonaws.com',
        eventName: 'AuthorizeSecurityGroupIngress',
        sourceIPAddress: '203.0.113.88',
        requestParameters: {
          ipPermissions: {
            items: [{ fromPort: 22, toPort: 22, ipProtocol: 'tcp', ipRanges: { items: [{ cidrIp: '0.0.0.0/0' }] } }],
          },
        },
      };

      const result = classifyCloudTrailEvent(record);
      assert.strictEqual(result.severity, 'High');
      assert.ok(result.mitreTechnique.includes('T1578.002'));
      assert.ok(result.summary.includes('0.0.0.0/0'));
    });
  });

  describe('2. Batch JSON & S3 Access Log Format Parsing', () => {
    test('Parses standard AWS CloudTrail { "Records": [...] } JSON payload', () => {
      const payload = {
        Records: [
          {
            eventVersion: '1.08',
            eventSource: 's3.amazonaws.com',
            eventName: 'GetObject',
            awsRegion: 'us-west-2',
            sourceIPAddress: '198.51.100.44',
            userIdentity: { userName: 'analyst-alice' },
            requestParameters: { bucketName: 'audit-logs', key: 'passwords.txt' },
          },
          {
            eventVersion: '1.08',
            eventSource: 'iam.amazonaws.com',
            eventName: 'AttachRolePolicy',
            awsRegion: 'us-east-1',
            sourceIPAddress: '203.0.113.12',
            userIdentity: { userName: 'admin-bob' },
            requestParameters: { roleName: 'SuperAdmin' },
          },
        ],
      };

      const events = parseCloudTrailTelemetry(payload);
      assert.strictEqual(events.length, 2);
      assert.strictEqual(events[0].sourceType, 'AWS_CLOUDTRAIL');
      assert.strictEqual(events[0].eventName, 'GetObject');
      assert.ok(events[0].mitreTechnique.includes('T1530'));
      assert.strictEqual(events[1].eventName, 'AttachRolePolicy');
      assert.ok(events[1].mitreTechnique.includes('T1098'));
    });

    test('Parses raw S3 Server Access Log line', () => {
      const s3Line = '79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be mybucket [06/Feb/2024:14:20:00 +0000] 198.51.100.77 79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be 3E57427F3EB2099A REST.GET.OBJECT database_backup.sql "GET /mybucket/database_backup.sql HTTP/1.1" 200 - 1048576 1048576 40 38 "-" "curl/8.1.2" -';

      const event = parseS3ServerAccessLog(s3Line, 0);
      assert.ok(event);
      assert.strictEqual(event.sourceType, 'AWS_S3_ACCESS');
      assert.strictEqual(event.sourceIPAddress, '198.51.100.77');
      assert.strictEqual(event.eventName, 'REST.GET.OBJECT');
      assert.ok(event.mitreTechnique.includes('T1530'));
      assert.ok(event.summary.includes('database_backup.sql'));
    });
  });

  describe('3. REST API Endpoint Integration (/api/ingest/cloudtrail)', () => {
    test('POST /api/ingest/cloudtrail processes CloudTrail records into SIEM', async () => {
      const cloudPayload = {
        Records: [
          {
            eventSource: 'cloudtrail.amazonaws.com',
            eventName: 'StopLogging',
            awsRegion: 'eu-west-1',
            sourceIPAddress: '185.220.101.5',
            userIdentity: { userName: 'compromised-root' },
          },
        ],
      };

      const res = await fetch(`${baseUrl}/api/ingest/cloudtrail`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${analystToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(cloudPayload),
      });

      assert.strictEqual(res.status, 200);
      const data: any = await res.json();
      assert.strictEqual(data.count, 1);
      assert.strictEqual(data.siemEventsCount, 1);
      assert.strictEqual(data.events[0].severity, 'Critical');
      assert.ok(data.events[0].mitreTechnique.includes('T1562.001'));
    });
  });
});
