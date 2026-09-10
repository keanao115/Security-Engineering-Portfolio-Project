import { Request, Response, Router } from 'express';
import { generateDefensiveAiAnalysis } from '../services/aiAnalysisService.js';
import { memoryDb } from '../db/client.js';
import { requireRole } from '../middleware/auth.js';
import { scanRateLimiter } from '../middleware/rateLimiter.js';
import { RiskScoringService } from '../services/riskScoringService.js';
import { lookupIpGeo, isPrivateIp } from '../services/geoIpService.js';
import { isIpInAuthorizedScope } from '../services/assetDiscoveryService.js';
import net from 'net';
import dns from 'dns';

export const threatRouter = Router();

// GET /api/threats/risk-score — Centralized Explainable Risk Score
threatRouter.get('/risk-score', requireRole(['Admin', 'Analyst', 'Viewer']), (_req: Request, res: Response) => {
  const result = RiskScoringService.evaluateSystemPosture();
  return res.json(result);
});

// GET /api/threats/geoip/:ip — Real GeoIP Lookup with LRU cache
threatRouter.get('/geoip/:ip', requireRole(['Admin', 'Analyst', 'Viewer']), async (req: Request, res: Response) => {
  const ip = req.params.ip;
  if (!ip) return res.status(400).json({ error: 'IP address is required' });
  const geo = await lookupIpGeo(ip);
  return res.json(geo);
});

threatRouter.post('/analyze', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const { logs, findings, scan } = req.body;

  const result = generateDefensiveAiAnalysis({
    logs: logs || memoryDb.logs,
    findings: findings || memoryDb.findings,
    scan
  });

  return res.json(result);
});

threatRouter.get('/scan', scanRateLimiter, requireRole(['Admin', 'Analyst']), async (req: Request, res: Response) => {
  const targetHost = ((req.query.target as string) || '127.0.0.1').trim().toLowerCase();

  // ─── SSRF & Input Validation Guard ───────────────────────────────────────────
  // Prohibit integer, octal, or hexadecimal IP notation bypasses
  if (
    /^(0x[0-9a-f]+|\d+)$/i.test(targetHost) ||
    /(^|\.)0x[0-9a-f]+(\.|$)/i.test(targetHost) ||
    /(^|\.)0\d+(\.|$)/.test(targetHost)
  ) {
    return res.status(400).json({
      error: 'Integer, octal, or hexadecimal IP notation is prohibited (SSRF Protection).'
    });
  }

  // Block link-local addresses, cloud metadata endpoints, and invalid formats
  const isInvalidFormat = !/^[a-z0-9.-]+$/.test(targetHost) || targetHost.length > 253;
  const isRestrictedTarget =
    targetHost === '0.0.0.0' ||
    targetHost.startsWith('169.254.') ||
    targetHost.startsWith('224.') ||
    targetHost.includes('metadata.google.internal') ||
    targetHost.includes('instance-data');

  if (isInvalidFormat || isRestrictedTarget) {
    return res.status(400).json({
      error: 'Invalid or restricted target host (SSRF Protection). Cloud metadata and link-local ranges are blocked.'
    });
  }

  // ─── Scope Whitelist & Scope Authorization Guard ──────────────────────────
  const isDirectIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(targetHost);
  if (isDirectIp) {
    if (!isPrivateIp(targetHost) && !isIpInAuthorizedScope(targetHost)) {
      return res.status(403).json({
        error: 'Target host is outside authorized scope whitelist. Probing public external IP addresses is prohibited (Scope Violation).'
      });
    }
  }

  // DNS Rebinding validation & Scope Enforcement: resolve hostname to verify resolved IP is safe
  if (targetHost !== 'localhost' && targetHost !== '127.0.0.1') {
    try {
      const resolved = await dns.promises.lookup(targetHost);
      const resolvedIp = resolved.address;
      if (
        resolvedIp === '0.0.0.0' ||
        resolvedIp.startsWith('169.254.') ||
        resolvedIp.startsWith('224.')
      ) {
        return res.status(400).json({
          error: 'Resolved target IP points to restricted cloud metadata or link-local range (SSRF Protection).'
        });
      }

      if (!isPrivateIp(resolvedIp) && !isIpInAuthorizedScope(resolvedIp) && resolvedIp !== '127.0.0.1') {
        return res.status(403).json({
          error: `Resolved target IP (${resolvedIp}) is outside authorized internal scope whitelist. Scanning public external hosts is prohibited (Scope Violation).`
        });
      }
    } catch {
      // Host resolution failed or offline
      if (!isDirectIp) {
        return res.status(400).json({ error: `Could not resolve hostname '${targetHost}'. Probe aborted.` });
      }
    }
  }

  const portsToScan = [
    { port: 21, name: 'FTP', service: 'File Transfer Protocol' },
    { port: 22, name: 'SSH', service: 'Secure Shell Remote Login' },
    { port: 23, name: 'Telnet', service: 'Unencrypted Telnet Text Protocol' },
    { port: 25, name: 'SMTP', service: 'Simple Mail Transfer Protocol' },
    { port: 53, name: 'DNS', service: 'Domain Name System' },
    { port: 80, name: 'HTTP', service: 'Web Server (HTTP)' },
    { port: 110, name: 'POP3', service: 'Post Office Protocol Mail' },
    { port: 135, name: 'MSRPC', service: 'Microsoft RPC Endpoint Mapper' },
    { port: 139, name: 'NetBIOS', service: 'NetBIOS Session Service' },
    { port: 143, name: 'IMAP', service: 'Internet Message Access Protocol' },
    { port: 443, name: 'HTTPS', service: 'Secure Web Server (HTTPS)' },
    { port: 445, name: 'SMB', service: 'Microsoft SMB File Sharing (MS17-010 Risk)' },
    { port: 1433, name: 'MSSQL', service: 'Microsoft SQL Server Database' },
    { port: 1521, name: 'Oracle', service: 'Oracle Database Listener' },
    { port: 3000, name: 'Dev-Server', service: 'Vite Development Server' },
    { port: 3306, name: 'MySQL', service: 'MySQL Database Server' },
    { port: 3389, name: 'RDP', service: 'Windows Remote Desktop Protocol' },
    { port: 5000, name: 'SOC-Backend', service: 'CyberMind SOC Express REST API' },
    { port: 5432, name: 'PostgreSQL', service: 'PostgreSQL Database Server' },
    { port: 6379, name: 'Redis', service: 'Redis In-Memory Key-Value Store' },
    { port: 8080, name: 'HTTP-Proxy', service: 'HTTP Proxy / Web Application' }
  ];

  const probePort = (host: string, portObj: { port: number; name: string; service: string }) => {
    return new Promise((resolve) => {
      const start = Date.now();
      const socket = new net.Socket();
      socket.setTimeout(1200);

      socket.on('connect', () => {
        const rtt = Date.now() - start;
        socket.destroy();
        resolve({
          port: portObj.port,
          protocol: 'tcp',
          state: 'open',
          service: `${portObj.name} - ${portObj.service}`,
          rtt: `${rtt}ms`,
          vulns: portObj.port === 445 ? 'Exposed SMB Port (Audit MS17-010 EternalBlue)' :
                portObj.port === 3389 ? 'Exposed RDP Port (Enforce NLA & MFA)' :
                portObj.port === 23 ? 'Insecure Telnet Protocol (Unencrypted)' :
                'Active TCP Service Listener'
        });
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve({
          port: portObj.port,
          protocol: 'tcp',
          state: 'filtered',
          service: portObj.name,
          rtt: 'Timeout',
          vulns: 'Connection timed out (Firewall Filtered)'
        });
      });

      socket.on('error', () => {
        socket.destroy();
        resolve({
          port: portObj.port,
          protocol: 'tcp',
          state: 'closed',
          service: portObj.name,
          rtt: 'Refused',
          vulns: 'Port closed (Connection refused)'
        });
      });

      socket.connect(portObj.port, host);
    });
  };

  try {
    const probeResults = await Promise.all(portsToScan.map(p => probePort(targetHost, p)));
    const openPorts = probeResults.filter((r: any) => r.state === 'open');

    return res.json({
      host: targetHost,
      scanTime: new Date().toISOString(),
      scannedPortsCount: portsToScan.length,
      openPorts: openPorts,
      allResults: probeResults
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});
