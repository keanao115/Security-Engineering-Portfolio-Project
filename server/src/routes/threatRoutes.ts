import { Request, Response, Router } from 'express';
import { generateDefensiveAiAnalysis } from '../services/aiAnalysisService.js';
import { memoryDb } from '../db/client.js';
import { requireRole } from '../middleware/auth.js';
import net from 'net';

export const threatRouter = Router();

threatRouter.post('/analyze', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const { logs, findings, scan } = req.body;

  const result = generateDefensiveAiAnalysis({
    logs: logs || memoryDb.logs,
    findings: findings || memoryDb.findings,
    scan
  });

  return res.json(result);
});

threatRouter.get('/scan', requireRole(['Admin', 'Analyst']), async (req: Request, res: Response) => {
  const targetHost = ((req.query.target as string) || '127.0.0.1').trim().toLowerCase();

  // ─── SSRF & Input Validation Guard ───────────────────────────────────────────
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
