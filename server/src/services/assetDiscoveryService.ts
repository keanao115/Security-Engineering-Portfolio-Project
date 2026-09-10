import { memoryDb, query } from '../db/client.js';
import { broadcastTelemetryEvent } from './websocketService.js';
import { loadPlatformConfig } from '../config/platformConfig.js';
import { buildRealAssetList } from './osNetworkDiscovery.js';

export interface DiscoveryScopeConfig {
  authorizedCidrs: string[]; // e.g. ["192.168.1.0/24", "10.0.0.0/16", "127.0.0.1/32"]
  scanSpeed: 'Normal' | 'Stealth' | 'Fast';
  verifyPermissions: boolean;
}

export interface DiscoveryJob {
  id: string;
  targetCidr: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  scanSpeed: 'Normal' | 'Stealth' | 'Fast';
  discoveredCount: number;
  scheduledIntervalMin: number;
  lastRun: string;
  nextRun?: string;
  createdBy: string;
}

export interface DiscoveredAsset {
  id?: number;
  hostname: string;
  ip_address: string;
  mac_address: string;
  os_name: string;
  status: string;
  installed_software: Array<{ name: string; version: string; riskFlag?: string }>;
  running_services: Array<{ port: number; service: string; critical?: boolean }>;
  owner: string;
  tags: string[];
  vulnerabilityCount: number;
  lastDiscoveredAt: string;
}

const discoveryConfig: DiscoveryScopeConfig = {
  authorizedCidrs: ['192.168.1.0/24', '10.0.0.0/16', '172.16.0.0/12', '127.0.0.1/32'],
  scanSpeed: 'Normal',
  verifyPermissions: true
};

const discoveryJobHistory: DiscoveryJob[] = [
  {
    id: 'JOB-DEF-001',
    targetCidr: '192.168.1.0/24',
    status: 'COMPLETED',
    scanSpeed: 'Normal',
    discoveredCount: 6,
    scheduledIntervalMin: 60,
    lastRun: new Date(Date.now() - 3600000).toISOString(),
    nextRun: new Date(Date.now() + 3600000).toISOString(),
    createdBy: 'SOC Automated Scheduler'
  }
];

// Active NodeJS intervals for scheduled jobs
const activeJobTimers = new Map<string, NodeJS.Timeout>();

// IP Bitwise Utilities
export function ipToLong(ip: string): number {
  if (ip === 'localhost') ip = '127.0.0.1';
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

export function isIpInCidr(ip: string, cidr: string): boolean {
  try {
    if (ip === '127.0.0.1' || ip === 'localhost') return true;
    const [range, bits = '32'] = cidr.split('/');
    const mask = ~(Math.pow(2, 32 - parseInt(bits, 10)) - 1);
    return (ipToLong(ip) & mask) === (ipToLong(range) & mask);
  } catch (e) {
    return false;
  }
}

export function isIpInAuthorizedScope(targetIp: string): boolean {
  return discoveryConfig.authorizedCidrs.some(cidr => isIpInCidr(targetIp, cidr));
}

export function getDiscoveryScopeConfig(): DiscoveryScopeConfig {
  return discoveryConfig;
}

export function updateDiscoveryScopeConfig(newConfig: Partial<DiscoveryScopeConfig>): DiscoveryScopeConfig {
  if (newConfig.authorizedCidrs) discoveryConfig.authorizedCidrs = newConfig.authorizedCidrs;
  if (newConfig.scanSpeed) discoveryConfig.scanSpeed = newConfig.scanSpeed;
  if (newConfig.verifyPermissions !== undefined) discoveryConfig.verifyPermissions = newConfig.verifyPermissions;
  return discoveryConfig;
}

export function getDiscoveryJobs(): DiscoveryJob[] {
  return discoveryJobHistory;
}

export async function runAuthorizedAssetSweep(targetCidr: string, scanSpeed: 'Normal' | 'Stealth' | 'Fast' = 'Normal') {
  const targetIp = targetCidr.split('/')[0];
  if (!isIpInAuthorizedScope(targetIp)) {
    throw new Error(`Target CIDR '${targetCidr}' is NOT within the administrator-approved authorization scope whitelist! Authorized ranges: ${discoveryConfig.authorizedCidrs.join(', ')}`);
  }

  const platformConfig = loadPlatformConfig();

  let discoveredHosts: (DiscoveredAsset & { isSynthetic?: boolean })[];

  if (platformConfig.platformMode === 'LIVE') {
    // ── LIVE MODE: Use real OS-level ARP table and network interface discovery ──
    try {
      const { assets: realAssets } = await buildRealAssetList();
      discoveredHosts = realAssets.map((asset: any) => ({
        hostname: asset.hostname || asset.ip_address,
        ip_address: asset.ip_address,
        mac_address: asset.mac_address || '00:00:00:00:00:00',
        os_name: asset.os_name || 'Unknown',
        status: 'Active',
        installed_software: asset.installed_software || [],
        running_services: asset.running_services || [],
        owner: asset.owner || 'Discovered via ARP',
        tags: asset.tags || ['Live Discovery'],
        vulnerabilityCount: asset.vulnerabilityCount || 0,
        lastDiscoveredAt: new Date().toISOString(),
        isSynthetic: false,
      }));
    } catch (err: any) {
      console.warn('[AssetDiscovery] Real discovery failed, returning empty result:', err.message);
      discoveredHosts = [];
    }
  } else {
    // ── DEMO MODE: Return clearly-labeled synthetic hosts for demonstration purposes ──
    // These are NOT real network observations. All data is fabricated for portfolio demonstration.
    discoveredHosts = [
      {
        hostname: 'DC-SRV-01.corp.internal',
        ip_address: '192.168.1.10',
        mac_address: '00:15:5D:01:2A:8C',
        os_name: 'Windows Server 2022 Datacenter',
        status: 'Active',
        installed_software: [
          { name: 'Microsoft SMB', version: 'v1.0', riskFlag: 'SMBv1 Deprecated' },
          { name: 'Active Directory Domain Services', version: 'v10.0' },
          { name: 'OpenSSL', version: '1.1.1k', riskFlag: 'Outdated Version' }
        ],
        running_services: [
          { port: 53, service: 'dns' },
          { port: 80, service: 'http' },
          { port: 445, service: 'smb', critical: true },
          { port: 3389, service: 'rdp', critical: true }
        ],
        owner: 'Domain Controller Admin',
        tags: ['Domain Controller', 'Critical', 'Internal Tier 0'],
        vulnerabilityCount: 2,
        lastDiscoveredAt: new Date().toISOString(),
        isSynthetic: true,
      },
      {
        hostname: 'web-prod-01.corp.internal',
        ip_address: '192.168.1.50',
        mac_address: '00:15:5D:04:3B:11',
        os_name: 'Ubuntu 22.04 LTS (Kernel 5.15)',
        status: 'Active',
        installed_software: [
          { name: 'Nginx', version: '1.18.0' },
          { name: 'Log4j Core', version: '2.14.1', riskFlag: 'CVE-2021-44228 Vulnerable' }
        ],
        running_services: [
          { port: 22, service: 'ssh' },
          { port: 80, service: 'http' },
          { port: 443, service: 'https' },
          { port: 8080, service: 'http-proxy' }
        ],
        owner: 'Web Infrastructure Team',
        tags: ['Production', 'DMZ', 'Web Front-End'],
        vulnerabilityCount: 3,
        lastDiscoveredAt: new Date().toISOString(),
        isSynthetic: true,
      },
      {
        hostname: 'workstation-win11-04',
        ip_address: '192.168.1.105',
        mac_address: '00:15:5D:88:99:AA',
        os_name: 'Windows 11 Enterprise (Build 22631)',
        status: 'Active',
        installed_software: [{ name: 'Microsoft Defender EDR', version: 'v4.18.24020' }],
        running_services: [{ port: 135, service: 'msrpc' }],
        owner: 'Corporate Endpoints',
        tags: ['Workstation', 'User Tier'],
        vulnerabilityCount: 0,
        lastDiscoveredAt: new Date().toISOString(),
        isSynthetic: true,
      },
      {
        hostname: 'db-cluster-01.corp.internal',
        ip_address: '192.168.1.80',
        mac_address: '00:15:5D:99:11:22',
        os_name: 'Red Hat Enterprise Linux 9.2',
        status: 'Active',
        installed_software: [
          { name: 'PostgreSQL Server', version: '15.3' },
          { name: 'Redis Cache', version: '7.0.11' }
        ],
        running_services: [
          { port: 22, service: 'ssh' },
          { port: 5432, service: 'postgresql', critical: true },
          { port: 6379, service: 'redis' }
        ],
        owner: 'Database Administration',
        tags: ['Database', 'PCI-DSS Scope', 'Critical'],
        vulnerabilityCount: 1,
        lastDiscoveredAt: new Date().toISOString(),
        isSynthetic: true,
      },
      {
        hostname: 'palo-firewall-gw.corp.internal',
        ip_address: '192.168.1.1',
        mac_address: '00:1B:17:00:AA:BB',
        os_name: 'Palo Alto PAN-OS 10.2.4',
        status: 'Active',
        installed_software: [{ name: 'PAN-OS Gateway', version: '10.2.4' }],
        running_services: [
          { port: 22, service: 'ssh' },
          { port: 443, service: 'https-mgmt', critical: true }
        ],
        owner: 'Network Security Team',
        tags: ['Perimeter Firewall', 'Infrastructure'],
        vulnerabilityCount: 0,
        lastDiscoveredAt: new Date().toISOString(),
        isSynthetic: true,
      },
      {
        hostname: 'vpn-gateway-01.corp.internal',
        ip_address: '10.0.4.15',
        mac_address: '00:15:5D:77:44:33',
        os_name: 'Cisco ASA OS 9.18',
        status: 'Active',
        installed_software: [{ name: 'Cisco AnyConnect', version: '4.10' }],
        running_services: [{ port: 8443, service: 'vpn-ssl' }],
        owner: 'Remote Access Admin',
        tags: ['VPN Gateway', 'External Ingress'],
        vulnerabilityCount: 1,
        lastDiscoveredAt: new Date().toISOString(),
        isSynthetic: true,
      }
    ];
  }

  // Synchronize discovered assets to memoryDb / Postgres
  discoveredHosts.forEach(host => {
    const existingIndex = memoryDb.assets.findIndex(a => a.ip_address === host.ip_address);
    if (existingIndex !== -1) {
      memoryDb.assets[existingIndex] = { ...memoryDb.assets[existingIndex], ...host };
    } else {
      memoryDb.assets.push({
        id: memoryDb.assets.length + 1,
        ...host
      });
    }

    query(
      `INSERT INTO assets (hostname, ip_address, mac_address, os_name, status, installed_software, running_services, owner, tags)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [host.hostname, host.ip_address, host.mac_address, host.os_name, host.status, JSON.stringify(host.installed_software), JSON.stringify(host.running_services), host.owner, JSON.stringify(host.tags)]
    ).catch(() => {});
  });

  broadcastTelemetryEvent({
    type: 'ASSET_SWEEP_COMPLETE',
    targetCidr,
    discoveredCount: discoveredHosts.length,
    timestamp: new Date().toISOString()
  });

  return {
    scannedCidr: targetCidr,
    authorizedScopeVerified: true,
    discoveredHostCount: discoveredHosts.length,
    assets: discoveredHosts
  };
}

export function scheduleDiscoveryJob(targetCidr: string, intervalMin: number, scanSpeed: 'Normal' | 'Stealth' | 'Fast' = 'Normal'): DiscoveryJob {
  const jobId = `JOB-${Date.now()}`;
  const job: DiscoveryJob = {
    id: jobId,
    targetCidr,
    status: 'PENDING',
    scanSpeed,
    discoveredCount: 0,
    scheduledIntervalMin: intervalMin,
    lastRun: new Date().toISOString(),
    nextRun: new Date(Date.now() + intervalMin * 60 * 1000).toISOString(),
    createdBy: 'SOC Analyst'
  };

  discoveryJobHistory.unshift(job);

  // Auto-run in backend on specified interval
  if (intervalMin > 0) {
    const timer = setInterval(async () => {
      try {
        job.status = 'RUNNING';
        const res = await runAuthorizedAssetSweep(targetCidr, scanSpeed);
        job.status = 'COMPLETED';
        job.discoveredCount = res.discoveredHostCount;
        job.lastRun = new Date().toISOString();
        job.nextRun = new Date(Date.now() + intervalMin * 60 * 1000).toISOString();
      } catch (err) {
        job.status = 'FAILED';
      }
    }, intervalMin * 60 * 1000);

    activeJobTimers.set(jobId, timer);
  }

  // Trigger initial sweep immediately
  runAuthorizedAssetSweep(targetCidr, scanSpeed).then(res => {
    job.status = 'COMPLETED';
    job.discoveredCount = res.discoveredHostCount;
  }).catch(() => {
    job.status = 'FAILED';
  });

  query(
    `INSERT INTO discovery_jobs (id, target_cidr, status, scan_speed, discovered_count, scheduled_interval_min, last_run, next_run)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [job.id, job.targetCidr, job.status, job.scanSpeed, job.discoveredCount, job.scheduledIntervalMin, job.lastRun, job.nextRun]
  ).catch(() => {});

  return job;
}
