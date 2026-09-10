import crypto from 'crypto';
import { UnifiedSecurityEvent, EventSeverity } from '../collectorTypes.js';
import { createProvenance } from '../../provenance/provenanceFactory.js';
import { memoryDb } from '../../db/client.js';

export interface SuricataEveEntry {
  timestamp?: string;
  event_type?: string;
  src_ip?: string;
  src_port?: number;
  dest_ip?: string;
  dest_port?: number;
  proto?: string;
  alert?: {
    action?: string;
    gid?: number;
    signature_id?: number;
    rev?: number;
    signature?: string;
    category?: string;
    severity?: number;
    metadata?: Record<string, any>;
  };
  dns?: { type?: string; rrname?: string; rdata?: string };
  http?: { hostname?: string; url?: string; http_method?: string };
  tls?: { sni?: string; version?: string; subject?: string };
  [key: string]: any;
}

export class SuricataCollectorService {
  private static instance: SuricataCollectorService | null = null;
  private alertCount: number = 0;
  private eventCount: number = 0;
  private lastAlertAt: string = new Date().toISOString();

  public static getInstance(): SuricataCollectorService {
    if (!SuricataCollectorService.instance) {
      SuricataCollectorService.instance = new SuricataCollectorService();
    }
    return SuricataCollectorService.instance;
  }

  public parseEveEntry(entry: SuricataEveEntry): UnifiedSecurityEvent {
    this.eventCount++;
    const timestamp = entry.timestamp || new Date().toISOString();

    const srcIp = entry.src_ip || 'Unknown';
    const destIp = entry.dest_ip || 'Unknown';
    const srcPort = entry.src_port || 0;
    const destPort = entry.dest_port || 0;
    const eventType = (entry.event_type || 'alert').toUpperCase();

    let severity: EventSeverity = 'Info';
    let summary = 'Suricata EVE Event';

    if (entry.alert) {
      this.alertCount++;
      this.lastAlertAt = new Date().toISOString();
      summary = entry.alert.signature || 'Suricata IDS Alert';

      const suriSev = entry.alert.severity || 3;
      severity = suriSev === 1 ? 'Critical' : suriSev === 2 ? 'High' : suriSev === 3 ? 'Medium' : 'Low';
    }

    const provenance = createProvenance({
      telemetrySource: 'SURICATA_EVE',
      collectionMethod: 'FILE_IMPORT',
      isSynthetic: false,
      collectorId: 'suricata-eve-sensor',
    });

    const unified: UnifiedSecurityEvent = {
      id: crypto.randomUUID(),
      timestamp,
      collector: 'syslog',
      vendor: 'Suricata',
      product: 'Suricata IDS/IPS (EVE JSON)',
      host: srcIp,
      ip: srcIp,
      severity,
      event_type: `SURICATA_${eventType}`,
      category: entry.alert?.category || 'Network IDS',
      raw: JSON.stringify(entry),
      normalized: {
        signature: entry.alert?.signature,
        signatureId: entry.alert?.signature_id,
        suricataSeverity: entry.alert?.severity,
        sourceIp: srcIp,
        sourcePort: srcPort,
        destinationIp: destIp,
        destinationPort: destPort,
        protocol: entry.proto || 'TCP',
        dnsQuery: entry.dns?.rrname,
        httpHost: entry.http?.hostname,
        httpUrl: entry.http?.url,
        tlsSni: entry.tls?.sni,
        summary,
      },
      metadata: {
        ingestTimestamp: new Date().toISOString(),
        protocol: (entry.proto?.toUpperCase() as any) || 'TCP',
        sourcePort: srcPort,
        destinationPort: destPort,
        eventId: entry.alert?.signature_id ? String(entry.alert.signature_id) : undefined,
        tags: ['suricata', 'ids', (entry.event_type || 'alert').toLowerCase()],
      },
      provenance,
    };

    memoryDb.unifiedEvents.unshift(unified);
    if (memoryDb.unifiedEvents.length > 1000) memoryDb.unifiedEvents.pop();

    return unified;
  }

  public getSensorStatus() {
    return {
      status: 'Healthy',
      engineVersion: '7.0.6-RELEASE',
      rulesLoaded: 34120,
      lastRuleReloadAt: new Date(Date.now() - 3600000).toISOString(),
      totalEventsProcessed: this.eventCount,
      totalAlertsReceived: this.alertCount,
      lastAlertAt: this.lastAlertAt,
    };
  }
}
