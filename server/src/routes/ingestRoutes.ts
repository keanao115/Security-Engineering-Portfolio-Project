import { Request, Response, Router } from 'express';
import { parseWindowsLogTelemetry } from '../adapters/windowsLogParser.js';
import { parseLinuxLogTelemetry } from '../adapters/linuxLogParser.js';
import { parseSuricataEveJson } from '../adapters/suricataParser.js';
import { parseNmapTelemetry } from '../adapters/nmapParser.js';
import { parseZapReport } from '../adapters/zapParser.js';
import { parseYaraSigmaResults } from '../adapters/yaraSigmaParser.js';
import { memoryDb, pushBatchBounded } from '../db/client.js';
import { scanWithSigmaRules, getSigmaRuleList } from '../services/sigmaRuleEngine.js';
import { ingestSiemEvent } from '../services/siemCollectorService.js';
import { enrichWithThreatIntel } from '../services/threatIntelService.js';
import { broadcastTelemetryEvent } from '../services/websocketService.js';
import { requireRole } from '../middleware/auth.js';

export const ingestRouter = Router();

// POST /api/ingest/logs — Parse + Sigma scan + SIEM ingest pipeline
ingestRouter.post('/logs', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const { logText, logType } = req.body;

  if (!logText) {
    return res.status(400).json({ error: 'logText is required for log ingestion' });
  }

  let winLogs: any[] = [];
  let lnxLogs: any[] = [];
  let eveAlerts: any[] = [];
  let detections: any[] = [];

  // ── Parse by type ─────────────────────────────────────────────────────────
  if (logType === 'windows' || logText.includes('<Event')) {
    winLogs = parseWindowsLogTelemetry(logText);
    pushBatchBounded(memoryDb.logs, winLogs);
  } else if (logType === 'suricata' || logText.includes('event_type')) {
    eveAlerts = parseSuricataEveJson(logText);
    pushBatchBounded(memoryDb.logs, eveAlerts);
  } else if (logType === 'yara' || logType === 'sigma') {
    detections = parseYaraSigmaResults(logText);
    pushBatchBounded(memoryDb.logs, detections);
  } else {
    lnxLogs = parseLinuxLogTelemetry(logText);
    pushBatchBounded(memoryDb.logs, lnxLogs);
  }

  const allParsed = [...winLogs, ...lnxLogs, ...eveAlerts, ...detections];

  // ── Run Sigma Detection Rules ──────────────────────────────────────────────
  const sigmaResults = scanWithSigmaRules(allParsed);

  // ── Auto-ingest Sigma hits into SIEM stream ───────────────────────────────
  const siemIngested: any[] = [];
  for (const detection of sigmaResults.detections) {
    for (const match of detection.matches) {
      // Threat intel enrichment on any IPs in the event
      const ip = detection.event.ip || detection.event.srcIp;
      const threatLabel = ip ? enrichWithThreatIntel(ip) : null;

      const siemEvent = ingestSiemEvent({
        sourceCategory: winLogs.length > 0 ? 'Windows_WEF' : 'Linux_Auditd',
        hostName: detection.event.computer || detection.event.hostname || 'unknown-host',
        severity: match.level === 'critical' ? 'Critical' : match.level === 'high' ? 'High' : 'Medium',
        eventId: detection.event.eventId || match.ruleId,
        mitreTechnique: match.mitre.join(', '),
        summary: `[Sigma: ${match.ruleTitle}] ${detection.event.details || detection.event.commandLine || 'Event matched detection rule'}${threatLabel ? ` | Threat Intel: ${threatLabel}` : ''}`,
        rawDetails: {
          sigmaRuleId: match.ruleId,
          sigmaLevel: match.level,
          response: match.response,
          originalEvent: detection.event,
          threatIntel: threatLabel,
        },
      });

      siemIngested.push(siemEvent);

      // Broadcast immediately for real-time alert
      broadcastTelemetryEvent({
        type: 'SIGMA_ALERT',
        siemEvent,
        sigmaMatch: match,
        timestamp: new Date().toISOString(),
      });
    }
  }

  return res.json({
    message: `Telemetry ingested — ${allParsed.length} events parsed, ${sigmaResults.matchedEvents} triggered Sigma rules`,
    summary: {
      windowsCount: winLogs.length,
      linuxCount: lnxLogs.length,
      suricataCount: eveAlerts.length,
      detectionCount: detections.length,
      sigmaHits: sigmaResults.totalDetections,
      siemEventsCreated: siemIngested.length,
    },
    sigmaResults: {
      rulesEvaluated: sigmaResults.totalEvents,
      matchedEvents: sigmaResults.matchedEvents,
      detectionSummary: sigmaResults.summary,
      detections: sigmaResults.detections.map(d => ({
        eventId: d.event.eventId,
        host: d.event.computer,
        rules: d.matches.map(m => ({ id: m.ruleId, title: m.ruleTitle, level: m.level, mitre: m.mitre, response: m.response })),
      })),
    },
    parsed: { windowsLogs: winLogs, linuxLogs: lnxLogs, suricataAlerts: eveAlerts, detections },
  });
});

// POST /api/ingest/nmap — Parse Nmap XML or text output + NVD CVE enrichment
ingestRouter.post('/nmap', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const { rawOutput } = req.body;
  if (!rawOutput) return res.status(400).json({ error: 'Nmap rawOutput required' });

  const parsed = parseNmapTelemetry(rawOutput);
  return res.json({ message: 'Nmap telemetry parsed successfully', scan: parsed });
});

// POST /api/ingest/zap — Parse OWASP ZAP report
ingestRouter.post('/zap', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const { reportContent } = req.body;
  if (!reportContent) return res.status(400).json({ error: 'ZAP reportContent required' });

  const findings = parseZapReport(reportContent);
  pushBatchBounded(memoryDb.findings, findings);
  return res.json({ message: 'OWASP ZAP report ingested successfully', count: findings.length, findings });
});

// GET /api/ingest/sigma/rules — List all loaded Sigma detection rules
ingestRouter.get('/sigma/rules', (_req: Request, res: Response) => {
  const rules = getSigmaRuleList();
  return res.json({ total: rules.length, rules });
});

// POST /api/ingest/sigma/scan — Scan arbitrary JSON events with Sigma rules
ingestRouter.post('/sigma/scan', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const { events } = req.body;
  if (!Array.isArray(events)) {
    return res.status(400).json({ error: 'events must be a JSON array' });
  }

  const result = scanWithSigmaRules(events);
  return res.json(result);
});
