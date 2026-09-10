import 'dotenv/config';
import express from 'express';
import http from 'http';
import helmet from 'helmet';
import cors from 'cors';
import { initDbConnection } from './db/client.js';
import { apiRateLimiter, ingestRateLimiter } from './middleware/rateLimiter.js';
import { authenticateJwt } from './middleware/auth.js';
import { authRouter } from './routes/authRoutes.js';
import { assetRouter } from './routes/assetRoutes.js';
import { ingestRouter } from './routes/ingestRoutes.js';
import { vulnerabilityRouter } from './routes/vulnerabilityRoutes.js';
import { reportRouter } from './routes/reportRoutes.js';
import { threatRouter } from './routes/threatRoutes.js';
import { networkFlowRouter } from './routes/networkFlowRoutes.js';
import { packetRouter } from './routes/packetRoutes.js';
import { discoveryRouter } from './routes/discoveryRoutes.js';
import { siemRouter } from './routes/siemRoutes.js';
import { aiRouter } from './routes/aiRoutes.js';
import { initWebSocketServer } from './services/websocketService.js';
import { startSyslogReceiver, getSyslogStats } from './services/syslogReceiverService.js';
import { loadThreatIntelFeeds, getThreatIntelStats, getActiveIocList } from './services/threatIntelService.js';
import { getSystemHealth } from './services/systemHealthService.js';

// Live Telemetry Collectors & Queue Layer
import { InMemoryMessageQueue } from './queue/inMemoryQueue.js';
import { TelemetryPipelineService } from './services/telemetryPipelineService.js';
import { SyslogCollectorService } from './collectors/syslogCollectorService.js';
import { WefCollectorService } from './collectors/wefCollectorService.js';
import { NetflowCollectorService } from './collectors/netflowCollectorService.js';
import { createCollectorRouter } from './routes/collectorRoutes.js';
import { generatePrometheusMetrics } from './metrics/prometheusExporter.js';

import { loadPlatformConfig } from './config/platformConfig.js';
import { platformRouter } from './routes/platformRoutes.js';
import { SyntheticFlowGenerator } from './demo/syntheticFlowGenerator.js';
import { seedDemoData } from './demo/seedDataService.js';

import { captureRouter } from './routes/captureRoutes.js';
import { zeekRouter } from './routes/zeekRoutes.js';
import { suricataRouter } from './routes/suricataRoutes.js';
import { pipelineRouter } from './routes/pipelineRoutes.js';
import { investigationRouter } from './routes/investigationRoutes.js';

const app = express();
const PORT = process.env.PORT || 5000;

// ─── Security Middlewares ────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ─── Global Rate Limiting ────────────────────────────────────────────────────
app.use('/api/', apiRateLimiter);

// ─── Telemetry Queue & Collector Pipeline Initialization ────────────────────
const messageQueue = new InMemoryMessageQueue(10000);
const pipelineService = new TelemetryPipelineService(messageQueue);
pipelineService.initializePipeline();

const syslogCollector = new SyslogCollectorService(
  {
    name: 'Syslog-Server',
    type: 'syslog',
    enabled: true,
    udpPort: 514,
    tcpPort: 514,
    maxPacketSizeBytes: 65536,
    rateLimitEventsPerSec: 500,
    rateLimitBurst: 2000,
    enableTls: false,
    enablePiiMasking: true,
    enabledVendorParsers: ['Linux', 'Cisco', 'PaloAlto', 'Fortinet'],
  },
  messageQueue
);

const wefCollector = new WefCollectorService(
  {
    name: 'Windows-Event-Collector',
    type: 'wef',
    enabled: true,
    httpPort: 5516,
    maxPacketSizeBytes: 2097152, // 2MB
    rateLimitEventsPerSec: 300,
    rateLimitBurst: 1000,
    enableTls: false,
    enablePiiMasking: true,
    enabledVendorParsers: ['Microsoft-Windows-Security-Auditing', 'Sysmon', 'PowerShell'],
  },
  messageQueue
);

const netflowCollector = new NetflowCollectorService(
  {
    name: 'NetFlow-IPFIX-Collector',
    type: 'netflow',
    enabled: true,
    udpPort: 2055,
    maxPacketSizeBytes: 65536,
    rateLimitEventsPerSec: 1000,
    rateLimitBurst: 5000,
    enableTls: false,
    enablePiiMasking: false,
    enabledVendorParsers: ['NetFlow-v5', 'NetFlow-v9', 'IPFIX'],
  },
  messageQueue
);

const collectors = [syslogCollector, wefCollector, netflowCollector];

// ─── Prometheus OpenMetrics Endpoint ───────────────────────────────────────
app.get('/metrics', (_req, res) => {
  res.setHeader('Content-Type', 'text/plain; version=0.0.4');
  res.send(generatePrometheusMetrics(collectors));
});

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  const systemHealth = await getSystemHealth();
  const syslogStats = getSyslogStats();
  const threatIntelStats = getThreatIntelStats();
  const geminiEnabled = !!process.env.GEMINI_API_KEY;

  res.json({
    status: 'HEALTHY',
    system: 'Intelligent Enterprise Security Operations Platform Engine',
    version: '3.0.0',
    timestamp: new Date().toISOString(),
    modules: [
      'Auth', 'Assets', 'Ingest', 'Vulnerabilities', 'Reports', 'Threats',
      'NetworkFlow', 'Packets', 'Discovery', 'SIEM', 'WebSocket',
      'GeminiAI', 'SyslogReceiver', 'ThreatIntel', 'GeoIP', 'NVD_CVE',
      'SyslogCollector', 'WefCollector', 'NetflowCollector', 'PrometheusMetrics'
    ],
    collectorHealth: collectors.map(c => c.getHealth()),
    realFeatures: {
      geminiAI: geminiEnabled ? 'ACTIVE' : 'FALLBACK (add GEMINI_API_KEY)',
      syslogReceiver: syslogStats,
      threatIntel: threatIntelStats,
      osDiscovery: 'ACTIVE (arp, netstat, os.networkInterfaces)',
      nvdCveApi: 'ACTIVE (services.nvd.nist.gov)',
      geoIp: 'ACTIVE (ip-api.com)',
      pcapParser: 'ACTIVE (binary PCAP, pure JS)',
      realTcpScanner: 'ACTIVE (net.Socket)',
    },
    systemHealth,
  });
});

// ─── REST Routes — Platform Mode & Enterprise Telemetry ───────────────────────
app.use('/api/platform', platformRouter);
app.use('/api/capture', authenticateJwt, captureRouter);
app.use('/api/zeek', authenticateJwt, zeekRouter);
app.use('/api/suricata', authenticateJwt, suricataRouter);
app.use('/api/pipeline', authenticateJwt, pipelineRouter);
app.use('/api/investigation', authenticateJwt, investigationRouter);

// ─── REST Routes — Core SOC ──────────────────────────────────────────────────
app.use('/api/auth', authRouter);
app.use('/api/assets', authenticateJwt, assetRouter);
app.use('/api/ingest', authenticateJwt, ingestRateLimiter, ingestRouter);
app.use('/api/vulnerabilities', authenticateJwt, vulnerabilityRouter);
app.use('/api/reports', authenticateJwt, reportRouter);
app.use('/api/threats', authenticateJwt, threatRouter);

// ─── REST Routes — Collector Management & Live Telemetry ─────────────────────
app.use('/api/collectors', authenticateJwt, createCollectorRouter(collectors));

// ─── REST Routes — Phase 2: Network Monitoring, PCAP, Discovery, SIEM ───────
app.use('/api/network-flows', authenticateJwt, networkFlowRouter);
app.use('/api/packets', authenticateJwt, packetRouter);
app.use('/api/discovery', authenticateJwt, discoveryRouter);
app.use('/api/siem', authenticateJwt, siemRouter);

// ─── REST Routes — Phase 4: Real AI, Threat Intel ───────────────────────────
app.use('/api/ai', authenticateJwt, aiRouter);

// Threat Intel IOC list (public read)
app.get('/api/threat-intel/iocs', authenticateJwt, (_req, res) => {
  res.json({ stats: getThreatIntelStats(), iocs: getActiveIocList().slice(0, 200) });
});

// Syslog receiver status
app.get('/api/syslog/status', authenticateJwt, (_req, res) => {
  res.json(getSyslogStats());
});

// ─── Error Handling ──────────────────────────────────────────────────────────
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('[SOC Backend Error]:', err.stack || err);
  res.status(500).json({ error: 'Internal SOC Backend Error', message: err.message });
});

// ─── HTTP Server + WebSocket ──────────────────────────────────────────────────
const httpServer = http.createServer(app);
initWebSocketServer(httpServer);

httpServer.listen(PORT, async () => {
  const platformConfig = loadPlatformConfig();

  console.log(`=======================================================`);
  console.log(`[Security Engineering Portfolio Project v3.0] Running on http://localhost:${PORT}`);
  console.log(`[Platform Mode] Operating Mode: ${platformConfig.platformMode} | Synthetic Data: ${platformConfig.enableSyntheticData ? 'ENABLED' : 'DISABLED'} | Seed Data: ${platformConfig.enableSeedData ? 'ENABLED' : 'DISABLED'}`);
  console.log(`[WebSocket] Live Telemetry Stream: ws://localhost:${PORT}/ws/telemetry`);
  console.log(`[Prometheus] OpenMetrics Endpoint: http://localhost:${PORT}/metrics`);
  console.log(`=======================================================`);

  await initDbConnection();

  // Start Enterprise Telemetry Collectors (Syslog RFC 3164/5424, WEF XML, NetFlow v5/v9/IPFIX)
  for (const c of collectors) {
    c.start().catch((err) => {
      console.warn(`[Collector Boot Warning] ${c.name} start delayed:`, err.message);
    });
  }

  // Conditionally seed assets or run synthetic generators ONLY if explicitly enabled in DEMO mode
  if (platformConfig.enableSeedData) {
    seedDemoData();
  }

  if (platformConfig.enableSyntheticData) {
    SyntheticFlowGenerator.getInstance().start();
  }

  // Load threat intel feeds asynchronously (non-blocking)
  loadThreatIntelFeeds().catch(err => {
    console.warn('[ThreatIntel] Initial feed load failed:', err.message);
  });

  const geminiStatus = process.env.GEMINI_API_KEY
    ? '[AI] Gemini 1.5 Flash: ACTIVE'
    : '[AI] Gemini: FALLBACK MODE (set GEMINI_API_KEY in server/.env)';
  console.log(geminiStatus);
});
