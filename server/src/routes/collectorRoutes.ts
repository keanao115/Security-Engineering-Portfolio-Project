import { Request, Response, Router } from 'express';
import { BaseCollector } from '../collectors/baseCollector.js';
import { WefCollectorService } from '../collectors/wefCollectorService.js';
import { memoryDb } from '../db/client.js';
import { requireRole } from '../middleware/auth.js';

export function createCollectorRouter(collectors: BaseCollector[]): Router {
  const router = Router();
  const collectorMap = new Map<string, BaseCollector>();
  for (const c of collectors) {
    collectorMap.set(c.name.toLowerCase(), c);
    collectorMap.set(c.type.toLowerCase(), c);
  }

  // GET /api/collectors/status — List all collectors & lifecycle states
  router.get('/status', (_req: Request, res: Response) => {
    const statuses = collectors.map((c) => c.getHealth());
    return res.json({ count: statuses.length, collectors: statuses });
  });

  // GET /api/collectors/health — Liveness & Readiness for K8s Probes
  router.get('/health', (_req: Request, res: Response) => {
    const healthReports = collectors.map((c) => c.getHealth());
    const allLive = healthReports.every((h) => h.liveness);
    const statusCode = allLive ? 200 : 503;

    return res.status(statusCode).json({
      status: allLive ? 'HEALTHY' : 'DEGRADED',
      timestamp: new Date().toISOString(),
      collectors: healthReports,
    });
  });

  // GET /api/collectors/metrics — Collector Performance & Watermark Metrics
  router.get('/metrics', (_req: Request, res: Response) => {
    const metrics = collectors.map((c) => c.getMetrics());
    const totalEps = metrics.reduce((sum, m) => sum + m.eventsPerSecond, 0);
    const totalEvents = metrics.reduce((sum, m) => sum + m.eventsProcessedTotal, 0);
    const totalDropped = metrics.reduce((sum, m) => sum + m.droppedPacketsTotal, 0);

    return res.json({
      totalEventsProcessed: totalEvents,
      aggregateEventsPerSec: totalEps,
      totalDroppedPackets: totalDropped,
      collectors: metrics,
    });
  });

  // GET /api/collectors/events — Query & Paginate Normalized Security Events
  router.get('/events', (req: Request, res: Response) => {
    const { collector, severity, vendor, q, page = '1', limit = '50' } = req.query;

    let filtered = [...memoryDb.unifiedEvents];

    if (collector) {
      filtered = filtered.filter((e) => e.collector === String(collector).toLowerCase());
    }
    if (severity) {
      filtered = filtered.filter((e) => e.severity.toLowerCase() === String(severity).toLowerCase());
    }
    if (vendor) {
      filtered = filtered.filter((e) => e.vendor.toLowerCase().includes(String(vendor).toLowerCase()));
    }
    if (q) {
      const queryStr = String(q).toLowerCase();
      filtered = filtered.filter(
        (e) =>
          e.host.toLowerCase().includes(queryStr) ||
          e.ip.includes(queryStr) ||
          e.event_type.toLowerCase().includes(queryStr) ||
          e.raw.toLowerCase().includes(queryStr)
      );
    }

    const pageNum = Math.max(1, parseInt(String(page), 10));
    const limitNum = Math.min(200, Math.max(1, parseInt(String(limit), 10)));

    const total = filtered.length;
    const startIndex = (pageNum - 1) * limitNum;
    const paginated = filtered.slice(startIndex, startIndex + limitNum);

    return res.json({
      total,
      page: pageNum,
      limit: limitNum,
      totalPages: Math.ceil(total / limitNum),
      events: paginated,
    });
  });

  // POST /api/collectors/:name/start — Lifecycle Start (Admin Only)
  router.post('/:name/start', requireRole(['Admin']), async (req: Request, res: Response) => {
    const collector = collectorMap.get(req.params.name.toLowerCase());
    if (!collector) return res.status(404).json({ error: `Collector "${req.params.name}" not found` });

    try {
      await collector.start();
      return res.json({ message: `Collector ${collector.name} started`, health: collector.getHealth() });
    } catch (err: any) {
      return res.status(500).json({ error: `Failed starting collector: ${err.message}` });
    }
  });

  // POST /api/collectors/:name/pause — Lifecycle Pause (Admin Only)
  router.post('/:name/pause', requireRole(['Admin']), async (req: Request, res: Response) => {
    const collector = collectorMap.get(req.params.name.toLowerCase());
    if (!collector) return res.status(404).json({ error: `Collector "${req.params.name}" not found` });

    await collector.pause();
    return res.json({ message: `Collector ${collector.name} paused`, health: collector.getHealth() });
  });

  // POST /api/collectors/:name/resume — Lifecycle Resume (Admin Only)
  router.post('/:name/resume', requireRole(['Admin']), async (req: Request, res: Response) => {
    const collector = collectorMap.get(req.params.name.toLowerCase());
    if (!collector) return res.status(404).json({ error: `Collector "${req.params.name}" not found` });

    await collector.resume();
    return res.json({ message: `Collector ${collector.name} resumed`, health: collector.getHealth() });
  });

  // POST /api/collectors/:name/stop — Lifecycle Stop (Admin Only)
  router.post('/:name/stop', requireRole(['Admin']), async (req: Request, res: Response) => {
    const collector = collectorMap.get(req.params.name.toLowerCase());
    if (!collector) return res.status(404).json({ error: `Collector "${req.params.name}" not found` });

    await collector.stop();
    return res.json({ message: `Collector ${collector.name} stopped`, health: collector.getHealth() });
  });

  // POST /api/collectors/:name/restart — Lifecycle Restart (Admin Only)
  router.post('/:name/restart', requireRole(['Admin']), async (req: Request, res: Response) => {
    const collector = collectorMap.get(req.params.name.toLowerCase());
    if (!collector) return res.status(404).json({ error: `Collector "${req.params.name}" not found` });

    await collector.restart();
    return res.json({ message: `Collector ${collector.name} restarted`, health: collector.getHealth() });
  });

  // POST /api/collectors/wef/ingest — Windows Event Forwarding HTTP Payload Ingestion
  router.post('/wef/ingest', async (req: Request, res: Response) => {
    const wefCollector = collectorMap.get('wef') as WefCollectorService;
    if (!wefCollector) return res.status(503).json({ error: 'WEF collector not initialized' });

    const rawPayload = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    const sourceIp = req.ip || req.socket.remoteAddress || '127.0.0.1';

    const success = await wefCollector.ingestWefPayload(rawPayload, sourceIp);

    if (success) {
      return res.json({ status: 'ACCEPTED', collector: 'wef' });
    } else {
      return res.status(429).json({ error: 'WEF Ingestion rate limited, paused, or buffer full' });
    }
  });

  return router;
}
