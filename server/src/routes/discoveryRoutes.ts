import { Request, Response, Router } from 'express';
import {
  getDiscoveryScopeConfig,
  updateDiscoveryScopeConfig,
  runAuthorizedAssetSweep,
  getDiscoveryJobs,
  scheduleDiscoveryJob
} from '../services/assetDiscoveryService.js';
import { runLocalNetworkDiscovery, buildRealAssetList, getArpTable, getActiveConnections } from '../services/osNetworkDiscovery.js';
import { requireRole } from '../middleware/auth.js';

export const discoveryRouter = Router();

// GET /api/discovery/scope (Admin, Analyst, Viewer)
discoveryRouter.get('/scope', requireRole(['Admin', 'Analyst', 'Viewer']), (req: Request, res: Response) => {
  const config = getDiscoveryScopeConfig();
  return res.json(config);
});

// POST /api/discovery/scope (Admin Only)
discoveryRouter.post('/scope', requireRole(['Admin']), (req: Request, res: Response) => {
  const updated = updateDiscoveryScopeConfig(req.body);
  return res.json({ message: 'Discovery CIDR scope updated', config: updated });
});

// POST /api/discovery/sweep — standard sweep (authorized CIDRs) (Admin & Analyst Only)
discoveryRouter.post('/sweep', requireRole(['Admin', 'Analyst']), async (req: Request, res: Response) => {
  const { targetCidr, scanSpeed } = req.body;
  try {
    const sweepResult = await runAuthorizedAssetSweep(targetCidr || '192.168.1.0/24', scanSpeed || 'Normal');
    return res.json(sweepResult);
  } catch (err: any) {
    return res.status(403).json({ error: 'Scope Authorization Violation', message: err.message });
  }
});

// GET /api/discovery/localhost — REAL OS-based local network discovery (Admin & Analyst Only)
discoveryRouter.get('/localhost', requireRole(['Admin', 'Analyst']), async (req: Request, res: Response) => {
  try {
    const result = await buildRealAssetList();
    return res.json({
      message: 'Real local network discovery complete (ARP table + active connections)',
      hostname: result.rawDiscovery.hostname,
      platform: result.rawDiscovery.platform,
      networkInterfaces: result.rawDiscovery.networkInterfaces,
      arpEntries: result.rawDiscovery.arpEntries,
      activeConnectionCount: result.rawDiscovery.activeConnections.length,
      activeConnections: result.rawDiscovery.activeConnections.slice(0, 30),
      discoveredAssets: result.assets,
      runAt: result.rawDiscovery.runAt,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/discovery/arp — Raw ARP table (Admin & Analyst Only)
discoveryRouter.get('/arp', requireRole(['Admin', 'Analyst']), async (req: Request, res: Response) => {
  try {
    const entries = await getArpTable();
    return res.json({ total: entries.length, entries });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /api/discovery/netstat — Real active connections (Admin & Analyst Only)
discoveryRouter.get('/netstat', requireRole(['Admin', 'Analyst']), async (req: Request, res: Response) => {
  try {
    const conns = await getActiveConnections();
    const listening = conns.filter(c => c.state === 'LISTENING' || c.state === 'LISTEN');
    const established = conns.filter(c => c.state === 'ESTABLISHED');
    return res.json({
      total: conns.length,
      listening: listening.length,
      established: established.length,
      connections: conns,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

discoveryRouter.get('/jobs', requireRole(['Admin', 'Analyst', 'Viewer']), (req: Request, res: Response) => {
  const jobs = getDiscoveryJobs();
  return res.json({ total: jobs.length, jobs });
});

discoveryRouter.post('/jobs/schedule', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const { targetCidr, intervalMin, scanSpeed } = req.body;
  if (!targetCidr) {
    return res.status(400).json({ error: 'targetCidr is required' });
  }
  try {
    const job = scheduleDiscoveryJob(targetCidr, intervalMin || 60, scanSpeed || 'Normal');
    return res.status(201).json({ message: 'Discovery job scheduled', job });
  } catch (err: any) {
    return res.status(403).json({ error: err.message });
  }
});
