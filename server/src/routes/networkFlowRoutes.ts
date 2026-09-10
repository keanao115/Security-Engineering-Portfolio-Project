import { Request, Response, Router } from 'express';
import {
  getLiveNetworkFlows,
  ingestNetFlowRecord,
  calculateNetworkBandwidthMetrics,
  getTopTalkers
} from '../services/networkFlowService.js';
import { broadcastTelemetryEvent } from '../services/websocketService.js';
import { requireRole } from '../middleware/auth.js';
import { isPrivateIp } from '../services/geoIpService.js';

export const networkFlowRouter = Router();

networkFlowRouter.get('/', requireRole(['Admin', 'Analyst', 'Viewer']), (req: Request, res: Response) => {
  const { protocol, anomaly, direction } = req.query;
  const flows = getLiveNetworkFlows({
    protocol: protocol as string,
    anomalyOnly: anomaly === 'true',
    direction: direction as string
  });
  const metrics = calculateNetworkBandwidthMetrics();
  return res.json({ metrics, flows });
});

networkFlowRouter.get('/metrics', requireRole(['Admin', 'Analyst', 'Viewer']), (req: Request, res: Response) => {
  const metrics = calculateNetworkBandwidthMetrics();
  return res.json(metrics);
});

networkFlowRouter.get('/top-talkers', requireRole(['Admin', 'Analyst', 'Viewer']), (req: Request, res: Response) => {
  const talkers = getTopTalkers();
  return res.json({ topTalkers: talkers });
});

networkFlowRouter.post('/ingest', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const { sourceType, srcIp, srcPort, destIp, destPort, protocol, bytes, packets, flags, direction, vlanId, geoCountry } = req.body;

  if (!srcIp || !destIp) {
    return res.status(400).json({ error: 'srcIp and destIp are required for NetFlow record' });
  }

  const isInternalSrc = isPrivateIp(srcIp);
  const isInternalDst = isPrivateIp(destIp);
  const inferredDirection = direction || (isInternalSrc && isInternalDst ? 'LATERAL' : isInternalSrc ? 'OUTBOUND' : 'INBOUND');

  const record = ingestNetFlowRecord({
    sourceType: sourceType || 'NetFlow_v9',
    srcIp,
    srcPort: srcPort || 0,
    destIp,
    destPort: destPort || 80,
    protocol: protocol || 'TCP',
    bytes: bytes || 1024,
    packets: packets || 8,
    durationMs: 120,
    flags: flags || 'ACK',
    direction: inferredDirection,
    vlanId: vlanId || 1,
    geoCountry: geoCountry || (isInternalSrc ? 'INTERNAL' : 'US')
  });

  broadcastTelemetryEvent({
    type: 'NETFLOW_RECORD',
    record,
    timestamp: new Date().toISOString()
  });

  return res.status(201).json({ message: 'NetFlow record ingested successfully', record });
});
