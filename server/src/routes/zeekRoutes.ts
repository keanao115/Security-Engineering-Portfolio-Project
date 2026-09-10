import { Request, Response, Router } from 'express';
import { ZeekCollectorService } from '../collectors/zeek/zeekCollector.js';
import { requireRole } from '../middleware/auth.js';

export const zeekRouter = Router();

// GET /api/zeek/status — Sensor health & event counts
zeekRouter.get('/status', requireRole(['Admin', 'Analyst', 'Viewer']), (_req: Request, res: Response) => {
  return res.json(ZeekCollectorService.getInstance().getSensorStatus());
});

// POST /api/zeek/ingest — Ingest JSON Zeek log payload
zeekRouter.post('/ingest', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const { logType, entry } = req.body;
  if (!logType || !entry) {
    return res.status(400).json({ error: 'logType and entry JSON object are required' });
  }

  try {
    const event = ZeekCollectorService.getInstance().parseZeekLog(logType, entry);
    return res.json({ message: 'Zeek log ingested', event });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});
