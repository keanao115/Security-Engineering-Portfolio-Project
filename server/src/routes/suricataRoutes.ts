import { Request, Response, Router } from 'express';
import { SuricataCollectorService } from '../collectors/suricata/suricataCollector.js';
import { requireRole } from '../middleware/auth.js';

export const suricataRouter = Router();

// GET /api/suricata/status — Suricata IDS sensor health
suricataRouter.get('/status', requireRole(['Admin', 'Analyst', 'Viewer']), (_req: Request, res: Response) => {
  return res.json(SuricataCollectorService.getInstance().getSensorStatus());
});

// POST /api/suricata/eve — Ingest Suricata EVE JSON event
suricataRouter.post('/eve', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const eveEntry = req.body;
  if (!eveEntry || typeof eveEntry !== 'object') {
    return res.status(400).json({ error: 'Valid EVE JSON entry object is required' });
  }

  try {
    const event = SuricataCollectorService.getInstance().parseEveEntry(eveEntry);
    return res.json({ message: 'Suricata EVE entry ingested', event });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});
