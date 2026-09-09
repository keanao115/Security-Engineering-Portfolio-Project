import { Request, Response, Router } from 'express';
import { InterfaceManager } from '../capture/interfaceManager.js';
import { CaptureManager } from '../capture/captureManager.js';
import { requireRole } from '../middleware/auth.js';

export const captureRouter = Router();

// GET /api/capture/interfaces — List network interfaces (Admin, Analyst, Viewer)
captureRouter.get('/interfaces', requireRole(['Admin', 'Analyst', 'Viewer']), (_req: Request, res: Response) => {
  const interfaces = InterfaceManager.getInterfaces();
  return res.json({ interfaces, count: interfaces.length });
});

// GET /api/capture/status — Capture engine status (Admin, Analyst, Viewer)
captureRouter.get('/status', requireRole(['Admin', 'Analyst', 'Viewer']), (_req: Request, res: Response) => {
  const status = CaptureManager.getInstance().getStatus();
  return res.json({ activeSession: status });
});

// POST /api/capture/start — Start capture session (Admin & Analyst Only)
captureRouter.post('/start', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const { interfaceId, bpfFilter, promiscuousMode } = req.body;
  if (!interfaceId) {
    return res.status(400).json({ error: 'interfaceId is required' });
  }

  try {
    const session = CaptureManager.getInstance().startCapture({
      interfaceId,
      bpfFilter,
      promiscuousMode,
    });
    return res.json({ message: 'Capture started', session });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /api/capture/stop — Stop capture session (Admin & Analyst Only)
captureRouter.post('/stop', requireRole(['Admin', 'Analyst']), (_req: Request, res: Response) => {
  const session = CaptureManager.getInstance().stopCapture();
  return res.json({ message: 'Capture stopped', session });
});

