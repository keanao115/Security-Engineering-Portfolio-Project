import { Request, Response, Router } from 'express';
import { getSiemEvents, ingestSiemEvent, getSiemStats } from '../services/siemCollectorService.js';
import { evaluateMultiVectorCorrelation } from '../services/aiCorrelationEngine.js';
import { broadcastTelemetryEvent } from '../services/websocketService.js';
import { requireRole } from '../middleware/auth.js';

export const siemRouter = Router();

siemRouter.get('/events', (req: Request, res: Response) => {
  const { category, severity } = req.query;
  const events = getSiemEvents(category as string, severity as string);

  return res.json({
    total: events.length,
    events
  });
});

siemRouter.get('/stats', (req: Request, res: Response) => {
  const stats = getSiemStats();
  return res.json(stats);
});

siemRouter.post('/events', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const { sourceCategory, hostName, severity, eventId, mitreTechnique, summary, rawDetails } = req.body;

  if (!hostName || !summary) {
    return res.status(400).json({ error: 'hostName and summary are required for SIEM event ingestion' });
  }

  const newEvent = ingestSiemEvent({
    sourceCategory: sourceCategory || 'Windows_WEF',
    hostName,
    severity: severity || 'Medium',
    eventId: eventId || 'GENERIC',
    mitreTechnique: mitreTechnique || '',
    summary,
    rawDetails: rawDetails || {}
  });

  broadcastTelemetryEvent({ type: 'SIEM_EVENT', event: newEvent, timestamp: new Date().toISOString() });

  return res.status(201).json({ message: 'SIEM event ingested and correlated', event: newEvent });
});

siemRouter.post('/ingest/bulk', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const { events } = req.body;
  if (!Array.isArray(events)) {
    return res.status(400).json({ error: 'events must be an array' });
  }

  const ingested = events.map(e =>
    ingestSiemEvent({
      sourceCategory: e.sourceCategory || 'Windows_WEF',
      hostName: e.hostName || 'unknown-host',
      severity: e.severity || 'Medium',
      eventId: e.eventId || 'BULK_INGEST',
      mitreTechnique: e.mitreTechnique || '',
      summary: e.summary || 'Bulk ingested log entry',
      rawDetails: e.rawDetails || {}
    })
  );

  return res.status(201).json({ message: `Successfully ingested ${ingested.length} SIEM events`, total: ingested.length });
});

siemRouter.get('/correlate', (req: Request, res: Response) => {
  const result = evaluateMultiVectorCorrelation();
  return res.json(result);
});
