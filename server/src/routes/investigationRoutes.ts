import { Request, Response, Router } from 'express';
import { EvidenceBundleService } from '../correlation/evidenceBundle.js';
import { TimelineEngine } from '../correlation/timelineEngine.js';
import { memoryDb, pushBounded } from '../db/client.js';
import { requireRole, AuthenticatedRequest } from '../middleware/auth.js';

export const investigationRouter = Router();

// GET /api/investigation/evidence-bundles — Multi-source evidence bundles
investigationRouter.get('/evidence-bundles', requireRole(['Admin', 'Analyst', 'Viewer']), (_req: Request, res: Response) => {
  const bundles = EvidenceBundleService.getEvidenceBundles();
  return res.json({ bundles, count: bundles.length });
});

// GET /api/investigation/timeline — Chronological incident timeline
investigationRouter.get('/timeline', requireRole(['Admin', 'Analyst', 'Viewer']), (req: Request, res: Response) => {
  const targetIp = req.query.ip as string | undefined;
  const timeline = TimelineEngine.getChronologicalTimeline(targetIp);
  return res.json({ timeline, count: timeline.length });
});

// GET /api/investigation/incidents — List all active SOC incidents / cases
investigationRouter.get('/incidents', requireRole(['Admin', 'Analyst', 'Viewer']), (_req: Request, res: Response) => {
  return res.json({
    incidents: memoryDb.incidents || [],
    total: (memoryDb.incidents || []).length
  });
});

// POST /api/investigation/incidents — Escalate an alert/bundle into a formal Incident
investigationRouter.post('/incidents', requireRole(['Admin', 'Analyst']), (req: AuthenticatedRequest, res: Response) => {
  const { title, severity, sourceIp, targetIp, mitreTechnique, summary, notes } = req.body;

  if (!title || typeof title !== 'string') {
    return res.status(400).json({ error: 'Incident title is required' });
  }

  const incidentId = `INC-${new Date().getFullYear()}-${String(memoryDb.incidents.length + 1).padStart(3, '0')}`;
  const newIncident = {
    id: incidentId,
    title: title.trim(),
    severity: ['Critical', 'High', 'Medium', 'Low', 'Info'].includes(severity) ? severity : 'Medium',
    status: 'New',
    assignedTo: req.user?.username || 'SOC Incident Lead Analyst',
    sourceIp: sourceIp || 'Unknown',
    targetIp: targetIp || 'Unknown',
    mitreTechnique: mitreTechnique || 'N/A',
    summary: summary || 'Escalated from SOC detection stream',
    notes: Array.isArray(notes) ? notes : notes ? [String(notes)] : [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  pushBounded(memoryDb.incidents, newIncident, 500);

  return res.status(201).json({
    message: 'Incident case created successfully',
    incident: newIncident
  });
});

// PATCH /api/investigation/incidents/:id — Update incident status, assignee, or notes
investigationRouter.patch('/incidents/:id', requireRole(['Admin', 'Analyst']), (req: AuthenticatedRequest, res: Response) => {
  const { id } = req.params;
  const { status, assignedTo, note } = req.body;

  const incident = memoryDb.incidents.find((inc: any) => inc.id === id);
  if (!incident) {
    return res.status(404).json({ error: `Incident ${id} not found` });
  }

  if (status && ['New', 'Investigating', 'Contained', 'Remediated', 'Closed'].includes(status)) {
    incident.status = status;
  }

  if (assignedTo && typeof assignedTo === 'string') {
    incident.assignedTo = assignedTo;
  }

  if (note && typeof note === 'string' && note.trim().length > 0) {
    if (!Array.isArray(incident.notes)) incident.notes = [];
    incident.notes.push(`[${new Date().toISOString()} by ${req.user?.username || 'Analyst'}] ${note.trim().slice(0, 1000)}`);
    if (incident.notes.length > 100) incident.notes.shift();
  }

  incident.updatedAt = new Date().toISOString();

  return res.json({
    message: `Incident ${id} updated`,
    incident
  });
});
