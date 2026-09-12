import { Request, Response, Router } from 'express';
import { SoarService } from '../services/soarService.js';
import { requireRole, AuthenticatedRequest } from '../middleware/auth.js';

export const soarRouter = Router();

// POST /api/soar/playbooks/block-ip — Enforce containment block on malicious IP
soarRouter.post('/playbooks/block-ip', requireRole(['Admin', 'Analyst']), (req: AuthenticatedRequest, res: Response) => {
  const { ip, reason, severity, incidentId, ruleId, force } = req.body;

  if (!ip || typeof ip !== 'string') {
    return res.status(400).json({ error: "Missing required 'ip' parameter." });
  }

  const result = SoarService.blockIp({
    ip: ip.trim(),
    reason: reason || 'SOAR Automated Threat Containment',
    severity: severity || 'High',
    incidentId,
    ruleId,
    analyst: req.user?.username || 'SOC Analyst',
    force: Boolean(force),
  });

  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }

  return res.status(201).json({
    message: `IP ${ip} blocked successfully. Firewall containment rules generated.`,
    record: result.record,
  });
});

// POST /api/soar/playbooks/unblock-ip — Remove IP from containment block
soarRouter.post('/playbooks/unblock-ip', requireRole(['Admin', 'Analyst']), (req: AuthenticatedRequest, res: Response) => {
  const { ip } = req.body;

  if (!ip || typeof ip !== 'string') {
    return res.status(400).json({ error: "Missing required 'ip' parameter." });
  }

  const result = SoarService.unblockIp(ip.trim(), req.user?.username || 'SOC Analyst');
  if (!result.success) {
    return res.status(404).json({ error: result.error });
  }

  return res.json({
    message: `IP ${ip} unblocked successfully.`,
  });
});

// GET /api/soar/blocked-ips — List all actively blocked IPs
soarRouter.get('/blocked-ips', requireRole(['Admin', 'Analyst', 'Viewer']), (_req: Request, res: Response) => {
  const blockedIps = SoarService.getBlockedIps();
  return res.json({
    total: blockedIps.length,
    blockedIps,
  });
});

// POST /api/soar/playbooks/webhook — Dispatch alert to Slack or TheHive
soarRouter.post('/playbooks/webhook', requireRole(['Admin', 'Analyst', 'Viewer']), async (req: AuthenticatedRequest, res: Response) => {
  const { destinationType, webhookUrl, incidentId, title, severity, details, targetIp, mitreTechnique } = req.body;

  if (!title || typeof title !== 'string') {
    return res.status(400).json({ error: "Missing required 'title' field." });
  }

  const result = await SoarService.dispatchWebhookAlert({
    destinationType: destinationType || 'slack',
    webhookUrl,
    incidentId,
    title: title.trim(),
    severity: severity || 'High',
    details: details || 'SOAR Playbook event dispatch',
    targetIp,
    mitreTechnique,
    operator: req.user?.username || 'SOC Playbook Orchestrator',
  });

  if (!result.success && !result.simulated) {
    return res.status(result.status || 500).json({
      error: result.error || 'Failed to dispatch webhook alert.',
      payload: result.payload,
    });
  }

  return res.json({
    message: result.simulated
      ? `Alert simulated for ${destinationType?.toUpperCase() || 'SLACK'} (Audit log recorded).`
      : `Alert successfully dispatched to ${destinationType?.toUpperCase() || 'SLACK'}.`,
    simulated: result.simulated,
    status: result.status,
    payload: result.payload,
  });
});

// POST /api/soar/playbooks/generate-rules — Preview firewall rules for an IP without committing block
soarRouter.post('/playbooks/generate-rules', requireRole(['Admin', 'Analyst', 'Viewer']), (req: Request, res: Response) => {
  const { ip, reason } = req.body;

  if (!ip || typeof ip !== 'string') {
    return res.status(400).json({ error: "Missing required 'ip' parameter." });
  }

  if (!SoarService.isValidIp(ip.trim())) {
    return res.status(400).json({ error: `Invalid IP format: '${ip}'` });
  }

  const rules = SoarService.generateFirewallRules(ip.trim(), reason);
  return res.json({ rules });
});

// POST /api/soar/playbooks/isolate-host — Generate EDR endpoint network isolation script
soarRouter.post('/playbooks/isolate-host', requireRole(['Admin', 'Analyst', 'Viewer']), (req: Request, res: Response) => {
  const { hostOrIp, os } = req.body;

  if (!hostOrIp || typeof hostOrIp !== 'string') {
    return res.status(400).json({ error: "Missing required 'hostOrIp' parameter." });
  }

  const scripts = SoarService.generateHostIsolationScript(hostOrIp.trim(), os === 'linux' ? 'linux' : 'windows');
  return res.json({
    target: hostOrIp.trim(),
    os: os === 'linux' ? 'linux' : 'windows',
    ...scripts,
  });
});

// GET /api/soar/history — View execution history
soarRouter.get('/history', requireRole(['Admin', 'Analyst', 'Viewer']), (req: Request, res: Response) => {
  const limit = Math.min(parseInt((req.query.limit as string) || '50', 10), 200);
  const history = SoarService.getExecutionHistory(limit);

  return res.json({
    total: history.length,
    history,
  });
});
