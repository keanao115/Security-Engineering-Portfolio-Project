import { Request, Response, Router } from 'express';
import { SigmaYamlEngine } from '../services/sigmaYamlEngine.js';
import { requireRole, AuthenticatedRequest } from '../middleware/auth.js';
import { memoryDb } from '../db/client.js';

export const sigmaRouter = Router();

// GET /api/sigma/rules — List all loaded Sigma YAML detection rules
sigmaRouter.get('/rules', requireRole(['Admin', 'Analyst', 'Viewer']), (_req: Request, res: Response) => {
  const engine = SigmaYamlEngine.getInstance();
  const rules = engine.getAllRules().map((r) => ({
    id: r.id,
    title: r.title,
    status: r.status,
    level: r.level,
    description: r.description,
    author: r.author,
    tags: r.tags,
    mitreTechniques: SigmaYamlEngine.extractMitreTechniques(r.tags),
    logsource: r.logsource,
    falsepositives: r.falsepositives,
    response: r.response,
    rawYaml: r.rawYaml,
  }));

  return res.json({
    total: rules.length,
    rules,
  });
});

// GET /api/sigma/rules/:id — Get details & raw YAML for a specific rule
sigmaRouter.get('/rules/:id', requireRole(['Admin', 'Analyst', 'Viewer']), (req: Request, res: Response) => {
  const { id } = req.params;
  const engine = SigmaYamlEngine.getInstance();
  const rule = engine.getRuleById(id);

  if (!rule) {
    return res.status(404).json({ error: `Sigma rule '${id}' not found` });
  }

  return res.json({
    rule: {
      ...rule,
      mitreTechniques: SigmaYamlEngine.extractMitreTechniques(rule.tags),
    },
  });
});

// POST /api/sigma/test — Test arbitrary Sigma YAML against sample or recent events
sigmaRouter.post('/test', requireRole(['Admin', 'Analyst', 'Viewer']), (req: Request, res: Response) => {
  const { yaml: yamlContent, events } = req.body;

  if (!yamlContent || typeof yamlContent !== 'string') {
    return res.status(400).json({ error: "Missing required 'yaml' string in request body." });
  }

  const engine = SigmaYamlEngine.getInstance();
  const targetEvents = Array.isArray(events) && events.length > 0 ? events : memoryDb.logs.slice(-50);

  const testResult = engine.testRuleAgainstEvents(yamlContent, targetEvents);

  if (!testResult.success) {
    return res.status(400).json({
      success: false,
      error: testResult.error,
    });
  }

  return res.json({
    success: true,
    rule: {
      id: testResult.rule?.id,
      title: testResult.rule?.title,
      level: testResult.rule?.level,
      mitre: SigmaYamlEngine.extractMitreTechniques(testResult.rule?.tags),
    },
    totalEventsTested: targetEvents.length,
    matchCount: testResult.matches.length,
    matches: testResult.matches,
  });
});

// POST /api/sigma/rules — Add / Deploy a custom Sigma YAML rule (Detection-as-Code)
sigmaRouter.post('/rules', requireRole(['Admin', 'Analyst']), (req: AuthenticatedRequest, res: Response) => {
  const { yaml: yamlContent, persist } = req.body;

  if (!yamlContent || typeof yamlContent !== 'string') {
    return res.status(400).json({ error: "Missing required 'yaml' string in request body." });
  }

  const engine = SigmaYamlEngine.getInstance();
  const result = engine.registerRule(yamlContent, persist !== false);

  if (!result.success) {
    return res.status(400).json({
      success: false,
      error: result.error,
    });
  }

  return res.status(201).json({
    success: true,
    message: `Sigma rule '${result.rule?.id}' successfully compiled and registered.`,
    rule: {
      id: result.rule?.id,
      title: result.rule?.title,
      level: result.rule?.level,
      status: result.rule?.status,
      mitre: SigmaYamlEngine.extractMitreTechniques(result.rule?.tags),
    },
  });
});

// POST /api/sigma/reload — Hot-reload rules from disk
sigmaRouter.post('/reload', requireRole(['Admin', 'Analyst']), (_req: Request, res: Response) => {
  const engine = SigmaYamlEngine.getInstance();
  const result = engine.loadRulesFromDirectory();

  return res.json({
    success: true,
    message: `Reloaded ${result.loaded} Sigma YAML rules from disk.`,
    loadedCount: result.loaded,
    errors: result.errors,
  });
});
