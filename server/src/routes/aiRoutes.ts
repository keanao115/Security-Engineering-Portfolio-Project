import { Request, Response, Router } from 'express';
import {
  chatWithSocCopilot,
  analyzeLogsWithGemini,
  testAiConnection,
  ChatMessage,
  UserAiConfig
} from '../services/geminiAiService.js';
import { getSiemEvents } from '../services/siemCollectorService.js';
import { memoryDb } from '../db/client.js';
import { requireRole } from '../middleware/auth.js';

export const aiRouter = Router();

// POST /api/ai/chat — Real AI analysis (user-configured model or local model)
aiRouter.post('/chat', requireRole(['Admin', 'Analyst']), async (req: Request, res: Response) => {
  const { history, message, includeContext, apiKey, aiConfig } = req.body;
  const config: UserAiConfig = aiConfig || (apiKey ? { apiKey } : {});

  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'message field is required' });
  }

  const chatHistory: ChatMessage[] = Array.isArray(history)
    ? history.map((h: any) => ({ role: h.role, parts: h.parts }))
    : [];

  // Grounding with live SOC telemetry data
  const context = includeContext !== false ? {
    siemEvents: getSiemEvents().slice(0, 10),
    findings: memoryDb.findings.slice(0, 10),
    logs: memoryDb.logs.slice(0, 15),
    assets: memoryDb.assets,
  } : undefined;

  try {
    const reply = await chatWithSocCopilot(chatHistory, message, context, config);
    return res.json({
      reply,
      timestamp: new Date().toISOString(),
      provider: config.provider || (config.apiKey ? 'custom_api' : 'local_engine')
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /api/ai/analyze — Real SOC telemetry threat assessment
aiRouter.post('/analyze', requireRole(['Admin', 'Analyst']), async (req: Request, res: Response) => {
  const { logs, findings, scan, apiKey, aiConfig } = req.body;
  const config: UserAiConfig = aiConfig || (apiKey ? { apiKey } : {});

  const telemetry = {
    logs: logs || memoryDb.logs,
    findings: findings || memoryDb.findings,
    scan,
    siemEvents: getSiemEvents(),
    assets: memoryDb.assets,
  };

  try {
    const analysis = await analyzeLogsWithGemini(telemetry, config.apiKey);
    return res.json(analysis);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /api/ai/test-connection — Test user-configured API model (Admin Only)
aiRouter.post('/test-connection', requireRole(['Admin']), async (req: Request, res: Response) => {
  const { aiConfig } = req.body;
  if (!aiConfig || typeof aiConfig !== 'object') {
    return res.status(400).json({ error: 'aiConfig object is required' });
  }

  try {
    const result = await testAiConnection(aiConfig);
    return res.json(result);
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/ai/status — Returns active AI configuration & live telemetry grounding stats
aiRouter.get('/status', (_req: Request, res: Response) => {
  const hasKey = !!process.env.GEMINI_API_KEY;
  const siemEvents = getSiemEvents();

  return res.json({
    geminiConfigured: hasKey,
    serverDefaultModel: hasKey ? 'gemini-1.5-flash' : 'local_telemetry_engine',
    mode: hasKey ? 'AI_POWERED' : 'LOCAL_MODEL_INFERENCE',
    telemetryCounts: {
      siemEvents: siemEvents.length,
      criticalEvents: siemEvents.filter(e => e.severity === 'Critical').length,
      findings: memoryDb.findings.length,
      logs: memoryDb.logs.length,
      assets: memoryDb.assets.length,
    },
    message: hasKey
      ? 'Gemini AI is configured on server. Custom user API takes precedence if provided.'
      : 'No default server API key. Using local telemetry inference engine when user API is omitted.',
  });
});
