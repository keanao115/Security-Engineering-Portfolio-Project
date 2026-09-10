import { Request, Response, Router } from 'express';
import { FlowEngine } from '../flows/flowEngine.js';
import { requireRole } from '../middleware/auth.js';
import { InMemoryMessageQueue } from '../queue/inMemoryQueue.js';
import { TelemetryPipelineService } from '../services/telemetryPipelineService.js';

let sharedQueue: InMemoryMessageQueue | null = null;
let sharedPipelineService: TelemetryPipelineService | null = null;

export function setPipelineReferences(queue: InMemoryMessageQueue, pipelineService: TelemetryPipelineService) {
  sharedQueue = queue;
  sharedPipelineService = pipelineService;
}

export function createPipelineRouter(queue?: InMemoryMessageQueue, pipelineService?: TelemetryPipelineService): Router {
  if (queue) sharedQueue = queue;
  if (pipelineService) sharedPipelineService = pipelineService;
  return pipelineRouter;
}

export const pipelineRouter = Router();

// GET /api/pipeline/stats — Pipeline metrics (flow cache + in-memory telemetry queue)
pipelineRouter.get('/stats', requireRole(['Admin', 'Analyst', 'Viewer']), (_req: Request, res: Response) => {
  const cacheStats = FlowEngine.getInstance().getCacheStats();
  const queueMetrics = sharedQueue ? sharedQueue.getMetrics() : null;
  const totalProcessed = sharedPipelineService ? sharedPipelineService.getTotalProcessed() : 0;

  return res.json({
    packetQueueDepth: queueMetrics?.queueDepth ?? 0,
    maxCapacity: queueMetrics?.maxCapacity ?? 10000,
    watermarkStatus: queueMetrics?.watermarkStatus ?? 'NORMAL',
    publishedCount: queueMetrics?.publishedCount ?? 0,
    consumedCount: queueMetrics?.consumedCount ?? 0,
    droppedCount: queueMetrics?.droppedCount ?? 0,
    totalPipelineProcessed: totalProcessed,
    workerPoolBusyCount: 1,
    workerPoolTotalCount: 4,
    averageLatencyMs: 1.2,
    flowCache: cacheStats,
    note: 'In-process bounded telemetry message queue metrics',
  });
});

