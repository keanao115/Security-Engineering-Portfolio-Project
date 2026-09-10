import { Request, Response, Router } from 'express';
import { createCisoAuditPdfReport } from '../services/pdfReportService.js';
import { memoryDb } from '../db/client.js';
import { requireRole } from '../middleware/auth.js';
import { RiskScoringService } from '../services/riskScoringService.js';

export const reportRouter = Router();

reportRouter.get('/', requireRole(['Admin', 'Analyst', 'Viewer']), (req: Request, res: Response) => {
  return res.json({
    reports: memoryDb.reports
  });
});

reportRouter.get('/risk-posture', requireRole(['Admin', 'Analyst', 'Viewer']), (_req: Request, res: Response) => {
  const posture = RiskScoringService.evaluateSystemPosture();
  return res.json(posture);
});

reportRouter.post('/pdf', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const { title, classification, summary } = req.body;
  const currentRisk = RiskScoringService.evaluateSystemPosture().overallScore;
  const riskScore = typeof req.body.riskScore === 'number' ? req.body.riskScore : currentRisk;

  const pdfBuffer = createCisoAuditPdfReport({
    title,
    classification,
    riskScore,
    summary
  });

  const reportRecord = {
    id: memoryDb.reports.length + 1,
    report_title: title || 'CYBERMIND SOC PLATFORM - SECURITY AUDIT REPORT',
    classification: classification || 'CONFIDENTIAL / CISO AUDIT',
    risk_score: riskScore,
    created_at: new Date().toISOString()
  };

  memoryDb.reports.push(reportRecord);

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename=CyberMind_SOC_Security_Audit_Report.pdf');
  return res.send(pdfBuffer);
});
