import { Request, Response, Router } from 'express';
import { createCisoAuditPdfReport } from '../services/pdfReportService.js';
import { memoryDb } from '../db/client.js';
import { requireRole } from '../middleware/auth.js';

export const reportRouter = Router();

reportRouter.get('/', requireRole(['Admin', 'Analyst', 'Viewer']), (req: Request, res: Response) => {
  return res.json({
    reports: memoryDb.reports
  });
});

reportRouter.post('/pdf', requireRole(['Admin', 'Analyst']), (req: Request, res: Response) => {
  const { title, classification, riskScore, summary } = req.body;

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
    risk_score: riskScore || 92,
    created_at: new Date().toISOString()
  };

  memoryDb.reports.push(reportRecord);

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename=CyberMind_SOC_Security_Audit_Report.pdf');
  return res.send(pdfBuffer);
});
