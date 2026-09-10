import { Request, Response, Router } from 'express';
import multer from 'multer';
import { parsePcapMetadata, getPcapHistory } from '../services/packetAnalysisService.js';
import { parsePcapBuffer } from '../services/pcapBinaryParser.js';
import { createPcapUploadProvenance } from '../provenance/provenanceFactory.js';
import { requireRole } from '../middleware/auth.js';

export const packetRouter = Router();

// Multer: store uploaded file in memory as Buffer (no disk writes needed)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max
  fileFilter: (_req, file, cb) => {
    const allowed = ['.pcap', '.pcapng', '.cap'];
    const ext = file.originalname.toLowerCase().slice(file.originalname.lastIndexOf('.'));
    if (allowed.includes(ext) || file.mimetype === 'application/octet-stream') {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type: ${ext}. Only .pcap, .pcapng, .cap files are accepted.`));
    }
  },
});

// POST /api/packets/upload — Real binary PCAP file upload and parse
packetRouter.post('/upload', requireRole(['Admin', 'Analyst']), upload.single('pcapFile'), (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No PCAP file uploaded. Use multipart/form-data with field name "pcapFile".' });
  }

  try {
    const buffer: Buffer = req.file.buffer;
    const fileName = req.file.originalname;

    // Parse the real binary PCAP
    const parseResult = parsePcapBuffer(buffer);

    if (!parseResult.isValid) {
      return res.status(422).json({
        error: parseResult.error || 'Invalid PCAP file',
        hint: 'File must be a valid PCAP capture (magic bytes: 0xa1b2c3d4 or 0xd4c3b2a1)',
      });
    }

    const sessionId = `PCAP-${Date.now()}`;
    const provenance = createPcapUploadProvenance(fileName, sessionId);

    // Convert to the legacy ParsedPcapSummary format for frontend compatibility
    const summary = {
      id: sessionId,
      pcapFileName: fileName,
      totalPackets: parseResult.totalPackets,
      validPackets: parseResult.validPackets,
      captureDurationSec: parseResult.captureDurationSec,
      uploadedAt: new Date().toISOString(),
      fileSizeBytes: buffer.length,
      linkType: parseResult.linkType,
      provenance,
      protocolDistribution: Object.entries(parseResult.protocolCounts)
        .map(([protocol, count]) => ({
          protocol,
          count,
          percentage: parseResult.validPackets > 0
            ? parseFloat(((count / parseResult.validPackets) * 100).toFixed(1))
            : 0,
        }))
        .sort((a, b) => b.count - a.count),
      dnsQueries: parseResult.dnsRecords.map(d => ({
        timestamp: d.timestamp,
        clientIp: d.clientIp,
        queryDomain: d.queryDomain,
        recordType: d.recordType,
        resolvedIp: d.resolvedIps[0] || 'NXDOMAIN',
        dgaScore: d.dgaScore,
        isSuspicious: d.isSuspicious,
      })),
      httpSessions: parseResult.httpRecords,
      tlsHandshakes: parseResult.tlsRecords,
      tcpFlows: parseResult.tcpFlows,
      flaggedThreats: parseResult.flaggedThreats,
      realParse: true,
    };

    return res.json({
      message: `PCAP file "${fileName}" parsed successfully`,
      summary,
    });
  } catch (err: any) {
    console.error('[PCAP Upload] Parse error:', err.message);
    return res.status(500).json({ error: `PCAP parse failed: ${err.message}` });
  }
});

// GET /api/packets/sample — Demo sample using legacy service
packetRouter.get('/sample', (req: Request, res: Response) => {
  const summary = parsePcapMetadata('enterprise_demo_capture.pcap');
  return res.json({ ...summary, realParse: false, note: 'Sample data — upload a real .pcap file to /api/packets/upload' });
});

// POST /api/packets/analyze-pcap — Legacy text-based route (kept for compatibility)
packetRouter.post('/analyze-pcap', (req: Request, res: Response) => {
  const { fileName, rawBufferText } = req.body;
  const summary = parsePcapMetadata(fileName || 'uploaded_capture.pcap', rawBufferText);
  return res.json({ message: 'PCAP metadata generated', summary, realParse: false });
});

// GET /api/packets/history — Past PCAP session list
packetRouter.get('/history', (req: Request, res: Response) => {
  const history = getPcapHistory();
  return res.json({ total: history.length, sessions: history });
});

// GET /api/packets/stats — Aggregate stats
packetRouter.get('/stats', (req: Request, res: Response) => {
  const history = getPcapHistory();
  const totalAnalyzed = history.length;
  const totalThreats = history.reduce((acc, s) => acc + s.flaggedThreats.length, 0);
  return res.json({ totalAnalyzed, totalThreats, sessions: history.length });
});
