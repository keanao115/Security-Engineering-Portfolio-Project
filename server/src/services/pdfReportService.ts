import jsPDFModule from 'jspdf';

const jsPDF = (jsPDFModule as any).jsPDF || jsPDFModule;

export interface CisoAuditReportData {
  title?: string;
  classification?: string;
  riskScore?: number;
  summary?: string;
  findings?: Array<{
    title?: string;
    cve_id?: string;
    cveId?: string;
    severity?: string;
    cvss_score?: number;
    cvss?: number;
    affected_resource?: string;
    host?: string;
    mitigation?: string;
  }>;
  anomalies?: Array<{
    title?: string;
    severity?: string;
    mitreId?: string;
    target?: string;
    remediation?: string;
  }>;
}

function toSafePdfText(str: string | undefined, defaultFallback: string): string {
  if (!str || !str.trim()) return defaultFallback;
  // If string contains non-Latin1 / CJK characters, extract ASCII or use default fallback
  const hasNonLatin = /[^\x00-\x7F]/.test(str);
  if (hasNonLatin) {
    const cleaned = str.replace(/[^\x20-\x7E\n\r\t]/g, ' ').replace(/\s+/g, ' ').trim();
    return cleaned.length >= 6 ? cleaned : defaultFallback;
  }
  return str.trim();
}

export function createCisoAuditPdfReport(data: CisoAuditReportData): Buffer {
  const doc = new jsPDF();
  const title = toSafePdfText(data.title, 'CYBERMIND SOC PLATFORM - SECURITY AUDIT REPORT');
  const classification = toSafePdfText(data.classification, 'CONFIDENTIAL / CISO AUDIT');
  const riskScore = data.riskScore ?? 92;

  // Header
  doc.setFontSize(16);
  doc.text(title, 14, 20);
  doc.setFontSize(10);
  doc.text(`Generated: ${new Date().toISOString()}`, 14, 28);
  doc.text(`Classification: ${classification}`, 14, 34);
  doc.text(`Overall Security Risk Score: ${riskScore} / 100`, 14, 40);

  // Section 1: Executive Summary
  doc.setFontSize(12);
  doc.text('1. Executive Telemetry Summary', 14, 50);
  doc.setFontSize(9);
  const summaryText = toSafePdfText(
    data.summary,
    'Defensive security sensors completed telemetry audit across enterprise assets. Real-time telemetry ingestion and correlation pipeline evaluated CVSS weighted posture.'
  );
  const splitSummary = doc.splitTextToSize(summaryText, 180);
  doc.text(splitSummary, 14, 56);

  let currentY = 56 + (splitSummary.length * 5) + 6;

  // Section 2: Correlated Vulnerabilities & Findings
  doc.setFontSize(12);
  doc.text('2. Correlated Vulnerabilities & Risk Findings', 14, currentY);
  currentY += 6;
  doc.setFontSize(9);

  const findingsList = (data.findings && data.findings.length > 0)
    ? data.findings.slice(0, 5)
    : [];

  if (findingsList.length === 0) {
    doc.text('• No active vulnerabilities identified across monitored enterprise assets (Pristine Posture).', 14, currentY);
    currentY += 5;
  } else {
    findingsList.forEach((f) => {
      const cve = f.cve_id || f.cveId || 'VULN-ID';
      const name = f.title || 'Security Finding';
      const sev = f.severity || 'High';
      const cvss = f.cvss_score || f.cvss || 7.5;
      const host = f.affected_resource || f.host || 'Enterprise Asset';

      doc.text(`• [${sev.toUpperCase()} | CVSS ${cvss}] ${cve} - ${name.substring(0, 50)} (Target: ${host})`, 14, currentY);
      currentY += 5;
    });
  }

  currentY += 6;

  // Section 3: Threat Indicators & MITRE ATT&CK Mappings
  doc.setFontSize(12);
  doc.text('3. Active Threat Detections & MITRE ATT&CK Framework', 14, currentY);
  currentY += 6;
  doc.setFontSize(9);

  const anomaliesList = (data.anomalies && data.anomalies.length > 0)
    ? data.anomalies.slice(0, 4)
    : [];

  if (anomaliesList.length === 0) {
    doc.text('- No anomalous threat detections recorded in current evaluation window (All Clear).', 14, currentY);
    currentY += 5;
  } else {
    anomaliesList.forEach((a) => {
      const mitre = a.mitreId || 'T1190';
      const titleText = a.title || 'Threat Vector';
      const sev = a.severity || 'High';
      doc.text(`- [${sev.toUpperCase()}] ${mitre}: ${titleText}`, 14, currentY);
      currentY += 5;
    });
  }

  currentY += 6;

  // Section 4: Prescriptive Defensive Remediation
  doc.setFontSize(12);
  doc.text('4. Defensive Remediation Guidance & Action Items', 14, currentY);
  currentY += 6;
  doc.setFontSize(9);

  if (findingsList.length === 0 && anomaliesList.length === 0) {
    doc.text('1. Maintain continuous telemetry ingestion across all network interfaces and SIEM channels.', 14, currentY);
    currentY += 5;
    doc.text('2. Enforce Multi-Factor Authentication (MFA) and least-privilege RBAC on all administrative surfaces.', 14, currentY);
    currentY += 5;
    doc.text('3. Regularly verify immutable log retention and schedule periodic attack simulations.', 14, currentY);
    currentY += 5;
  } else {
    doc.text('1. Immediately deploy perimeter firewall blocks and account lockout policies for flagged threat IPs.', 14, currentY);
    currentY += 5;
    doc.text('2. Prioritize patching identified high/critical CVE vulnerabilities across affected host systems.', 14, currentY);
    currentY += 5;
    doc.text('3. Enforce MFA on all remote management consoles and isolate exposed management ports.', 14, currentY);
    currentY += 5;
    doc.text('4. Continuous monitoring: ingest streaming Zeek/Suricata alerts and automate SIEM Sigma rule evaluations.', 14, currentY);
  }

  const arrayBuffer = doc.output('arraybuffer');
  return Buffer.from(arrayBuffer);
}
