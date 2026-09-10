export interface ZapFinding {
  id: string;
  sourceTool: string;
  cveId: string;
  title: string;
  severity: string;
  cvssScore: number;
  affectedResource: string;
  description: string;
  evidence: string;
  mitigation: string;
}

export function parseZapReport(rawContent: string): ZapFinding[] {
  const findings: ZapFinding[] = [];

  try {
    const data = JSON.parse(rawContent);
    const alerts = Array.isArray(data) ? data : (data.site?.alerts || data.alerts || []);

    alerts.forEach((alert: any, idx: number) => {
      const risk = alert.riskdesc || alert.risk || 'Medium';
      const severity = risk.toLowerCase().includes('high') ? 'High' :
                       risk.toLowerCase().includes('critical') ? 'Critical' :
                       risk.toLowerCase().includes('low') ? 'Low' : 'Medium';

      findings.push({
        id: `ZAP-${idx + 1}`,
        sourceTool: 'OWASP ZAP',
        cveId: alert.cweid ? `CWE-${alert.cweid}` : 'CWE-200',
        title: alert.name || alert.alert || 'Web Security Alert',
        severity,
        cvssScore: severity === 'Critical' ? 9.0 : severity === 'High' ? 7.5 : 5.0,
        affectedResource: alert.url || alert.uri || 'Web Application Perimeter',
        description: alert.desc || alert.description || 'Web application configuration security finding',
        evidence: alert.evidence || alert.other || 'HTTP Header / Payload response evidence recorded by OWASP ZAP',
        mitigation: alert.solution || 'Enforce security headers, input sanitization, and HTTPS redirection.'
      });
    });
  } catch (err) {
    // Attempt XML alertitem parsing if report is XML
    if (rawContent.includes('<alertitem>') || rawContent.includes('<OWASPZAPReport>')) {
      const alertBlocks = rawContent.split('</alertitem>');
      alertBlocks.forEach((block, idx) => {
        if (!block.includes('<alertitem>')) return;
        const nameMatch = block.match(/<alert>([^<]+)<\/alert>/);
        const riskMatch = block.match(/<riskdesc>([^<]+)<\/riskdesc>/);
        const cweMatch = block.match(/<cweid>([^<]+)<\/cweid>/);
        const urlMatch = block.match(/<uri>([^<]+)<\/uri>/);
        const descMatch = block.match(/<desc>([^<]+)<\/desc>/);
        const solMatch = block.match(/<solution>([^<]+)<\/solution>/);

        const risk = riskMatch ? riskMatch[1] : 'Medium';
        const severity = risk.toLowerCase().includes('high') ? 'High' :
                         risk.toLowerCase().includes('critical') ? 'Critical' :
                         risk.toLowerCase().includes('low') ? 'Low' : 'Medium';

        findings.push({
          id: `ZAP-XML-${idx + 1}`,
          sourceTool: 'OWASP ZAP (XML)',
          cveId: cweMatch ? `CWE-${cweMatch[1]}` : 'CWE-200',
          title: nameMatch ? nameMatch[1] : 'Web Security Finding',
          severity,
          cvssScore: severity === 'Critical' ? 9.0 : severity === 'High' ? 7.5 : 5.0,
          affectedResource: urlMatch ? urlMatch[1] : 'Web Application Endpoint',
          description: descMatch ? descMatch[1] : 'Vulnerability identified by OWASP ZAP XML report',
          evidence: 'Identified by automated dynamic application security scan',
          mitigation: solMatch ? solMatch[1] : 'Enforce defensive security headers and sanitization.'
        });
      });
    }
  }

  return findings;
}
