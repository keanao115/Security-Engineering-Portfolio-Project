import { RiskScoringService } from './riskScoringService.js';

export interface AiAnalysisSummary {
  riskScore: number;
  postureStatus: 'OPTIMAL' | 'ELEVATED_RISK' | 'ACTION_REQUIRED';
  executiveSummary: string;
  mitreCoverage: Array<{ technique: string; description: string }>;
  prioritizedRemediations: string[];
}

export function generateDefensiveAiAnalysis(telemetryData: {
  logs?: any[];
  findings?: any[];
  scan?: any;
}): AiAnalysisSummary {
  const logCount = telemetryData.logs?.length || 0;
  const findings = telemetryData.findings || [];
  const openPorts = telemetryData.scan?.openPorts?.length || 0;

  // Count findings by severity for CVSS-weighted scoring
  const criticalVulns = findings.filter((f: any) => (f.severity || '').toUpperCase() === 'CRITICAL').length;
  const highVulns = findings.filter((f: any) => (f.severity || '').toUpperCase() === 'HIGH').length;
  const mediumVulns = findings.filter((f: any) => (f.severity || '').toUpperCase() === 'MEDIUM').length;

  // Use the canonical CVSS-weighted risk scoring model (consistent with Dashboard, SIEM, CISO reports)
  const riskResult = RiskScoringService.calculateRisk({
    criticalVulns,
    highVulns,
    mediumVulns,
    openPortsCount: openPorts,
  });

  const riskScore = riskResult.overallScore;
  const postureStatus: AiAnalysisSummary['postureStatus'] =
    riskScore >= 85 ? 'OPTIMAL' : riskScore >= 70 ? 'ELEVATED_RISK' : 'ACTION_REQUIRED';

  const executiveSummary = `Security analysis evaluated ${logCount} log telemetry events, ${openPorts} active service endpoints, and ${findings.length} security findings (${criticalVulns} Critical, ${highVulns} High, ${mediumVulns} Medium). System security posture is currently rated at ${riskScore}/100 (${postureStatus}). Scoring methodology: ${riskResult.methodology}. Recommended focus: network perimeter access restriction and prompt patch deployment.`;

  const mitreCoverage = [
    { technique: 'T1110.001', description: 'Password Guessing / SSH Brute Force Monitoring' },
    { technique: 'T1059.001', description: 'PowerShell Encoded Command Auditing' },
    { technique: 'T1071.001', description: 'Application Protocol C2 Traffic Filter' },
    { technique: 'T1070.001', description: 'Event Log Clearing Verification' }
  ];

  const prioritizedRemediations = [
    'Enforce Multi-Factor Authentication (MFA) on all SSH and RDP management endpoints.',
    'Restrict incoming SMB (TCP 445) and RDP (TCP 3389) traffic via perimeter firewalls.',
    'Upgrade legacy software packages (Log4j, Apache httpd) to latest vendor-patched builds.',
    'Enable immutable audit log streaming to a centralized SIEM collector.'
  ];

  return {
    riskScore,
    postureStatus,
    executiveSummary,
    mitreCoverage,
    prioritizedRemediations
  };
}
