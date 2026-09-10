import { memoryDb } from '../db/client.js';

export interface RiskFactors {
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
  lowVulns?: number;
  openPortsCount: number;
}

export interface RiskScoreBreakdown {
  criticalPenalty: number;
  highPenalty: number;
  mediumPenalty: number;
  openPortsPenalty: number;
  totalPenalty: number;
}

export interface RiskScoreResult {
  overallScore: number;
  networkProtectionScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  penalty: number;
  breakdown: RiskScoreBreakdown;
  methodology: string;
  evaluatedAt: string;
}

/**
 * RiskScoringService
 * Centralizes the transparent, explainable CVSS-weighted risk scoring model.
 *
 * Formula:
 *   Score = 100 - (Critical * 18 + High * 9 + Medium * 3 + OpenPorts * 2)
 *   Network Posture = 100 - (OpenPorts * 5 + Critical * 10)
 *
 * Ensures mathematical consistency across Dashboard, SIEM, CISO Audit Reports,
 * and AI Security Copilot analytics.
 */
export class RiskScoringService {
  public static calculateRisk(factors: RiskFactors): RiskScoreResult {
    const critical = Math.max(0, factors.criticalVulns || 0);
    const high = Math.max(0, factors.highVulns || 0);
    const medium = Math.max(0, factors.mediumVulns || 0);
    const openPorts = Math.max(0, factors.openPortsCount || 0);

    const criticalPenalty = critical * 18;
    const highPenalty = high * 9;
    const mediumPenalty = medium * 3;
    const openPortsPenalty = openPorts * 2;
    const totalPenalty = criticalPenalty + highPenalty + mediumPenalty + openPortsPenalty;

    const overallScore = Math.max(0, Math.min(100, 100 - totalPenalty));
    const networkProtectionScore = Math.max(0, Math.min(100, 100 - (openPorts * 5) - (critical * 10)));

    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    if (overallScore >= 85) {
      riskLevel = 'LOW';
    } else if (overallScore >= 70) {
      riskLevel = 'MEDIUM';
    } else if (overallScore >= 50) {
      riskLevel = 'HIGH';
    } else {
      riskLevel = 'CRITICAL';
    }

    return {
      overallScore,
      networkProtectionScore,
      riskLevel,
      penalty: totalPenalty,
      breakdown: {
        criticalPenalty,
        highPenalty,
        mediumPenalty,
        openPortsPenalty,
        totalPenalty,
      },
      methodology: 'CVSS v3.1 Weighted Penalty: 100 - (Critical*18 + High*9 + Medium*3 + OpenPorts*2)',
      evaluatedAt: new Date().toISOString(),
    };
  }

  /**
   * Evaluates current system risk score dynamically from in-memory database entities.
   */
  public static evaluateSystemPosture(): RiskScoreResult {
    const vulns = memoryDb.findings || [];
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    for (const v of vulns) {
      const sev = (v.severity || '').toUpperCase();
      if (sev === 'CRITICAL') critical++;
      else if (sev === 'HIGH') high++;
      else if (sev === 'MEDIUM') medium++;
      else if (sev === 'LOW') low++;
    }

    // Tally open ports across discovered assets
    const assets = memoryDb.assets || [];
    let openPortsCount = 0;
    for (const asset of assets) {
      if (Array.isArray(asset.running_services)) {
        openPortsCount += asset.running_services.length;
      }
    }

    return this.calculateRisk({
      criticalVulns: critical,
      highVulns: high,
      mediumVulns: medium,
      lowVulns: low,
      openPortsCount,
    });
  }
}
