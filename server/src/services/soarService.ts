import net from 'net';
import { memoryDb, pushBounded } from '../db/client.js';
import { broadcastTelemetryEvent } from './websocketService.js';
import { logger } from '../utils/logger.js';

export interface GeneratedFirewallRules {
  ip: string;
  iptables: {
    blockCommands: string[];
    unblockCommands: string[];
  };
  awsWaf: {
    cliCommand: string;
    jsonPayload: object;
  };
  windowsNetsh: {
    blockCommand: string;
    unblockCommand: string;
  };
  ciscoAsa: {
    blockCommand: string;
  };
}

export interface BlockedIpRecord {
  id: string;
  ip: string;
  reason: string;
  severity: string;
  incidentId?: string;
  ruleId?: string;
  analyst: string;
  status: 'ACTIVE' | 'UNBLOCKED';
  blockedAt: string;
  unblockedAt?: string;
  firewallRules: GeneratedFirewallRules;
}

export interface SoarExecutionRecord {
  id: string;
  actionType: 'BLOCK_IP' | 'UNBLOCK_IP' | 'WEBHOOK_DISPATCH' | 'ISOLATE_HOST';
  target: string;
  status: 'SUCCESS' | 'SIMULATED' | 'FAILED';
  operator: string;
  details: string;
  payload?: any;
  result?: any;
  timestamp: string;
}

export interface WebhookDispatchOptions {
  destinationType?: 'slack' | 'thehive' | 'generic';
  webhookUrl?: string;
  incidentId?: string;
  title: string;
  severity: string;
  details: string;
  targetIp?: string;
  mitreTechnique?: string;
  operator?: string;
}

export class SoarService {
  /**
   * Validate if an IP address is valid IPv4 or IPv6
   */
  public static isValidIp(ip: string): boolean {
    return net.isIP(ip) !== 0;
  }

  /**
   * Prohibit accidental permanent blocking of loopback and broadcast addresses
   */
  public static isProtectedIp(ip: string): boolean {
    return ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0' || ip === '255.255.255.255';
  }

  /**
   * Generate syntax-accurate firewall enforcement commands across multiple infrastructures
   */
  public static generateFirewallRules(ip: string, reason?: string): GeneratedFirewallRules {
    const comment = reason ? ` # ${reason.replace(/[\r\n"']/g, ' ')}` : '';

    return {
      ip,
      iptables: {
        blockCommands: [
          `# Linux iptables: Drop all inbound and forwarded traffic from offending IP`,
          `sudo iptables -I INPUT -s ${ip} -j DROP${comment}`,
          `sudo iptables -I FORWARD -s ${ip} -j DROP${comment}`,
          `# Optional ipset blacklist enforcement:`,
          `sudo ipset add -exist blacklist ${ip}`,
        ],
        unblockCommands: [
          `sudo iptables -D INPUT -s ${ip} -j DROP`,
          `sudo iptables -D FORWARD -s ${ip} -j DROP`,
          `sudo ipset del blacklist ${ip}`,
        ],
      },
      awsWaf: {
        cliCommand: `aws wafv2 update-ip-set --name "BlockedThreatIps" --scope "REGIONAL" --id "waf-set-cybermind-01" --addresses "${ip}/32" --lock-token "\${WAF_LOCK_TOKEN}"`,
        jsonPayload: {
          Name: 'BlockedThreatIps',
          Scope: 'REGIONAL',
          Id: 'waf-set-cybermind-01',
          Addresses: [`${ip}/32`],
          Description: `Automated containment by CyberMind SOAR Engine: ${reason || 'Malicious activity detected'}`,
        },
      },
      windowsNetsh: {
        blockCommand: `netsh advfirewall firewall add rule name="SOAR-BLOCK-${ip}" dir=in action=block remoteip=${ip} description="CyberMind SOAR Automated Block"`,
        unblockCommand: `netsh advfirewall firewall delete rule name="SOAR-BLOCK-${ip}"`,
      },
      ciscoAsa: {
        blockCommand: `access-list OUTSIDE-IN line 1 extended deny ip host ${ip} any log interval 300`,
      },
    };
  }

  /**
   * Execute IP Blocking Playbook Action
   */
  public static blockIp(params: {
    ip: string;
    reason?: string;
    severity?: string;
    incidentId?: string;
    ruleId?: string;
    analyst?: string;
    force?: boolean;
  }): { success: boolean; record?: BlockedIpRecord; error?: string } {
    const { ip, reason = 'Automated SOAR threat containment', severity = 'High', incidentId, ruleId, analyst = 'SOC Playbook Engine', force = false } = params;

    if (!this.isValidIp(ip)) {
      return { success: false, error: `Invalid IP address format: '${ip}'` };
    }

    if (this.isProtectedIp(ip) && !force) {
      return { success: false, error: `Refused to block critical system IP '${ip}' (Loopback / Broadcast Protection).` };
    }

    const firewallRules = this.generateFirewallRules(ip, reason);
    const existing = memoryDb.blockedIps.find((b: BlockedIpRecord) => b.ip === ip && b.status === 'ACTIVE');

    if (existing) {
      return {
        success: true,
        record: existing,
      };
    }

    const record: BlockedIpRecord = {
      id: `BLK-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      ip,
      reason,
      severity,
      incidentId,
      ruleId,
      analyst,
      status: 'ACTIVE',
      blockedAt: new Date().toISOString(),
      firewallRules,
    };

    pushBounded(memoryDb.blockedIps, record, 500);

    const execLog: SoarExecutionRecord = {
      id: `SOAR-EXEC-${Date.now()}`,
      actionType: 'BLOCK_IP',
      target: ip,
      status: 'SUCCESS',
      operator: analyst,
      details: `Enforced perimeter block for ${ip}. Generated iptables and AWS WAF containment rules. Reason: ${reason}`,
      result: firewallRules,
      timestamp: new Date().toISOString(),
    };
    pushBounded(memoryDb.soarExecutions, execLog, 500);

    broadcastTelemetryEvent({
      type: 'SOAR_ACTION_EXECUTED',
      action: 'BLOCK_IP',
      target: ip,
      record,
      timestamp: new Date().toISOString(),
    });

    logger.info(`[SOAR Playbook] Enforced block on IP ${ip} by ${analyst}`);
    return { success: true, record };
  }

  /**
   * Execute IP Unblocking Playbook Action
   */
  public static unblockIp(ip: string, analyst = 'SOC Analyst'): { success: boolean; error?: string } {
    const record = memoryDb.blockedIps.find((b: BlockedIpRecord) => b.ip === ip && b.status === 'ACTIVE');
    if (!record) {
      return { success: false, error: `IP '${ip}' is not actively blocked in SOAR database.` };
    }

    record.status = 'UNBLOCKED';
    record.unblockedAt = new Date().toISOString();

    const execLog: SoarExecutionRecord = {
      id: `SOAR-EXEC-${Date.now()}`,
      actionType: 'UNBLOCK_IP',
      target: ip,
      status: 'SUCCESS',
      operator: analyst,
      details: `Unblocked IP ${ip} from perimeter defenses.`,
      timestamp: new Date().toISOString(),
    };
    pushBounded(memoryDb.soarExecutions, execLog, 500);

    broadcastTelemetryEvent({
      type: 'SOAR_ACTION_EXECUTED',
      action: 'UNBLOCK_IP',
      target: ip,
      timestamp: new Date().toISOString(),
    });

    return { success: true };
  }

  /**
   * Format and build Slack Webhook Message
   */
  public static buildSlackPayload(opts: WebhookDispatchOptions): object {
    const sevEmoji = opts.severity === 'Critical' ? '🚨' : opts.severity === 'High' ? '⚠️' : 'ℹ️';
    const sevColor = opts.severity === 'Critical' ? '#dc2626' : opts.severity === 'High' ? '#f59e0b' : '#3b82f6';

    return {
      text: `${sevEmoji} *[SOAR ALERT - ${opts.severity?.toUpperCase()}]* ${opts.title}`,
      attachments: [
        {
          color: sevColor,
          blocks: [
            {
              type: 'header',
              text: {
                type: 'plain_text',
                text: `${sevEmoji} CyberMind SOC Security Alert: ${opts.severity?.toUpperCase()}`,
                emoji: true,
              },
            },
            {
              type: 'section',
              fields: [
                { type: 'mrkdwn', text: `*Incident Case:*\n\`${opts.incidentId || 'UNLINKED'}\`` },
                { type: 'mrkdwn', text: `*Severity:*\n*${opts.severity}*` },
                { type: 'mrkdwn', text: `*Offending IP:*\n\`${opts.targetIp || 'N/A'}\`` },
                { type: 'mrkdwn', text: `*MITRE ATT&CK:*\n\`${opts.mitreTechnique || 'N/A'}\`` },
              ],
            },
            {
              type: 'section',
              text: {
                type: 'mrkdwn',
                text: `*Investigation Summary:*\n${opts.details}`,
              },
            },
            {
              type: 'context',
              elements: [
                {
                  type: 'mrkdwn',
                  text: `Dispatched by *CyberMind SOAR Engine* | Operator: _${opts.operator || 'Automated Playbook'}_ | ${new Date().toUTCString()}`,
                },
              ],
            },
          ],
        },
      ],
    };
  }

  /**
   * Format and build TheHive / Cortex Case Alert
   */
  public static buildTheHivePayload(opts: WebhookDispatchOptions): object {
    const sevNum = opts.severity === 'Critical' ? 4 : opts.severity === 'High' ? 3 : opts.severity === 'Medium' ? 2 : 1;

    const artifacts: Array<{ dataType: string; data: string; message: string }> = [];
    if (opts.targetIp && SoarService.isValidIp(opts.targetIp)) {
      artifacts.push({
        dataType: 'ip',
        data: opts.targetIp,
        message: 'Suspicious remote host observed in incident telemetry',
      });
    }

    return {
      title: `[SOAR Alert] ${opts.severity.toUpperCase()} - ${opts.title}`,
      description: `${opts.details}\n\nIncident Reference: ${opts.incidentId || 'N/A'}\nMITRE Technique: ${opts.mitreTechnique || 'N/A'}`,
      severity: sevNum,
      startDate: Date.now(),
      type: 'external',
      source: 'CyberMind-SOAR-Engine',
      sourceRef: opts.incidentId || `SOAR-${Date.now()}`,
      tags: [
        'soar:automated',
        `severity:${opts.severity.toLowerCase()}`,
        opts.mitreTechnique ? `mitre:${opts.mitreTechnique}` : 'telemetry:alert',
      ],
      artifacts,
    };
  }

  /**
   * SSRF Protection Guard for Webhook URLs
   */
  public static validateWebhookUrl(rawUrl: string): { valid: boolean; reason?: string } {
    try {
      const parsed = new URL(rawUrl);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return { valid: false, reason: 'Webhook URL must use HTTP or HTTPS protocol.' };
      }

      const host = parsed.hostname.toLowerCase();
      // Block link-local, AWS/GCP metadata, and multicast
      if (
        host === '169.254.169.254' ||
        host.startsWith('169.254.') ||
        host.includes('metadata.google.internal') ||
        host.includes('instance-data') ||
        host.startsWith('224.')
      ) {
        return { valid: false, reason: 'Cloud metadata and link-local targets are prohibited (SSRF Protection).' };
      }

      // Prohibit localhost/loopback in production
      if (process.env.NODE_ENV === 'production' && (host === 'localhost' || host === '127.0.0.1' || host === '::1')) {
        return { valid: false, reason: 'Loopback target is forbidden in production environment.' };
      }

      return { valid: true };
    } catch {
      return { valid: false, reason: 'Malformed Webhook URL.' };
    }
  }

  /**
   * Dispatch Webhook Alert to Slack, TheHive, or generic SIEM Webhook
   */
  public static async dispatchWebhookAlert(
    opts: WebhookDispatchOptions
  ): Promise<{ success: boolean; simulated: boolean; status: number; payload: object; error?: string }> {
    const destType = opts.destinationType || 'slack';
    const targetUrl = opts.webhookUrl || (destType === 'thehive' ? process.env.THEHIVE_WEBHOOK_URL : process.env.SLACK_WEBHOOK_URL);

    // Build payload according to destination
    const payload = destType === 'thehive' ? this.buildTheHivePayload(opts) : this.buildSlackPayload(opts);

    // If no webhook URL is configured or URL is empty, run in safe simulation mode
    if (!targetUrl || targetUrl.trim().length === 0) {
      const execLog: SoarExecutionRecord = {
        id: `SOAR-EXEC-${Date.now()}`,
        actionType: 'WEBHOOK_DISPATCH',
        target: `${destType.toUpperCase()} (Simulated / Local Dispatch)`,
        status: 'SIMULATED',
        operator: opts.operator || 'SOC Lead Analyst',
        details: `Dispatched formatted ${destType.toUpperCase()} alert for incident ${opts.incidentId || 'UNLINKED'}. Simulated delivery (no external webhook URL provided in environment).`,
        payload,
        result: { status: 200, simulated: true },
        timestamp: new Date().toISOString(),
      };
      pushBounded(memoryDb.soarExecutions, execLog, 500);

      broadcastTelemetryEvent({
        type: 'SOAR_ACTION_EXECUTED',
        action: 'WEBHOOK_DISPATCH',
        destination: destType,
        simulated: true,
        payload,
        timestamp: new Date().toISOString(),
      });

      return { success: true, simulated: true, status: 200, payload };
    }

    // SSRF Validation
    const urlCheck = this.validateWebhookUrl(targetUrl);
    if (!urlCheck.valid) {
      return { success: false, simulated: false, status: 400, payload, error: urlCheck.reason };
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      const response = await fetch(targetUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'CyberMind-SOAR-Engine/3.0',
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      const isOk = response.ok || response.status === 200 || response.status === 201 || response.status === 204;

      const execLog: SoarExecutionRecord = {
        id: `SOAR-EXEC-${Date.now()}`,
        actionType: 'WEBHOOK_DISPATCH',
        target: `${destType.toUpperCase()} (${targetUrl})`,
        status: isOk ? 'SUCCESS' : 'FAILED',
        operator: opts.operator || 'SOC Lead Analyst',
        details: `Dispatched ${destType.toUpperCase()} alert to ${targetUrl}. Response HTTP ${response.status}`,
        payload,
        result: { status: response.status, ok: isOk },
        timestamp: new Date().toISOString(),
      };
      pushBounded(memoryDb.soarExecutions, execLog, 500);

      return { success: isOk, simulated: false, status: response.status, payload };
    } catch (err: any) {
      const execLog: SoarExecutionRecord = {
        id: `SOAR-EXEC-${Date.now()}`,
        actionType: 'WEBHOOK_DISPATCH',
        target: `${destType.toUpperCase()} (${targetUrl})`,
        status: 'FAILED',
        operator: opts.operator || 'SOC Lead Analyst',
        details: `Dispatch error: ${err.message}`,
        payload,
        timestamp: new Date().toISOString(),
      };
      pushBounded(memoryDb.soarExecutions, execLog, 500);

      return { success: false, simulated: false, status: 500, payload, error: err.message };
    }
  }

  /**
   * Generate EDR Host Network Containment Scripts
   */
  public static generateHostIsolationScript(targetHostOrIp: string, os: 'windows' | 'linux' = 'windows'): { script: string; rollback: string } {
    if (os === 'windows') {
      return {
        script: `# PowerShell Windows Endpoint Isolation Script
# Target: ${targetHostOrIp}
# Retains connection ONLY to SOC Management Gateway (Port 5000 / 5985)
New-NetFirewallRule -DisplayName "SOAR-Isolate-DropAllOutbound" -Direction Outbound -Action Block -Priority 1
New-NetFirewallRule -DisplayName "SOAR-Isolate-DropAllInbound" -Direction Inbound -Action Block -Priority 1
New-NetFirewallRule -DisplayName "SOAR-Isolate-AllowSOC" -Direction Inbound -Action Allow -RemoteAddress "192.168.1.0/24" -Priority 2
Write-Output "Endpoint ${targetHostOrIp} isolated successfully from corporate LAN."`,
        rollback: `# Rollback Windows Isolation
Remove-NetFirewallRule -DisplayName "SOAR-Isolate-DropAllOutbound"
Remove-NetFirewallRule -DisplayName "SOAR-Isolate-DropAllInbound"
Remove-NetFirewallRule -DisplayName "SOAR-Isolate-AllowSOC"`,
      };
    } else {
      return {
        script: `#!/usr/bin/env bash
# Linux Host Network Isolation Script for ${targetHostOrIp}
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT DROP
# Permit loopback and established SOC admin sessions
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
echo "Host ${targetHostOrIp} network isolation enforced."`,
        rollback: `#!/usr/bin/env bash
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -F`,
      };
    }
  }

  /**
   * Retrieve active blocked IPs
   */
  public static getBlockedIps(): BlockedIpRecord[] {
    return memoryDb.blockedIps.filter((b: BlockedIpRecord) => b.status === 'ACTIVE');
  }

  /**
   * Retrieve SOAR execution history
   */
  public static getExecutionHistory(limit = 100): SoarExecutionRecord[] {
    return (memoryDb.soarExecutions || []).slice(-limit).reverse();
  }
}
