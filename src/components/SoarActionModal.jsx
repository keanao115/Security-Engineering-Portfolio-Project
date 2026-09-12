import React, { useState, useEffect } from 'react';
import { ShieldAlert, Shield, Check, Copy, AlertTriangle, Send, RefreshCw, X, Radio, Terminal, Server } from 'lucide-react';
import { executeSoarBlockIp, executeSoarUnblockIp, fetchBlockedIps, dispatchSoarWebhook, generateSoarFirewallRules, generateHostIsolationScript } from '../services/apiClient';
import { useLanguage } from '../contexts/LanguageContext';

export default function SoarActionModal({ isOpen, onClose, initialData = {} }) {
  const { language } = useLanguage();
  const isZh = language === 'zh-TW';

  const [activeTab, setActiveTab] = useState('block'); // 'block' | 'webhook' | 'isolate'
  const [ip, setIp] = useState(initialData.ip || initialData.sourceIp || '198.51.100.42');
  const [reason, setReason] = useState(initialData.summary || 'Triggered high severity detection alert');
  const [severity, setSeverity] = useState(initialData.severity || 'High');
  const [incidentId, setIncidentId] = useState(initialData.incidentId || initialData.id || 'INC-2026-SOAR');

  // Firewall state
  const [firewallRules, setFirewallRules] = useState(null);
  const [loadingRules, setLoadingRules] = useState(false);
  const [blocking, setBlocking] = useState(false);
  const [blockStatus, setBlockStatus] = useState(null);
  const [blockedIpsList, setBlockedIpsList] = useState([]);
  const [copiedKey, setCopiedKey] = useState(null);

  // Webhook state
  const [webhookType, setWebhookType] = useState('slack'); // 'slack' | 'thehive'
  const [webhookUrl, setWebhookUrl] = useState('');
  const [dispatching, setDispatching] = useState(false);
  const [webhookResult, setWebhookResult] = useState(null);

  // Isolation state
  const [isolationScripts, setIsolationScripts] = useState(null);

  useEffect(() => {
    if (initialData.ip || initialData.sourceIp) {
      setIp(initialData.ip || initialData.sourceIp);
    }
    if (initialData.summary) {
      setReason(initialData.summary);
    }
    if (initialData.severity) {
      setSeverity(initialData.severity);
    }
    if (initialData.incidentId || initialData.id) {
      setIncidentId(initialData.incidentId || initialData.id);
    }
  }, [initialData]);

  useEffect(() => {
    if (isOpen) {
      loadBlockedIps();
      loadRulesForIp(ip);
      loadIsolationScripts(ip);
    }
  }, [isOpen, ip]);

  const loadBlockedIps = async () => {
    try {
      const res = await fetchBlockedIps();
      setBlockedIpsList(res.blockedIps || []);
    } catch (err) {
      console.warn('Failed to load blocked IPs:', err);
    }
  };

  const loadRulesForIp = async (targetIp) => {
    if (!targetIp || !targetIp.trim()) return;
    setLoadingRules(true);
    try {
      const res = await generateSoarFirewallRules(targetIp.trim(), reason);
      setFirewallRules(res.rules);
    } catch {
      setFirewallRules(null);
    } finally {
      setLoadingRules(false);
    }
  };

  const loadIsolationScripts = async (targetHost) => {
    if (!targetHost) return;
    try {
      const res = await generateHostIsolationScript(targetHost, 'windows');
      setIsolationScripts(res);
    } catch {
      setIsolationScripts(null);
    }
  };

  const handleCopy = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleBlockIp = async () => {
    setBlocking(true);
    setBlockStatus(null);
    try {
      const res = await executeSoarBlockIp({
        ip: ip.trim(),
        reason,
        severity,
        incidentId,
      });
      setBlockStatus({ success: true, message: res.message });
      loadBlockedIps();
    } catch (err) {
      setBlockStatus({ success: false, message: err.message });
    } finally {
      setBlocking(false);
    }
  };

  const handleUnblock = async (targetIp) => {
    try {
      await executeSoarUnblockIp(targetIp);
      loadBlockedIps();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleDispatchWebhook = async () => {
    setDispatching(true);
    setWebhookResult(null);
    try {
      const res = await dispatchSoarWebhook({
        destinationType: webhookType,
        webhookUrl: webhookUrl.trim() || undefined,
        incidentId,
        title: `[SOAR Alert] ${severity} - Security Incident on ${ip}`,
        severity,
        details: reason,
        targetIp: ip,
        mitreTechnique: initialData.mitreTechnique || 'T1059',
      });
      setWebhookResult({ success: true, ...res });
    } catch (err) {
      setWebhookResult({ success: false, error: err.message });
    } finally {
      setDispatching(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="glass-panel p-6 rounded-2xl max-w-3xl w-full border border-red-500/30 space-y-5 shadow-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-xl bg-red-500/20 text-red-400 border border-red-500/30">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-white flex items-center gap-2">
                {isZh ? 'SOAR 安全協同與自動應變處置器 (SOAR Action Orchestrator)' : 'SOAR Security Orchestration & Automated Response'}
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                {isZh ? '針對高危事件執行即時防火牆阻擋 (iptables / AWS WAF) 與告警通知' : 'Automated containment and webhook notification for high-risk threat events.'}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Target Context */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3 rounded-xl bg-slate-950/60 border border-slate-900 font-mono text-xs">
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">{isZh ? '目標 IP' : 'Target IP'}</span>
            <input
              type="text"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-cyan-400 font-bold w-full mt-0.5 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">{isZh ? '嚴重性' : 'Severity'}</span>
            <span className="inline-block mt-1 font-bold text-red-400 px-2 py-0.5 rounded bg-red-500/10 border border-red-500/20">
              {severity}
            </span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">{isZh ? '關聯工單編號' : 'Incident ID'}</span>
            <span className="inline-block mt-1 text-slate-300">{incidentId}</span>
          </div>
        </div>

        {/* Tab switcher */}
        <div className="flex border-b border-slate-800 font-mono text-xs">
          <button
            onClick={() => setActiveTab('block')}
            className={`pb-2 px-4 font-bold border-b-2 transition-all ${
              activeTab === 'block'
                ? 'border-red-500 text-red-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            🛡️ {isZh ? '阻擋 IP (iptables / AWS WAF)' : 'Firewall Containment (iptables / AWS WAF)'}
          </button>
          <button
            onClick={() => setActiveTab('webhook')}
            className={`pb-2 px-4 font-bold border-b-2 transition-all ${
              activeTab === 'webhook'
                ? 'border-cyan-500 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            📢 {isZh ? '發送 Webhook 告警 (Slack / TheHive)' : 'Webhook Alert (Slack / TheHive)'}
          </button>
          <button
            onClick={() => setActiveTab('isolate')}
            className={`pb-2 px-4 font-bold border-b-2 transition-all ${
              activeTab === 'isolate'
                ? 'border-amber-500 text-amber-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            🔒 {isZh ? 'EDR 主機隔離腳本' : 'EDR Host Isolation Script'}
          </button>
        </div>

        {/* TAB 1: BLOCK IP */}
        {activeTab === 'block' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-300">
                {isZh ? '即時生成之多平台邊界阻擋指令：' : 'Generated Multi-Platform Firewall Enforcement Rules:'}
              </span>
              <button
                onClick={handleBlockIp}
                disabled={blocking || !ip}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white font-mono text-xs font-bold transition-all shadow-lg shadow-red-500/20"
              >
                <AlertTriangle className="w-4 h-4" />
                {blocking ? (isZh ? '正在執行阻擋…' : 'Blocking...') : (isZh ? '立即執行邊界阻擋' : 'Enforce Perimeter Block')}
              </button>
            </div>

            {blockStatus && (
              <div className={`p-3 rounded-xl border text-xs font-mono flex items-center gap-2 ${blockStatus.success ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30' : 'bg-red-500/10 text-red-300 border-red-500/30'}`}>
                {blockStatus.success ? <Check className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-red-400" />}
                {blockStatus.message}
              </div>
            )}

            {/* Linux iptables */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1.5 text-cyan-400 font-bold">
                  <Terminal className="w-3.5 h-3.5" /> Linux iptables Drop Rules:
                </span>
                <button
                  onClick={() => handleCopy(firewallRules?.iptables?.blockCommands?.join('\n') || '', 'iptables')}
                  className="flex items-center gap-1 text-[11px] hover:text-cyan-300 text-slate-400"
                >
                  {copiedKey === 'iptables' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copiedKey === 'iptables' ? (isZh ? '已複製' : 'Copied') : (isZh ? '複製指令' : 'Copy')}
                </button>
              </div>
              <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-emerald-400 overflow-x-auto">
                {firewallRules?.iptables?.blockCommands?.join('\n') || (isZh ? '# 正在計算規則…' : '# Calculating rules...')}
              </pre>
            </div>

            {/* AWS WAF v2 CLI */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1.5 text-amber-400 font-bold">
                  <Server className="w-3.5 h-3.5" /> AWS WAF v2 CLI IPSet Update:
                </span>
                <button
                  onClick={() => handleCopy(firewallRules?.awsWaf?.cliCommand || '', 'awswaf')}
                  className="flex items-center gap-1 text-[11px] hover:text-amber-300 text-slate-400"
                >
                  {copiedKey === 'awswaf' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copiedKey === 'awswaf' ? (isZh ? '已複製' : 'Copied') : (isZh ? '複製指令' : 'Copy')}
                </button>
              </div>
              <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-amber-300 overflow-x-auto">
                {firewallRules?.awsWaf?.cliCommand || (isZh ? '# 正在計算 AWS WAF 規則…' : '# Calculating AWS WAF rule...')}
              </pre>
            </div>

            {/* Windows Defender Netsh */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1.5 text-blue-400 font-bold">
                  <Terminal className="w-3.5 h-3.5" /> Windows Firewall (netsh advfirewall):
                </span>
                <button
                  onClick={() => handleCopy(firewallRules?.windowsNetsh?.blockCommand || '', 'netsh')}
                  className="flex items-center gap-1 text-[11px] hover:text-blue-300 text-slate-400"
                >
                  {copiedKey === 'netsh' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copiedKey === 'netsh' ? (isZh ? '已複製' : 'Copied') : (isZh ? '複製指令' : 'Copy')}
                </button>
              </div>
              <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-blue-300 overflow-x-auto">
                {firewallRules?.windowsNetsh?.blockCommand || ''}
              </pre>
            </div>

            {/* Active Blocked IPs */}
            <div className="pt-3 border-t border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span>{isZh ? `目前處於阻擋狀態之 IP 清單 (${blockedIpsList.length} 個):` : `Actively Blocked Threat IPs (${blockedIpsList.length}):`}</span>
                <button onClick={loadBlockedIps} className="text-[11px] hover:text-white flex items-center gap-1">
                  <RefreshCw className="w-3 h-3" /> {isZh ? '重新載入' : 'Refresh'}
                </button>
              </div>
              {blockedIpsList.length === 0 ? (
                <div className="text-xs font-mono text-slate-600 p-2">{isZh ? '目前尚無被阻擋之 IP。' : 'No active IP blocks currently recorded.'}</div>
              ) : (
                <div className="space-y-1.5 max-h-36 overflow-y-auto">
                  {blockedIpsList.map((b) => (
                    <div key={b.id} className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono">
                      <div>
                        <span className="font-bold text-red-400">{b.ip}</span>
                        <span className="text-slate-500 ml-2 text-[10px]">({b.reason})</span>
                      </div>
                      <button
                        onClick={() => handleUnblock(b.ip)}
                        className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-[10px] font-bold"
                      >
                        {isZh ? '解除阻擋' : 'Unblock'}
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 2: WEBHOOK ALERT */}
        {activeTab === 'webhook' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="space-y-2">
              <label className="text-slate-400 block">{isZh ? '選擇告警目標平台：' : 'Select Destination Platform:'}</label>
              <div className="flex gap-4">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="radio"
                    name="whType"
                    checked={webhookType === 'slack'}
                    onChange={() => setWebhookType('slack')}
                    className="text-cyan-500"
                  />
                  <span className="text-white font-bold">Slack / Mattermost</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="radio"
                    name="whType"
                    checked={webhookType === 'thehive'}
                    onChange={() => setWebhookType('thehive')}
                    className="text-cyan-500"
                  />
                  <span className="text-white font-bold">TheHive / Cortex</span>
                </label>
              </div>
            </div>

            <div>
              <label className="text-slate-400 block mb-1">{isZh ? '自訂 Webhook URL (留空則使用系統設定或模擬派送)：' : 'Custom Webhook URL (leave empty for env default / simulated dispatch):'}</label>
              <input
                type="text"
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
                placeholder="https://hooks.slack.com/services/..."
                className="w-full bg-slate-950 border border-slate-800 text-xs rounded-xl p-2.5 text-cyan-300 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Payload Preview */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-slate-400">
                <span>{isZh ? '派送之 JSON 格式化警報結構 (Preview)：' : 'Dispatched JSON Alert Payload Preview:'}</span>
                <span className="text-[10px] text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                  {webhookType.toUpperCase()} FORMAT
                </span>
              </div>
              <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] text-cyan-400 max-h-48 overflow-y-auto">
                {JSON.stringify(
                  webhookType === 'slack'
                    ? {
                        text: `🚨 [SOAR ALERT - ${severity}] ${reason}`,
                        incidentId,
                        severity,
                        targetIp: ip,
                        dispatchedBy: 'CyberMind SOAR Engine',
                        action: 'Automated Playbook Triggered',
                      }
                    : {
                        title: `[SOAR] ${severity} - Security Alert on ${ip}`,
                        description: reason,
                        severity: severity === 'Critical' ? 4 : 3,
                        type: 'external',
                        source: 'CyberMind-SOAR-Engine',
                        artifacts: [{ dataType: 'ip', data: ip }],
                      },
                  null,
                  2
                )}
              </pre>
            </div>

            {webhookResult && (
              <div className={`p-3 rounded-xl border text-xs flex items-center gap-2 ${webhookResult.success ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30' : 'bg-red-500/10 text-red-300 border-red-500/30'}`}>
                {webhookResult.success ? <Check className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-red-400" />}
                <span>
                  {webhookResult.message || webhookResult.error}
                  {webhookResult.simulated && (
                    <span className="ml-2 text-[10px] text-cyan-400 bg-cyan-500/20 px-1.5 py-0.5 rounded">
                      {isZh ? '模擬分發審計已留存' : 'Simulated audit logged'}
                    </span>
                  )}
                </span>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={handleDispatchWebhook}
                disabled={dispatching}
                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-bold transition-all shadow-lg shadow-cyan-500/20"
              >
                <Send className="w-4 h-4" />
                {dispatching ? (isZh ? '派送中…' : 'Dispatching...') : (isZh ? `發送 ${webhookType.toUpperCase()} Webhook` : `Dispatch ${webhookType.toUpperCase()} Webhook`)}
              </button>
            </div>
          </div>
        )}

        {/* TAB 3: EDR HOST ISOLATION */}
        {activeTab === 'isolate' && (
          <div className="space-y-4 font-mono text-xs">
            <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <span>
                {isZh
                  ? '主機網路隔離程序將切斷受感染端點除 SOC 應變伺服器 (連接埠 5000/5985) 外之所有網路流量，防止勒索軟體橫向擴散。'
                  : 'Host network containment halts all inbound and outbound traffic on the endpoint except the SOC management gateway, preventing lateral movement.'}
              </span>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-slate-400">
                <span className="font-bold text-cyan-400">Windows PowerShell Isolation Script:</span>
                <button
                  onClick={() => handleCopy(isolationScripts?.script || '', 'psisolate')}
                  className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-cyan-300"
                >
                  {copiedKey === 'psisolate' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copiedKey === 'psisolate' ? (isZh ? '已複製' : 'Copied') : (isZh ? '複製指令' : 'Copy')}
                </button>
              </div>
              <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] text-cyan-400 overflow-x-auto">
                {isolationScripts?.script || (isZh ? '# 正在生成腳本…' : '# Generating script...')}
              </pre>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-slate-400">
                <span className="font-bold text-slate-400">Rollback Script:</span>
                <button
                  onClick={() => handleCopy(isolationScripts?.rollback || '', 'psrollback')}
                  className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-300"
                >
                  {copiedKey === 'psrollback' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {copiedKey === 'psrollback' ? (isZh ? '已複製' : 'Copied') : (isZh ? '複製指令' : 'Copy')}
                </button>
              </div>
              <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] text-slate-400 overflow-x-auto">
                {isolationScripts?.rollback || ''}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
