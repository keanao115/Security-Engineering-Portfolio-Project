import React, { useState } from 'react';
import { ShieldAlert, Copy, Check, Terminal, FileCode, Play, AlertCircle, ShieldCheck } from 'lucide-react';
import { generateRemediationScripts } from '../utils/threatEngine';
import { useLanguage } from '../contexts/LanguageContext';

export default function ThreatAnalysisView({ anomalies }) {
  const { t, language } = useLanguage();
  const [copied, setCopied] = useState(false);
  const [activeScriptTab, setActiveScriptTab] = useState('powershell');

  const scripts = generateRemediationScripts(anomalies);

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-red-400" />
            {t('threat.title', 'AI Automated Threat Analysis & Mitigation')}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {t('threat.subtitle', 'Automated correlation, CVE lookup, MITRE ATT&CK mapping, and remediation script synthesis.')}
          </p>
        </div>
      </div>

      {/* Operational Analysis Banner */}
      <div className="glass-panel p-5 rounded-2xl border-l-4 border-l-cyan-500 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-bold text-cyan-300 mb-1 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            {language === 'zh-TW' ? '標準實時檢測與威脅關聯引擎 (Real Telemetry & Anomaly Analysis)' : 'Standard Real-Time Detection & Threat Correlation Engine'}
          </h3>
          <p className="text-xs text-slate-300 leading-relaxed font-mono">
            {language === 'zh-TW' 
              ? '根據實際收集之系統日誌、網絡封包與掃描報告進行客觀之 MITRE ATT&CK 關聯與處置腳本生成。無任何虛構劇情。'
              : 'Performs objective MITRE ATT&CK correlation and script generation based on actual logs, network packets, and scanner outputs.'}
          </p>
        </div>
        <div className="hidden sm:block text-right font-mono text-xs shrink-0">
          <span className="text-slate-400 block">{language === 'zh-TW' ? '若欲測試 AI 攻擊劇情敘事：' : 'To test simulated AI attack narratives:'}</span>
          <span className="text-amber-400 font-bold">{language === 'zh-TW' ? '請使用選單中的「攻擊模擬」功能' : 'Use the Attack Simulation module in the sidebar'}</span>
        </div>
      </div>

      {/* Flagged Anomalies Grid */}
      {anomalies.length === 0 ? (
        <div className="glass-panel p-8 text-center rounded-2xl border border-slate-800 space-y-4">
          <ShieldCheck className="w-12 h-12 text-emerald-400 mx-auto" />
          <div className="space-y-1">
            <h3 className="text-base font-bold text-white">
              {language === 'zh-TW' ? '實時威脅防禦狀態：良好 (Baseline Secure)' : 'Real-Time Threat Status: Baseline Secure'}
            </h3>
            <p className="text-xs text-slate-400 font-mono max-w-xl mx-auto">
              {language === 'zh-TW'
                ? '目前尚未上傳或檢測到真實日誌威脅。所有 AI 模擬劇情威脅已統一放置於【攻擊模擬】模組中進行展示與演練。'
                : 'No active threats detected in live baseline. Simulated attack scenarios are available in the Attack Simulation module.'}
            </p>
          </div>
          <div className="pt-2">
            <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 px-3 py-1.5 rounded-xl border border-cyan-500/20">
              {language === 'zh-TW' ? '💡 提示：可至「Log Analyzer」上傳真實 Log，或前往「攻擊模擬」啟動 AI 劇情威脅演練' : '💡 Tip: Upload logs in Log Analyzer or launch scenarios in Attack Simulation'}
            </span>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {anomalies.map((anom) => (
            <div key={anom.id} className="glass-panel p-5 rounded-2xl flex flex-col justify-between space-y-4 border border-slate-800 hover:border-cyan-500/30 transition-all">
              <div>
                <div className="flex items-start justify-between">
                  <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase ${
                    anom.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                    anom.severity === 'High' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                    'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                  }`}>
                    {anom.severity} {language === 'zh-TW' ? '風險等級' : 'Severity'}
                  </span>
                  <span className="text-xs font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                    {anom.mitreId}
                  </span>
                </div>
                <h4 className="text-sm font-bold text-white mt-2">{anom.title}</h4>
                <p className="text-xs text-slate-400 mt-1">{anom.description}</p>
              </div>

              <div className="space-y-2 text-xs font-mono bg-slate-950/60 p-3 rounded-xl border border-slate-900">
                <div className="flex justify-between">
                  <span className="text-slate-500">{t('threat.targetSystem', 'Target System:')}</span>
                  <span className="text-slate-300 font-semibold">{anom.target}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">{t('threat.attackerOrigin', 'Attacker Origin:')}</span>
                  <span className="text-red-400 font-semibold">{anom.attackerIp}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">{t('threat.mitreTechnique', 'MITRE Technique:')}</span>
                  <span className="text-cyan-300">{anom.mitreName}</span>
                </div>
              </div>

              <div className="text-xs text-slate-300 bg-slate-900/40 p-3 rounded-xl border border-slate-800">
                <span className="font-bold text-emerald-400 flex items-center gap-1 mb-1">
                  <ShieldCheck className="w-3.5 h-3.5" /> {t('threat.aiFix', 'AI Recommended Fix:')}
                </span>
                {anom.remediation}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Auto-Generated Containment Scripts */}
      <div className="glass-panel p-5 rounded-2xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              {t('threat.scriptGeneratorTitle', 'Automated Incident Containment Script Generator')}
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              {t('threat.scriptGeneratorDesc', 'One-click copyable mitigation scripts tailor-made for this incident')}
            </p>
          </div>

          {/* Script Tabs */}
          <div className="flex flex-wrap items-center gap-1 bg-slate-900 p-1 rounded-xl border border-slate-800 text-xs font-mono">
            {['powershell', 'bash', 'sigma', 'yara', 'snort', 'suricata'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveScriptTab(tab)}
                className={`px-3 py-1.5 rounded-lg transition-all ${
                  activeScriptTab === tab
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {t(`threat.tabs.${tab}`, tab.toUpperCase())}
              </button>
            ))}
          </div>
        </div>

        {/* Code Editor Preview */}
        <div className="relative rounded-xl bg-slate-950 border border-cyan-500/20 p-4 font-mono text-xs overflow-x-auto">
          <button
            onClick={() => handleCopy(scripts[activeScriptTab])}
            className="absolute top-3 right-3 flex items-center gap-1.5 px-3 py-1 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 transition-all text-xs font-semibold"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? t('threat.copied', 'Copied!') : t('threat.copyCode', 'Copy Code')}
          </button>
          <pre className="text-slate-300 leading-relaxed">
            {scripts[activeScriptTab]}
          </pre>
        </div>
      </div>
    </div>
  );
}
