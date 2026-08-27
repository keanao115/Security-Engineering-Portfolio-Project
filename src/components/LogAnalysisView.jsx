import React, { useState } from 'react';
import { FileText, Upload, RefreshCw, CheckCircle, Search, ShieldAlert, Sparkles, Filter } from 'lucide-react';
import { SAMPLE_WINDOWS_LOGS, SAMPLE_LINUX_LOGS, SAMPLE_FIREWALL_LOGS } from '../data/sampleData';
import { parseWindowsEventLog, parseLinuxLog, parseFirewallLog } from '../utils/logParsers';
import { ingestLogs } from '../services/apiClient';
import { useLanguage } from '../contexts/LanguageContext';

export default function LogAnalysisView({ onLogAnalyzed }) {
  const { t, language } = useLanguage();
  const [logText, setLogText] = useState(SAMPLE_WINDOWS_LOGS);
  const [logType, setLogType] = useState('windows');
  const [filterQuery, setFilterQuery] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const handleLoadSample = (type) => {
    setLogType(type);
    if (type === 'windows') setLogText(SAMPLE_WINDOWS_LOGS);
    if (type === 'linux') setLogText(SAMPLE_LINUX_LOGS);
    if (type === 'firewall') setLogText(SAMPLE_FIREWALL_LOGS);
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      setLogText(event.target.result);
    };
    reader.readAsText(file);
  };

  const handleRunAnalysis = async () => {
    setIsAnalyzing(true);
    
    // Call Express REST API for backend normalization & storage
    try {
      const apiResult = await ingestLogs(logText, logType);
      if (apiResult && apiResult.parsed) {
        onLogAnalyzed({
          windowsLogs: apiResult.parsed.windowsLogs || [],
          linuxLogs: apiResult.parsed.linuxLogs || [],
          firewallLogs: apiResult.parsed.suricataAlerts || []
        });
        setIsAnalyzing(false);
        return;
      }
    } catch (e) {
      console.warn("Backend API unavailable, executing client parser fallback:", e);
    }

    // Client-side parser fallback
    setTimeout(() => {
      let win = [];
      let lnx = [];
      let fw = [];

      if (logType === 'windows') win = parseWindowsEventLog(logText);
      if (logType === 'linux') lnx = parseLinuxLog(logText);
      if (logType === 'firewall') fw = parseFirewallLog(logText);

      onLogAnalyzed({ windowsLogs: win, linuxLogs: lnx, firewallLogs: fw });
      setIsAnalyzing(false);
    }, 400);
  };

  const filteredLines = logText.split('\n').filter(l => l.toLowerCase().includes(filterQuery.toLowerCase()));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <FileText className="w-6 h-6 text-cyan-400" />
            {t('logAnalysis.title', 'Enterprise Multi-Source Log Analyzer')}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {t('logAnalysis.subtitle', 'Drag & drop raw log files or select standard sample logs to perform log anomaly parsing.')}
          </p>
        </div>
      </div>

      {/* Preset Data Selector & Upload Bar */}
      <div className="glass-panel p-5 rounded-2xl flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-mono text-slate-400">
            {t('logAnalysis.samplePresets', 'Standard Sample Logs:')}
          </span>
          <button
            onClick={() => handleLoadSample('windows')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${logType === 'windows' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm' : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white'}`}
          >
            {t('logAnalysis.windowsBtn', 'Windows Event Log')}
          </button>
          <button
            onClick={() => handleLoadSample('linux')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${logType === 'linux' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm' : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white'}`}
          >
            {t('logAnalysis.linuxBtn', 'Linux Syslog / Auth')}
          </button>
          <button
            onClick={() => handleLoadSample('firewall')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${logType === 'firewall' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm' : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white'}`}
          >
            {t('logAnalysis.firewallBtn', 'Palo Alto Firewall Logs')}
          </button>
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          <label className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 cursor-pointer font-mono transition-all">
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            {t('logAnalysis.uploadBtn', 'Upload Log File')}
            <input type="file" onChange={handleFileUpload} className="hidden" />
          </label>

          <button
            onClick={handleRunAnalysis}
            disabled={isAnalyzing}
            className="flex items-center gap-2 px-4 py-1.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-lg shadow-cyan-500/25 transition-all disabled:opacity-50"
          >
            {isAnalyzing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
            {isAnalyzing ? t('logAnalysis.analyzingBtn', 'Analyzing...') : t('logAnalysis.runBtn', 'Run AI Threat Analysis')}
          </button>
        </div>
      </div>

      {/* Log Search & Syntax Highlight Inspector */}
      <div className="glass-panel p-5 rounded-2xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-300">
            <Filter className="w-4 h-4 text-cyan-400" /> {t('logAnalysis.filterLabel', 'Filter Logs:')}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
              <input
                type="text"
                placeholder={t('logAnalysis.searchPlaceholder', 'Search IP, Event ID, Keyword...')}
                value={filterQuery}
                onChange={(e) => setFilterQuery(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg pl-8 pr-3 py-1.5 focus:outline-none focus:border-cyan-500 w-64"
              />
            </div>
          </div>

          <span className="text-xs font-mono text-slate-400">
            {t('logAnalysis.showingEntries', 'Showing')} <strong className="text-cyan-400">{filteredLines.length}</strong> {language === 'zh-TW' ? '行日誌紀錄' : 'raw log entries'}
          </span>
        </div>

        {/* Console / Log Viewer */}
        <div className="bg-slate-950 border border-slate-900 rounded-xl p-4 font-mono text-xs max-h-96 overflow-y-auto space-y-1">
          {filteredLines.map((line, idx) => {
            const isSuspicious = line.includes("4625") || line.includes("4688") || line.includes("-enc") || line.includes("DROP") || line.includes("Failed password");
            return (
              <div
                key={idx}
                className={`py-1 px-2 rounded flex items-start gap-2 ${
                  isSuspicious ? 'bg-red-500/10 text-red-300 border-l-2 border-red-500' : 'text-slate-300 hover:bg-slate-900/50'
                }`}
              >
                <span className="text-slate-600 select-none w-8 text-right font-mono text-[10px]">{idx + 1}</span>
                <span className="break-all">{line}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
