import React, { useState, useEffect } from 'react';
import { FileCode, Shield, Check, Copy, AlertTriangle, Play, RefreshCw, X, Plus, Filter, Tag } from 'lucide-react';
import { fetchSigmaRules, testSigmaRule, createSigmaRule, reloadSigmaRules } from '../services/apiClient';
import { useLanguage } from '../contexts/LanguageContext';

const SAMPLE_CUSTOM_RULE = `title: Detect Suspicious Mimikatz Command Line Usage
id: custom-mimikatz-001
status: test
description: Detects command line executions invoking Mimikatz Sekurlsa or privilege debug
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    commandLine|contains:
      - 'sekurlsa'
      - 'privilege::debug'
      - 'logonpasswords'
  condition: selection
level: critical
response: Immediately isolate the endpoint and rotate compromised domain administrator credentials.`;

export default function SigmaRulesModal({ isOpen, onClose }) {
  const { language } = useLanguage();
  const isZh = language === 'zh-TW';

  const [activeTab, setActiveTab] = useState('rules'); // 'rules' | 'test'
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedSev, setSelectedSev] = useState('ALL');
  const [expandedRuleId, setExpandedRuleId] = useState(null);
  const [copiedId, setCopiedId] = useState(null);

  // Playground state
  const [testYaml, setTestYaml] = useState(SAMPLE_CUSTOM_RULE);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [deploying, setDeploying] = useState(false);
  const [deployStatus, setDeployStatus] = useState(null);

  useEffect(() => {
    if (isOpen) {
      loadRules();
    }
  }, [isOpen]);

  const loadRules = async () => {
    setLoading(true);
    try {
      const res = await fetchSigmaRules();
      setRules(res.rules || []);
      if (res.rules?.length > 0 && !expandedRuleId) {
        setExpandedRuleId(res.rules[0].id);
      }
    } catch (err) {
      console.warn('Failed to load Sigma rules:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleRunTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await testSigmaRule(testYaml);
      setTestResult({ success: true, ...res });
    } catch (err) {
      setTestResult({ success: false, error: err.message });
    } finally {
      setTesting(false);
    }
  };

  const handleDeployRule = async () => {
    setDeploying(true);
    setDeployStatus(null);
    try {
      const res = await createSigmaRule(testYaml, true);
      setDeployStatus({ success: true, message: res.message });
      loadRules();
    } catch (err) {
      setDeployStatus({ success: false, error: err.message });
    } finally {
      setDeploying(false);
    }
  };

  const filteredRules = rules.filter((r) => {
    const matchText =
      search === '' ||
      r.title.toLowerCase().includes(search.toLowerCase()) ||
      r.id.toLowerCase().includes(search.toLowerCase()) ||
      (r.mitreTechniques || []).some((m) => m.toLowerCase().includes(search.toLowerCase()));

    const matchSev = selectedSev === 'ALL' || (r.level || '').toLowerCase() === selectedSev.toLowerCase();
    return matchText && matchSev;
  });

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="glass-panel p-6 rounded-2xl max-w-4xl w-full border border-purple-500/30 space-y-5 shadow-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-xl bg-purple-500/20 text-purple-400 border border-purple-500/30">
              <FileCode className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-extrabold text-white flex items-center gap-2">
                {isZh ? 'Detection-as-Code: Sigma Rules 偵測引擎' : 'Detection-as-Code: Sigma Rules Engine'}
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                {isZh ? '以標準 YAML 定義之威脅偵測規則，支援修飾符解析、MITRE 對齊與即時掃描' : 'Declarative threat detection rules parsed from standard YAML with MITRE ATT&CK mappings.'}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab switcher */}
        <div className="flex items-center justify-between border-b border-slate-800 font-mono text-xs">
          <div className="flex">
            <button
              onClick={() => setActiveTab('rules')}
              className={`pb-2 px-4 font-bold border-b-2 transition-all ${
                activeTab === 'rules'
                  ? 'border-purple-500 text-purple-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              📜 {isZh ? `現役規則清單 (${rules.length})` : `Loaded Rules (${rules.length})`}
            </button>
            <button
              onClick={() => setActiveTab('test')}
              className={`pb-2 px-4 font-bold border-b-2 transition-all ${
                activeTab === 'test'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              🧪 {isZh ? '規則測試與部署實驗室 (Playground)' : 'Detection Rule Playground'}
            </button>
          </div>
          {activeTab === 'rules' && (
            <button
              onClick={async () => {
                await reloadSigmaRules();
                loadRules();
              }}
              className="text-xs text-slate-400 hover:text-white flex items-center gap-1 pb-2"
            >
              <RefreshCw className="w-3.5 h-3.5" /> {isZh ? '重新讀取磁碟' : 'Reload Disk'}
            </button>
          )}
        </div>

        {/* TAB 1: RULES LIST */}
        {activeTab === 'rules' && (
          <div className="space-y-4">
            {/* Search & Severity filter */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-xs">
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={isZh ? '搜尋規則名稱、ID 或 MITRE 戰術…' : 'Search rule title, ID, or MITRE...'}
                className="bg-slate-950 border border-slate-800 text-slate-300 rounded-lg px-3 py-1.5 focus:outline-none focus:border-purple-500 w-full sm:w-72"
              />
              <div className="flex items-center gap-1.5 shrink-0">
                <Filter className="w-3.5 h-3.5 text-slate-500" />
                {['ALL', 'Critical', 'High', 'Medium'].map((s) => (
                  <button
                    key={s}
                    onClick={() => setSelectedSev(s)}
                    className={`px-2.5 py-1 rounded text-[11px] font-bold transition-all ${
                      selectedSev === s
                        ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                        : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white'
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>

            {loading ? (
              <div className="text-center py-8 text-xs font-mono text-slate-500">
                {isZh ? '正在讀取 Sigma YAML 規則…' : 'Loading Sigma YAML rules...'}
              </div>
            ) : filteredRules.length === 0 ? (
              <div className="text-center py-8 text-xs font-mono text-slate-500">
                {isZh ? '找不到相符之 Sigma 規則。' : 'No matching Sigma rules found.'}
              </div>
            ) : (
              <div className="space-y-3">
                {filteredRules.map((rule) => {
                  const isExpanded = expandedRuleId === rule.id;
                  const sevColor =
                    rule.level === 'critical'
                      ? 'text-red-400 bg-red-500/10 border-red-500/30'
                      : rule.level === 'high'
                      ? 'text-amber-400 bg-amber-500/10 border-amber-500/30'
                      : 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30';

                  return (
                    <div key={rule.id} className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-2.5 transition-all hover:border-purple-500/30">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${sevColor}`}>
                            {rule.level}
                          </span>
                          <span className="text-sm font-bold text-white font-mono">{rule.title}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono text-slate-500">ID: {rule.id}</span>
                          <button
                            onClick={() => setExpandedRuleId(isExpanded ? null : rule.id)}
                            className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-purple-400 text-[10px] font-mono font-bold border border-slate-800"
                          >
                            {isExpanded ? (isZh ? '隱藏 YAML' : 'Hide YAML') : (isZh ? '檢視 YAML' : 'View YAML')}
                          </button>
                        </div>
                      </div>

                      <p className="text-xs text-slate-400 font-mono leading-relaxed">{rule.description}</p>

                      <div className="flex items-center justify-between flex-wrap gap-2 pt-2 border-t border-slate-900 text-xs font-mono">
                        <div className="flex items-center gap-2 flex-wrap">
                          {(rule.mitreTechniques || []).map((m) => (
                            <span key={m} className="px-1.5 py-0.5 rounded bg-slate-900 text-cyan-400 text-[10px] border border-slate-800 flex items-center gap-1">
                              <Tag className="w-2.5 h-2.5" /> MITRE: {m}
                            </span>
                          ))}
                          {rule.logsource?.category && (
                            <span className="text-[10px] text-slate-500">Source: {rule.logsource.category}</span>
                          )}
                        </div>
                        <div className="text-[11px] text-emerald-400 font-mono">
                          {rule.response ? `💡 ${rule.response}` : ''}
                        </div>
                      </div>

                      {/* Expandable YAML Viewer */}
                      {isExpanded && (
                        <div className="pt-2 space-y-1">
                          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                            <span>{isZh ? '原始 Sigma YAML 定義檔：' : 'Raw Sigma YAML Specification:'}</span>
                            <button
                              onClick={() => handleCopy(rule.rawYaml || '', rule.id)}
                              className="flex items-center gap-1 text-[11px] hover:text-white"
                            >
                              {copiedId === rule.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              {copiedId === rule.id ? (isZh ? '已複製' : 'Copied') : (isZh ? '複製 YAML' : 'Copy YAML')}
                            </button>
                          </div>
                          <pre className="p-3 rounded-xl bg-slate-950 border border-purple-500/20 text-[11px] font-mono text-purple-300 overflow-x-auto max-h-60 leading-relaxed">
                            {rule.rawYaml}
                          </pre>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* TAB 2: PLAYGROUND / TESTER */}
        {activeTab === 'test' && (
          <div className="space-y-4 font-mono text-xs">
            <div>
              <div className="flex items-center justify-between mb-1.5 text-slate-400">
                <span>{isZh ? '自訂 Sigma YAML 規則編輯區：' : 'Custom Sigma Rule YAML Editor:'}</span>
                <button
                  onClick={() => setTestYaml(SAMPLE_CUSTOM_RULE)}
                  className="text-[10px] text-purple-400 hover:text-purple-300"
                >
                  {isZh ? '重設為範例' : 'Reset to Sample'}
                </button>
              </div>
              <textarea
                rows={12}
                value={testYaml}
                onChange={(e) => setTestYaml(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-cyan-300 font-mono text-[11px] focus:outline-none focus:border-purple-500 leading-relaxed"
              />
            </div>

            <div className="flex items-center justify-between">
              <div className="text-[11px] text-slate-400">
                {isZh
                  ? '點擊「執行比對測試」將以此 YAML 對照目前記憶體中的日誌遙測資料流進行比對。'
                  : 'Tests this Sigma YAML against in-memory telemetry logs without persisting.'}
              </div>
              <div className="flex gap-2">
                <button
                  onClick={handleDeployRule}
                  disabled={deploying}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold transition-all disabled:opacity-50"
                >
                  <Plus className="w-3.5 h-3.5" />
                  {deploying ? (isZh ? '部署中…' : 'Deploying...') : (isZh ? '儲存並部署規則' : 'Save & Deploy')}
                </button>
                <button
                  onClick={handleRunTest}
                  disabled={testing}
                  className="flex items-center gap-1.5 px-4 py-1.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold transition-all disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5 fill-slate-950" />
                  {testing ? (isZh ? '測試中…' : 'Testing...') : (isZh ? '執行比對測試' : 'Run Detection Test')}
                </button>
              </div>
            </div>

            {/* Test Results */}
            {testResult && (
              <div
                className={`p-4 rounded-xl border space-y-2 ${
                  testResult.success
                    ? 'bg-slate-950/80 border-emerald-500/30'
                    : 'bg-red-500/10 border-red-500/30 text-red-300'
                }`}
              >
                {testResult.success ? (
                  <>
                    <div className="flex items-center justify-between text-emerald-400 font-bold">
                      <span className="flex items-center gap-1.5">
                        <Check className="w-4 h-4" />
                        {isZh
                          ? `YAML 語法校驗合格！測試 ${testResult.totalEventsTested} 筆日誌，命中 ${testResult.matchCount} 次`
                          : `YAML Validated! Tested ${testResult.totalEventsTested} events, ${testResult.matchCount} matched.`}
                      </span>
                      <span className="text-[10px] text-slate-500">Rule ID: {testResult.rule?.id}</span>
                    </div>
                    {testResult.matches?.length > 0 && (
                      <div className="space-y-2 max-h-40 overflow-y-auto pt-2">
                        {testResult.matches.map((m, idx) => (
                          <div key={idx} className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-300">
                            <span className="text-cyan-400 font-bold">Event #{idx + 1}:</span> {m.event?.details || m.event?.commandLine || JSON.stringify(m.event)}
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                ) : (
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-red-400" />
                    <span>{testResult.error}</span>
                  </div>
                )}
              </div>
            )}

            {deployStatus && (
              <div
                className={`p-3 rounded-xl border flex items-center gap-2 ${
                  deployStatus.success
                    ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                    : 'bg-red-500/10 text-red-300 border-red-500/30'
                }`}
              >
                {deployStatus.success ? <Check className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-red-400" />}
                <span>{deployStatus.message || deployStatus.error}</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
