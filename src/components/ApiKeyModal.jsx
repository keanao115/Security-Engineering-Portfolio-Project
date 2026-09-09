import React, { useState } from 'react';
import { Key, X, Check, Cpu, Globe, Shield, RefreshCw, Eye, EyeOff, Server, Zap, CheckCircle2, XCircle } from 'lucide-react';
import { useLanguage } from '../contexts/LanguageContext';
import { useAiConfig } from '../contexts/AiConfigContext';

export default function ApiKeyModal({ apiKey: propApiKey, setApiKey: propSetApiKey, onClose }) {
  const { t, language } = useLanguage();
  const isZh = language === 'zh-TW';
  const { aiConfig, updateAiConfig, aiStatus, refreshAiStatus, testCurrentConnection } = useAiConfig();

  const [provider, setProvider] = useState(aiConfig?.provider || 'gemini');
  const [apiKey, setApiKey] = useState(aiConfig?.apiKey || propApiKey || '');
  const [model, setModel] = useState(aiConfig?.model || (provider === 'gemini' ? 'gemini-1.5-flash' : 'gpt-4o-mini'));
  const [baseUrl, setBaseUrl] = useState(aiConfig?.baseUrl || '');
  const [showKey, setShowKey] = useState(false);
  
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);

  const handleProviderChange = (newProvider) => {
    setProvider(newProvider);
    setTestResult(null);
    if (newProvider === 'gemini') {
      if (!model || model.startsWith('gpt') || model.startsWith('llama')) {
        setModel('gemini-1.5-flash');
      }
    } else if (newProvider === 'openai') {
      if (!model || model.startsWith('gemini')) {
        setModel('gpt-4o-mini');
      }
    } else if (newProvider === 'local') {
      setModel('Ollama / Embedded SOC Engine');
      if (!baseUrl) setBaseUrl('http://localhost:11434/v1');
    }
  };

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const draftConfig = {
        provider,
        apiKey: apiKey.trim(),
        model: model.trim(),
        baseUrl: baseUrl.trim() || undefined,
      };
      const result = await testCurrentConnection(draftConfig);
      setTestResult(result);
    } catch (err) {
      setTestResult({ success: false, message: err.message || '連線測試時發生異常' });
    } finally {
      setTesting(false);
    }
  };

  const handleSave = () => {
    const trimmedKey = apiKey.trim();
    const effectiveProvider = provider === 'local' || !trimmedKey ? 'local' : provider;
    
    const newConfig = {
      provider: effectiveProvider,
      apiKey: trimmedKey,
      model: model.trim() || (effectiveProvider === 'gemini' ? 'gemini-1.5-flash' : 'Embedded SOC Engine'),
      baseUrl: baseUrl.trim() || undefined,
    };

    updateAiConfig(newConfig);
    if (propSetApiKey) {
      propSetApiKey(trimmedKey);
    }
    refreshAiStatus();
    onClose();
  };

  const handleClearToLocal = () => {
    setApiKey('');
    setProvider('local');
    setModel('Embedded SOC Engine');
    setBaseUrl('http://localhost:11434/v1');
    setTestResult(null);

    const localConfig = {
      provider: 'local',
      apiKey: '',
      model: 'Embedded SOC Engine',
      baseUrl: 'http://localhost:11434/v1',
    };
    updateAiConfig(localConfig);
    if (propSetApiKey) propSetApiKey('');
    refreshAiStatus();
    onClose();
  };

  const siemCount = aiStatus?.telemetry?.siemEventsCount ?? 0;
  const portCount = aiStatus?.telemetry?.openPortsCount ?? 0;
  const cveCount = aiStatus?.telemetry?.nvdFindingsCount ?? 0;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 overflow-y-auto">
      <div className="glass-panel p-6 rounded-2xl max-w-xl w-full border border-cyan-500/30 space-y-5 shadow-2xl my-8">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
              <Cpu className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-bold text-sm text-white font-mono flex items-center gap-2">
                {t('apiKeyModal.title', 'CyberMind AI 模型與 API 設定中心')}
              </h3>
              <p className="text-[11px] text-slate-400 font-mono">
                {t('apiKeyModal.subtitle', '由您指定之 AI 模型進行全系統真實數據分析；未提供 API 時自動切換為本地模型')}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800/60 transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Real SOC Telemetry Grounding Banner */}
        <div className="bg-slate-950/80 border border-emerald-500/30 rounded-xl p-3 flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse shrink-0" />
            <span className="text-emerald-300 font-semibold">
              {t('apiKeyModal.telemetryActive', '全系統真實數據源已掛載')}
            </span>
          </div>
          <div className="flex items-center gap-2 text-[11px] text-slate-400">
            <span>SIEM: <strong className="text-cyan-300">{siemCount}</strong></span>
            <span>•</span>
            <span>開放端口: <strong className="text-cyan-300">{portCount}</strong></span>
            <span>•</span>
            <span>CVE 弱點: <strong className="text-cyan-300">{cveCount}</strong></span>
          </div>
        </div>

        {/* Provider Selector Cards */}
        <div className="space-y-2">
          <label className="text-xs font-mono font-semibold text-slate-300 flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            {t('apiKeyModal.providerLabel', 'AI 服務提供商與架構')}
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 font-mono text-xs">
            <button
              type="button"
              onClick={() => handleProviderChange('gemini')}
              className={`p-3 rounded-xl border text-left transition-all ${
                provider === 'gemini'
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-md shadow-cyan-500/10 font-bold'
                  : 'bg-slate-900/60 text-slate-400 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-white text-xs">Google Gemini</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300">API</span>
              </div>
              <div className="text-[10px] text-slate-400 font-normal">Gemini 1.5 Flash / Pro</div>
            </button>

            <button
              type="button"
              onClick={() => handleProviderChange('openai')}
              className={`p-3 rounded-xl border text-left transition-all ${
                provider === 'openai'
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-md shadow-cyan-500/10 font-bold'
                  : 'bg-slate-900/60 text-slate-400 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-white text-xs">OpenAI / 相容</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300">API</span>
              </div>
              <div className="text-[10px] text-slate-400 font-normal">GPT-4o / DeepSeek</div>
            </button>

            <button
              type="button"
              onClick={() => handleProviderChange('local')}
              className={`p-3 rounded-xl border text-left transition-all ${
                provider === 'local'
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50 shadow-md shadow-emerald-500/10 font-bold'
                  : 'bg-slate-900/60 text-slate-400 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-white text-xs">{isZh ? '本地模型' : 'Local Model'}</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300">Zero Egress</span>
              </div>
              <div className="text-[10px] text-slate-400 font-normal">Ollama / 嵌入式引擎</div>
            </button>
          </div>
        </div>

        {/* Configuration Details Form */}
        <div className="space-y-3 bg-slate-950/60 border border-slate-800/80 rounded-xl p-4 font-mono text-xs">
          
          {/* If Local Model chosen */}
          {provider === 'local' ? (
            <div className="space-y-2.5">
              <div className="flex items-start gap-2.5 text-slate-300 text-xs leading-relaxed bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                <Shield className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <p className="font-semibold text-emerald-300 mb-1">
                    {isZh ? '本地模式運作機制 (真實數據解析)' : 'Local Mode Operational Logic (Real SOC Telemetry)'}
                  </p>
                  <p className="text-[11px] text-slate-400">
                    {t(
                      'apiKeyModal.localModelHint',
                      '未提供 API 時，CyberMind 將直接調用本機 Ollama (localhost:11434) 或嵌入式 SOC 遙測真實數據推論引擎，即時關聯當前所有 SIEM 事件、NVD 漏洞與連接埠。'
                    )}
                  </p>
                </div>
              </div>

              <div>
                <label className="text-[11px] text-slate-400 block mb-1">
                  {isZh ? '本機端點 (Ollama / Local Endpoint)' : 'Local Endpoint URL'}
                </label>
                <input
                  type="text"
                  value={baseUrl || 'http://localhost:11434/v1'}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  placeholder="http://localhost:11434/v1"
                  className="w-full bg-slate-900 border border-slate-800 text-slate-200 rounded-lg px-3 py-2 text-xs focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>
          ) : (
            /* Online API Configuration (Gemini / OpenAI) */
            <div className="space-y-3">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-[11px] text-slate-300 flex items-center gap-1.5">
                    <Key className="w-3 h-3 text-cyan-400" />
                    {t('apiKeyModal.apiKeyLabel', 'API 金鑰 (API Key)')}
                  </label>
                  <span className="text-[10px] text-amber-400">
                    {isZh ? '未填寫金鑰時將自動使用本地模型分析' : 'If left blank, local model is used'}
                  </span>
                </div>
                <div className="relative">
                  <input
                    type={showKey ? 'text' : 'password'}
                    value={apiKey}
                    onChange={(e) => {
                      setApiKey(e.target.value);
                      setTestResult(null);
                    }}
                    placeholder={provider === 'gemini' ? 'AIzaSy... (Google Gemini API Key)' : 'sk-... (OpenAI / DeepSeek Key)'}
                    className="w-full bg-slate-900 border border-slate-800 text-cyan-300 rounded-lg pl-3 pr-10 py-2 text-xs focus:outline-none focus:border-cyan-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowKey(!showKey)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                  >
                    {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <div>
                  <label className="text-[11px] text-slate-400 block mb-1">
                    {t('apiKeyModal.modelLabel', 'AI 模型名稱 (Model Name)')}
                  </label>
                  {provider === 'gemini' ? (
                    <select
                      value={model}
                      onChange={(e) => setModel(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-800 text-slate-200 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:border-cyan-500"
                    >
                      <option value="gemini-1.5-flash">gemini-1.5-flash (推薦: 高速即時分析)</option>
                      <option value="gemini-1.5-pro">gemini-1.5-pro (深度資安推理)</option>
                      <option value="gemini-2.0-flash-exp">gemini-2.0-flash-exp (最新實驗模型)</option>
                    </select>
                  ) : (
                    <input
                      type="text"
                      value={model}
                      onChange={(e) => setModel(e.target.value)}
                      placeholder="gpt-4o-mini / deepseek-chat"
                      className="w-full bg-slate-900 border border-slate-800 text-slate-200 rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:border-cyan-500"
                    />
                  )}
                </div>

                <div>
                  <label className="text-[11px] text-slate-400 block mb-1">
                    {t('apiKeyModal.baseUrlLabel', 'API 自訂端點 (Base URL - 可選)')}
                  </label>
                  <input
                    type="text"
                    value={baseUrl}
                    onChange={(e) => setBaseUrl(e.target.value)}
                    placeholder={provider === 'gemini' ? 'https://generativelanguage.googleapis.com' : 'https://api.openai.com/v1'}
                    className="w-full bg-slate-900 border border-slate-800 text-slate-200 rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
            </div>
          )}

          {/* Test Connection Button & Result Box */}
          <div className="pt-1">
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleTestConnection}
                disabled={testing}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/30 text-xs font-mono font-medium flex items-center gap-1.5 transition-all disabled:opacity-50"
              >
                <RefreshCw className={`w-3 h-3 ${testing ? 'animate-spin' : ''}`} />
                {testing ? t('apiKeyModal.testing', '測試連線中...') : t('apiKeyModal.testConnection', '測試連線 (Test Connection)')}
              </button>
            </div>

            {testResult && (
              <div
                className={`mt-2.5 p-2.5 rounded-lg border flex items-start gap-2 text-[11px] font-mono ${
                  testResult.success
                    ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                    : 'bg-red-950/40 border-red-500/40 text-red-300'
                }`}
              >
                {testResult.success ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                ) : (
                  <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                )}
                <div className="flex-1">
                  <div className="font-bold flex items-center justify-between">
                    <span>{testResult.success ? t('apiKeyModal.statusConnected', '連線成功') : t('apiKeyModal.statusFailed', '連線失敗')}</span>
                    {testResult.latencyMs && (
                      <span className="text-[10px] opacity-80">{testResult.latencyMs} ms</span>
                    )}
                  </div>
                  <p className="mt-0.5 opacity-90">{testResult.message}</p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Modal Action Buttons */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800">
          <button
            type="button"
            onClick={handleClearToLocal}
            className="text-[11px] font-mono text-slate-400 hover:text-amber-400 transition-colors py-1"
          >
            {t('apiKeyModal.clearToLocal', '清除金鑰並切換為本地模型')}
          </button>

          <div className="flex items-center gap-2 ml-auto">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 font-mono text-xs hover:bg-slate-800 transition-colors"
            >
              {isZh ? '取消' : 'Cancel'}
            </button>
            <button
              type="button"
              onClick={handleSave}
              className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-mono text-xs font-bold transition-all flex items-center gap-1.5 shadow-lg shadow-cyan-500/20"
            >
              <Check className="w-3.5 h-3.5" />
              {t('apiKeyModal.saveAndClose', '儲存並套用設定')}
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
