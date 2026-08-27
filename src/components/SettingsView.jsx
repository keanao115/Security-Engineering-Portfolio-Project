import React from 'react';
import { Settings, Key, Cpu, ShieldCheck, UserCheck, Lock, Globe } from 'lucide-react';
import { useLanguage } from '../contexts/LanguageContext';
import LanguageSelector from './LanguageSelector';

export default function SettingsView({ apiKey, setApiKey, aiModel, setAiModel }) {
  const { t } = useLanguage();

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Settings className="w-6 h-6 text-cyan-400" />
            {t('settings.title', '系統設定與使用者權限配置')}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {t('settings.subtitle', 'Configure AI Engine Model, API key credentials, and Role-Based Access Controls (RBAC).')}
          </p>
        </div>
      </div>

      {/* Language Preference Section */}
      <div className="glass-panel p-6 rounded-2xl space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2 font-mono">
              <Globe className="w-4 h-4 text-cyan-400" /> {t('settings.languageSection', '語言與介面偏好設定 (Language & Region)')}
            </h3>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              {t('settings.languageDesc', '選擇系統操作介面的主要顯示語言。')}
            </p>
          </div>
        </div>

        <LanguageSelector variant="settings" />
      </div>

      {/* AI Model Selection */}
      <div className="glass-panel p-6 rounded-2xl space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2 font-mono">
          <Cpu className="w-4 h-4 text-cyan-400" /> {t('settings.aiModelSection', 'AI 推理模型選擇')}
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
          {[
            { name: 'Google Gemini 1.5 Pro', desc: t('settings.deepReasoning', '深度資安脈絡推理 (推薦)') },
            { name: 'Google Gemini 1.5 Flash', desc: t('settings.ultraFast', '極速日誌比對與高通量分析') },
            { name: 'Local Security Rule Engine (Offline)', desc: t('settings.offlineMode', '100% 離線本地規則引擎運算') }
          ].map((item) => (
            <button
              key={item.name}
              onClick={() => setAiModel(item.name)}
              className={`p-4 rounded-xl border text-left transition-all ${
                aiModel === item.name
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 shadow-md shadow-cyan-500/10'
                  : 'bg-slate-950 text-slate-400 border-slate-900 hover:border-slate-800 hover:text-slate-200'
              }`}
            >
              <div className="font-bold text-white mb-1">{item.name}</div>
              <div className="text-[10px] text-slate-500">
                {item.desc}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* API Key Credentials */}
      <div className="glass-panel p-6 rounded-2xl space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2 font-mono">
          <Key className="w-4 h-4 text-cyan-400" /> {t('settings.apiKeySection', 'API 金鑰與憑證管理')}
        </h3>

        <div className="space-y-2 font-mono text-xs">
          <label className="text-slate-400">{t('settings.keyLabel', 'Gemini / OpenAI API 密鑰：')}</label>
          <input
            type="password"
            placeholder="AIzaSy... / sk-..."
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-cyan-300 rounded-xl px-4 py-2.5 w-full focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Role-Based Access Control (RBAC) */}
      <div className="glass-panel p-6 rounded-2xl space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2 font-mono">
          <Lock className="w-4 h-4 text-cyan-400" /> {t('settings.rbacSection', '角色存取控制 (RBAC 矩陣)')}
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 font-mono text-xs">
          <div className="p-3 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyan-300 font-bold text-center">
            {t('settings.adminRole', '資安管理員 (完整權限)')}
          </div>
          <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl text-slate-400 text-center">
            {t('settings.analystRole', 'SOC 分析師')}
          </div>
          <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl text-slate-400 text-center">
            {t('settings.engineerRole', '資安維運工程師')}
          </div>
          <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl text-slate-400 text-center">
            {t('settings.readOnlyRole', '唯讀稽核員')}
          </div>
        </div>
      </div>
    </div>
  );
}
