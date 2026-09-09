import React from 'react';
import { Shield, Key, Sparkles, Activity, User, Bell } from 'lucide-react';
import PlatformModeBadge from './PlatformModeBadge';
import LanguageSelector from './LanguageSelector';
import { useLanguage } from '../contexts/LanguageContext';

import { useAuth } from '../contexts/AuthContext';
import { useAiConfig } from '../contexts/AiConfigContext';

export default function Header({ apiKey, setApiKey, setShowApiModal: propSetShowApiModal }) {
  const { t, language } = useLanguage();
  const isZh = language === 'zh-TW';
  const { user, role, switchRole } = useAuth();
  const { aiConfig, setShowApiModal: contextSetShowApiModal, isOnlineApiConfigured } = useAiConfig();

  const openModal = propSetShowApiModal || contextSetShowApiModal;
  const isOnline = isOnlineApiConfigured || (apiKey && apiKey.trim().length > 0);

  const getRoleBadgeStyle = (r) => {
    switch (r) {
      case 'Admin': return 'bg-red-500/20 text-red-300 border-red-500/40';
      case 'Analyst': return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';
      case 'Viewer': return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
      default: return 'bg-slate-700 text-slate-300 border-slate-600';
    }
  };

  return (
    <header className="h-16 border-b border-cyan-500/15 bg-slate-950/80 backdrop-blur-xl sticky top-0 z-40 px-6 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 p-0.5 shadow-lg shadow-cyan-500/20">
          <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-extrabold text-base tracking-wider bg-gradient-to-r from-white via-slate-200 to-cyan-400 bg-clip-text text-transparent">
              {t('header.portfolioTitle', 'Security Engineering Portfolio Project')}
            </h1>
            <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              {t('header.version', 'ENTERPRISE v3.0')}
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono">
            {t('header.subtitle', 'Autonomous AI Threat Detection & Real-Time SOC Monitoring')}
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3 md:gap-4">
        {/* Language Selector Dropdown */}
        <LanguageSelector variant="header" />

        <PlatformModeBadge />

        {/* Dynamic AI Status Indicator */}
        <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors">
          {isOnline ? (
            <div className="flex items-center gap-1.5 text-cyan-400">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              <span>AI: {aiConfig?.provider?.toUpperCase()} API ({aiConfig?.model || 'Online'})</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              <span>AI: {isZh ? '本地模型 (實時遙測推論)' : 'Local Model (Zero Egress)'}</span>
            </div>
          )}
        </div>

        <button
          onClick={() => openModal(true)}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs transition-all font-mono shadow-sm ${
            isOnline
              ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-300 hover:border-cyan-400'
              : 'bg-slate-900 hover:bg-slate-800 border-slate-700 text-slate-300 hover:text-cyan-300 hover:border-cyan-500/30'
          }`}
          title={isZh ? '配置由您提供之 AI API 模型，未提供時自動使用本地模型分析' : 'Configure custom AI API or utilize Local Model'}
        >
          <Key className="w-3.5 h-3.5 text-cyan-400" />
          <span>
            {isOnline
              ? (isZh ? `API 已配置 (${aiConfig?.provider || 'Gemini'})` : `API Set: ${aiConfig?.provider || 'Gemini'}`)
              : (isZh ? '本地模型 (點擊配置 API)' : 'Local Model (Configure API)')}
          </span>
        </button>

        <div className="flex items-center gap-2 border-l border-slate-800 pl-4">
          <div className="flex flex-col items-end">
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-mono font-semibold text-slate-300">
                {user?.username || 'soc_analyst'}
              </span>
              <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase font-bold ${getRoleBadgeStyle(role)}`}>
                {role}
              </span>
            </div>
            {/* RBAC Role Switcher for Interviews & Testing */}
            <div className="flex items-center gap-1 mt-0.5">
              <span className="text-[10px] text-slate-500 font-mono">RBAC:</span>
              <select
                value={role}
                onChange={(e) => switchRole(e.target.value)}
                className="bg-slate-900 border border-slate-700 text-cyan-300 text-[10px] rounded px-1 py-0.5 font-mono cursor-pointer focus:outline-none focus:border-cyan-400"
                title="切換身分角色以測試後端 403 Forbidden / 最小權限原則"
              >
                <option value="Admin">Admin (全權限)</option>
                <option value="Analyst">Analyst (分析維運)</option>
                <option value="Viewer">Viewer (唯讀稽核)</option>
                <option value="Guest">Guest (無 Token 測試)</option>
              </select>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
