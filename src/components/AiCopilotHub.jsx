import React, { useState } from 'react';
import { Bot, MessageSquare } from 'lucide-react';
import AiChatView from './AiChatView';
import SocCopilotView from './SocCopilotView';
import { useLanguage } from '../contexts/LanguageContext';

export default function AiCopilotHub({ apiKey }) {
  const { t, language } = useLanguage();
  const isZh = language === 'zh-TW';
  const [activeSubTab, setActiveSubTab] = useState('chat');

  const subTabs = [
    { id: 'chat', label: t('aiHub.chatTab', 'AI 資安智能對話 (AI Chat Copilot)'), icon: MessageSquare },
    { id: 'playbook', label: t('aiHub.playbookTab', '事件應變與處置劇本 (SOC Playbooks)'), icon: Bot },
  ];

  return (
    <div className="space-y-6">
      {/* Sub-navigation bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Bot className="w-6 h-6 text-cyan-400" />
            {t('aiHub.title', 'AI 資安副手與應變決策中心 (AI SOC Copilot Hub)')}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            {isZh
              ? '整合使用者指定 API 模型與本地模型真實數據分析，並支援標準化資安事件處置應變 (Incident Response) 引導劇本'
              : 'Enterprise SOC reasoning powered by user-configured AI APIs or Local Model with Incident Response playbooks'}
          </p>
        </div>

        <div className="flex items-center gap-1 bg-slate-900/80 p-1 rounded-xl border border-slate-800">
          {subTabs.map(tab => {
            const Icon = tab.icon;
            const isActive = activeSubTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveSubTab(tab.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab Contents */}
      {activeSubTab === 'chat' && <AiChatView apiKey={apiKey} />}
      {activeSubTab === 'playbook' && <SocCopilotView />}
    </div>
  );
}
