import React from 'react';
import {
  LayoutDashboard,
  Shield,
  Radar,
  Bug,
  Activity,
  Bot,
  FileSpreadsheet,
  Database,
  Zap,
  Settings,
  ShieldAlert
} from 'lucide-react';
import { useLanguage } from '../contexts/LanguageContext';

export default function Sidebar({ activeTab, setActiveTab }) {
  const { t } = useLanguage();

  const navGroups = [
    {
      label: t('sidebar.socOperations', 'SOC 核心運維與遙測'),
      items: [
        { id: 'dashboard', label: t('sidebar.dashboard', '戰情總覽 (Dashboard)'), icon: LayoutDashboard },
        { id: 'siem-console', label: t('sidebar.siemConsole', 'SIEM 即時事件主控台'), icon: Shield, badge: 'PROD' },
        { id: 'asset-discovery', label: t('sidebar.assetDiscovery', '主動資產發現與掃描'), icon: Radar },
        { id: 'vuln', label: t('sidebar.vuln', '弱點管理 (NVD API)'), icon: Bug },
        { id: 'network-telemetry', label: '網路遙測與封包解構', icon: Activity, badge: 'NPCAP' },
        { id: 'threat-investigation', label: 'IDS 聯防與事件調查', icon: ShieldAlert, badge: 'EVE' },
      ]
    },
    {
      label: t('sidebar.aiResponse', 'AI 智能與事件處置'),
      items: [
        { id: 'ai-copilot', label: 'AI 資安副手 (Copilot)', icon: Bot, badge: 'GEMINI' },
        { id: 'reports', label: t('sidebar.reports', '資安事件調查報告'), icon: FileSpreadsheet },
      ]
    },
    {
      label: t('sidebar.intelSimulation', '情報知識與模擬演練'),
      items: [
        { id: 'threat-intel', label: '威脅情報與 MITRE 矩陣', icon: Database, badge: 'REF' },
        { id: 'simulation', label: t('sidebar.simulation', '攻擊演練模擬 (Simulation)'), icon: Zap, badge: 'DEMO' },
        { id: 'settings', label: t('sidebar.settings', '系統設定與權限 (Settings)'), icon: Settings },
      ]
    }
  ];

  return (
    <aside className="w-64 border-r border-cyan-500/15 bg-slate-950/60 backdrop-blur-xl flex flex-col justify-between py-4 shrink-0 overflow-y-auto">
      <div className="space-y-4 px-3">
        {navGroups.map((group, gIdx) => (
          <div key={gIdx}>
            <div className="px-3 py-2 text-[10px] font-mono font-semibold text-slate-500 uppercase tracking-widest">
              {group.label}
            </div>
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveTab(item.id)}
                    className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all duration-200 group ${
                      isActive
                        ? 'bg-gradient-to-r from-cyan-500/20 to-blue-600/10 text-cyan-300 border border-cyan-500/30 shadow-md shadow-cyan-500/10'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                    }`}
                  >
                    <div className="flex items-center gap-3 truncate">
                      <Icon className={`w-4 h-4 shrink-0 transition-colors ${isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-cyan-400'}`} />
                      <span className="truncate">{item.label}</span>
                    </div>
                    {item.badge && (
                      <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border shrink-0 ${
                        item.badge === 'PROD' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30' :
                        item.badge === 'GEMINI' ? 'bg-purple-500/20 text-purple-300 border-purple-500/30' :
                        item.badge === 'NPCAP' ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30' :
                        item.badge === 'EVE' ? 'bg-blue-500/20 text-blue-300 border-blue-500/30' :
                        item.badge === 'DEMO' ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' :
                        'bg-slate-800 text-slate-400 border-slate-700'
                      }`}>
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      <div className="px-4 py-3 border-t border-slate-900 text-[10px] text-slate-500 font-mono flex items-center justify-between">
        <span>CyberMind Architecture</span>
        <span className="text-cyan-400">Zero Fake Data</span>
      </div>
    </aside>
  );
}
