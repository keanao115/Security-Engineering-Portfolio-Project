import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  FileText,
  Network,
  Bug,
  FileSpreadsheet,
  Grid,
  Database,
  Zap,
  Bot,
  BookOpen,
  MessageSquare,
  Settings,
  Activity,
  Search,
  Radar,
  Shield,
  Server
} from 'lucide-react';
import { useLanguage } from '../contexts/LanguageContext';

export default function Sidebar({ activeTab, setActiveTab }) {
  const { t } = useLanguage();

  const navGroups = [
    {
      label: t('sidebar.socNavigation', 'SOC NAVIGATION'),
      items: [
        { id: 'dashboard', label: t('sidebar.dashboard', '首頁 Dashboard'), icon: LayoutDashboard },
        { id: 'threat', label: t('sidebar.threat', '威脅深度分析 (Threat Analysis)'), icon: ShieldAlert },
        { id: 'log', label: t('sidebar.log', '多源日誌分析 (Log Analyzer)'), icon: FileText },
        { id: 'network', label: t('sidebar.network', '網路安全掃描 (Network Scanner)'), icon: Network },
        { id: 'vuln', label: t('sidebar.vuln', '弱點掃描引擎 (Vulnerability Scanner)'), icon: Bug },
        { id: 'reports', label: t('sidebar.reports', '資安事件報告 (Incident Reports)'), icon: FileSpreadsheet },
        { id: 'mitre', label: t('sidebar.mitre', 'MITRE ATT&CK 矩陣'), icon: Grid },
        { id: 'ioc', label: t('sidebar.ioc', 'IOC 威脅情報庫 (IOC Database)'), icon: Database },
      ]
    },
    {
      label: t('sidebar.liveMonitoring', 'LIVE MONITORING & TELEMETRY'),
      items: [
        { id: 'collectors', label: t('sidebar.collectors', '採集器管理 (Collector Management)'), icon: Server, badge: 'PROD' },
        { id: 'packet-capture', label: t('sidebar.packetCapture', '即時封包捕獲 (Packet Capture)'), icon: Activity, badge: 'NPCAP' },
        { id: 'zeek-suricata', label: t('sidebar.zeekSuricata', 'Zeek & Suricata IDS 聯防'), icon: Shield, badge: 'EVE' },
        { id: 'pipeline-performance', label: t('sidebar.pipelinePerformance', '數據管線效能 (Pipeline Perf)'), icon: Zap, badge: 'METRICS' },
        { id: 'investigation-timeline', label: t('sidebar.investigationTimeline', '事件證據時間軸 (Evidence Timeline)'), icon: Radar, badge: 'AI' },
        { id: 'live-network', label: t('sidebar.liveNetwork', '即時網路監控 (Live Network)'), icon: Activity },
        { id: 'packet-inspector', label: t('sidebar.packetInspector', '深度封包檢視 (Packet Inspector)'), icon: Search },
        { id: 'asset-discovery', label: t('sidebar.assetDiscovery', '主動資產發現 (Asset Discovery)'), icon: Radar },
        { id: 'siem-console', label: t('sidebar.siemConsole', 'SIEM 即時事件主控台'), icon: Shield },
      ]
    },
    {
      label: t('sidebar.aiSimulation', 'AI & SIMULATION'),
      items: [
        { id: 'simulation', label: t('sidebar.simulation', '攻擊模擬 (Simulation)'), icon: Zap, highlight: true },
        { id: 'copilot', label: t('sidebar.copilot', 'SOC Copilot (處置劇本)'), icon: Bot, highlight: true },
        { id: 'rag', label: t('sidebar.rag', 'RAG 知識庫 (Knowledge)'), icon: BookOpen, highlight: true },
        { id: 'chat', label: t('sidebar.chat', 'AI 資安助理 (AI Copilot)'), icon: MessageSquare },
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
                    <div className="flex items-center gap-3">
                      <Icon className={`w-4 h-4 transition-colors ${isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-cyan-400'}`} />
                      <span>{item.label}</span>
                    </div>
                    {item.badge && (
                      <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                        {item.badge}
                      </span>
                    )}
                    {item.highlight && !item.badge && (
                      <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                        {t('common.featureBadge', 'FEATURE')}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Footer info */}
      <div className="px-4 pt-4 border-t border-slate-900 text-[11px] text-slate-500 font-mono">
        <div className="flex justify-between items-center mb-1">
          <span>{t('sidebar.securityScore', 'Security Score')}</span>
          <span className="text-emerald-400 font-bold">94 / 100</span>
        </div>
        <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden">
          <div className="bg-gradient-to-r from-emerald-500 to-cyan-400 h-full w-[94%] rounded-full"></div>
        </div>
      </div>
    </aside>
  );
}
