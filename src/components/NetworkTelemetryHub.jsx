import React, { useState } from 'react';
import { Activity, Search, Zap, Server } from 'lucide-react';
import LivePacketCaptureView from './LivePacketCaptureView';
import PacketInspectorView from './PacketInspectorView';
import PipelinePerformanceView from './PipelinePerformanceView';
import CollectorManagementView from './CollectorManagementView';
import { useLanguage } from '../contexts/LanguageContext';

export default function NetworkTelemetryHub() {
  const { t } = useLanguage();
  const [activeSubTab, setActiveSubTab] = useState('capture');

  const subTabs = [
    { id: 'capture', label: t('telemetryHub.liveCapture', '即時封包捕獲 (Npcap Live)'), icon: Activity, badge: 'NPCAP' },
    { id: 'inspector', label: t('telemetryHub.inspector', 'PCAP 深度檢視 (Packet Inspector)'), icon: Search },
    { id: 'collectors', label: t('telemetryHub.collectors', '採集器生命週期 (Collectors)'), icon: Server, badge: 'PROD' },
    { id: 'performance', label: t('telemetryHub.performance', '管線效能與指標 (Pipeline Perf)'), icon: Zap, badge: 'METRICS' },
  ];

  return (
    <div className="space-y-6">
      {/* Sub-navigation bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Activity className="w-6 h-6 text-cyan-400" />
            {t('telemetryHub.title', '網路遙測與封包分析中心 (Network Telemetry & PCAP Hub)')}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            整合本機網卡即時抓包、二進位 PCAP 上傳解析與遙測採集器（Syslog / WEF / NetFlow）狀態
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
                {tab.badge && (
                  <span className="text-[9px] font-bold px-1 py-0.2 rounded bg-cyan-500/20 text-cyan-300">
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab Contents */}
      {activeSubTab === 'capture' && <LivePacketCaptureView />}
      {activeSubTab === 'inspector' && <PacketInspectorView />}
      {activeSubTab === 'collectors' && <CollectorManagementView />}
      {activeSubTab === 'performance' && <PipelinePerformanceView />}
    </div>
  );
}
