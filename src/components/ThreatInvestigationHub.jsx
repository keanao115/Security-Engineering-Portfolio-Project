import React, { useState } from 'react';
import { Shield, Radar, AlertOctagon } from 'lucide-react';
import ZeekSuricataView from './ZeekSuricataView';
import InvestigationTimelineView from './InvestigationTimelineView';
import IncidentCasesView from './IncidentCasesView';
import { useLanguage } from '../contexts/LanguageContext';

export default function ThreatInvestigationHub() {
  const { t } = useLanguage();
  const [activeSubTab, setActiveSubTab] = useState('ids');

  const subTabs = [
    { id: 'ids', label: t('investigationHub.idsTab', 'Zeek & Suricata IDS 聯防監控'), icon: Shield, badge: 'EVE' },
    { id: 'timeline', label: t('investigationHub.timelineTab', '多源關聯證據時間軸 (Evidence Timeline)'), icon: Radar, badge: 'AI' },
    { id: 'incidents', label: t('investigationHub.incidentsTab', 'SOC 事件工單閉環 (Incident Cases)'), icon: AlertOctagon, badge: 'SOAR' },
  ];

  return (
    <div className="space-y-6">
      {/* Sub-navigation bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-cyan-400" />
            {t('investigationHub.title', 'IDS 聯防與事件威脅調查 (Threat Investigation Hub)')}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            即時彙整 Zeek 協定中繼日誌、Suricata EVE 告警、多維度事件時序關聯證據鏈與事件處置工單生命週期
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
                  <span className="text-[9px] font-bold px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300">
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab Contents */}
      {activeSubTab === 'ids' && <ZeekSuricataView />}
      {activeSubTab === 'timeline' && <InvestigationTimelineView />}
      {activeSubTab === 'incidents' && <IncidentCasesView />}
    </div>
  );
}
