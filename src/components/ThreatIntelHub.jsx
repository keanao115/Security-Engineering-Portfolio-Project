import React, { useState } from 'react';
import { Database, Grid, BookOpen, Info } from 'lucide-react';
import MitreMatrixView from './MitreMatrixView';
import IocDatabaseView from './IocDatabaseView';
import RagKnowledgeView from './RagKnowledgeView';
import { useLanguage } from '../contexts/LanguageContext';

export default function ThreatIntelHub({ nmapScan }) {
  const { t } = useLanguage();
  const [activeSubTab, setActiveSubTab] = useState('mitre');

  const subTabs = [
    { id: 'mitre', label: t('intelHub.mitreTab', 'MITRE ATT&CK 戰術矩陣'), icon: Grid },
    { id: 'ioc', label: t('intelHub.iocTab', 'IOC 威脅情報資料庫'), icon: Database },
    { id: 'rag', label: t('intelHub.ragTab', 'RAG 資安知識庫'), icon: BookOpen },
  ];

  return (
    <div className="space-y-6">
      {/* Sub-navigation bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
              <Database className="w-6 h-6 text-cyan-400" />
              {t('intelHub.title', '威脅情報與防禦框架知識庫 (Threat Intel & Knowledge)')}
            </h2>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
              STATIC REFERENCE
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            收錄企業級防禦框架標準參照：MITRE ATT&CK 矩陣映射、已知惡意 IOC 特徵庫與檢索增強 (RAG) 知識體系
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

      {/* Truthful Positioning Banner */}
      <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center gap-3 text-xs text-slate-300">
        <Info className="w-4 h-4 text-cyan-400 shrink-0" />
        <div>
          <span className="font-semibold text-cyan-300">[架構定位說明] </span>
          本專區為靜態參考知識庫，為分析師研判資安事件與比對攻擊戰術（TTPs）時提供標準化防禦依據，非動態遙測流。
        </div>
      </div>

      {/* Tab Contents */}
      {activeSubTab === 'mitre' && <MitreMatrixView nmapScan={nmapScan} />}
      {activeSubTab === 'ioc' && <IocDatabaseView />}
      {activeSubTab === 'rag' && <RagKnowledgeView />}
    </div>
  );
}
