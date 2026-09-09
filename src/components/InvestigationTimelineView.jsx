import React, { useState, useEffect } from 'react';
import { Clock, ShieldAlert, Layers } from 'lucide-react';
import TelemetrySourceBadge from './TelemetrySourceBadge';
import { useLanguage } from '../contexts/LanguageContext';
import { authFetch } from '../services/apiClient';

export default function InvestigationTimelineView() {
  const { t, language } = useLanguage();
  const isZh = language === 'zh-TW';

  const [timeline, setTimeline] = useState([]);
  const [bundles, setBundles] = useState([]);

  const fetchData = async () => {
    try {
      const resT = await authFetch('/api/investigation/timeline');
      if (resT.ok) setTimeline((await resT.json()).timeline || []);

      const resB = await authFetch('/api/investigation/evidence-bundles');
      if (resB.ok) setBundles((await resB.json()).bundles || []);
    } catch (err) {
      console.warn('[InvestigationTimelineView] Fetch failed:', err);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-cyan-500/20 pb-4">
        <div>
          <h2 className="text-xl font-bold bg-gradient-to-r from-amber-400 to-rose-400 bg-clip-text text-transparent flex items-center gap-2">
            <Clock className="w-6 h-6 text-amber-400" /> {isZh ? '鑑識調查時序時間軸與證據聚合包' : 'Chronological Investigation Timeline & Evidence Bundles'}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {isZh
              ? '跨 Live Capture, NetFlow, Syslog, WEF, Zeek 與 Suricata 多源訊號之綜合事件時序關聯。'
              : 'Synthesized incident timelines correlating Live Capture, NetFlow, Syslog, WEF, Zeek, and Suricata signals'}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Bundles List */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
            <Layers className="w-4 h-4 text-amber-400" /> {isZh ? '多源關聯證據包' : 'Correlated Evidence Bundles'}
          </h3>

          {bundles.length === 0 ? (
            <p className="text-xs text-slate-500 italic">{isZh ? '目前尚未偵測到多源資安事件聚合包。' : 'No multi-source incident bundles detected yet.'}</p>
          ) : (
            bundles.map((b) => (
              <div key={b.bundleId} className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 space-y-2">
                <div className="flex justify-between items-center text-xs font-bold text-amber-400 font-mono">
                  <span>{b.bundleId}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/40 uppercase">
                    {b.severity}
                  </span>
                </div>
                <p className="text-xs text-slate-300 font-semibold">{b.title}</p>
                <div className="flex flex-wrap gap-1 pt-1">
                  {b.telemetrySources.map((s) => (
                    <TelemetrySourceBadge key={s} sourceText={s} />
                  ))}
                </div>
              </div>
            ))
          )}
        </div>

        {/* Timeline View */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4 md:col-span-2">
          <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" /> {isZh ? `實時事件時間序列 (${timeline.length} 筆事件)` : `Live Event Chronology (${timeline.length} events)`}
          </h3>

          {timeline.length === 0 ? (
            <p className="text-xs text-slate-500 italic text-center py-8">
              {isZh ? '目前尚無時間軸事件紀錄。請注入遙測日誌或啟動封包擷取以觀察實時事件。' : 'No timeline events recorded yet. Ingest telemetry or start packet capture to observe events.'}
            </p>
          ) : (
            <div className="space-y-3 max-h-[500px] overflow-y-auto pr-2">
              {timeline.map((item) => (
                <div key={item.id} className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex items-center justify-between text-xs font-mono">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-400 text-[11px]">{new Date(item.timestamp).toLocaleTimeString()}</span>
                      <TelemetrySourceBadge provenance={item.provenance} sourceText={item.source} />
                      <span className="text-slate-200 font-bold">{item.eventType}</span>
                    </div>
                    <p className="text-slate-300 text-[11px] font-sans">{item.summary}</p>
                  </div>
                  <span className="text-slate-400 text-[10px]">{item.host}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
