import React, { useState, useEffect, useRef } from 'react';
import { Shield, AlertTriangle, CheckCircle, Filter, RefreshCw, Zap, Clock, Activity, Search, PlusCircle, Layers, ArrowUpRight, Check, ChevronLeft, ChevronRight } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { fetchSiemEvents, fetchMultiVectorCorrelation, connectLiveTelemetryStream, authFetch, escalateEventToIncident } from '../services/apiClient';
import { useLanguage } from '../contexts/LanguageContext';

const SEV_COLORS = { Critical: '#ef4444', High: '#f59e0b', Medium: '#06b6d4', Low: '#10b981', Info: '#64748b' };
const SEV_BG = { Critical: 'bg-red-500/10 text-red-400 border-red-500/30', High: 'bg-amber-500/10 text-amber-400 border-amber-500/30', Medium: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30', Low: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30', Info: 'bg-slate-800 text-slate-400 border-slate-700' };

const SOURCE_BADGE = {
  Windows_WEF: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  Sysmon: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
  Linux_Auditd: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  Zeek: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  Wazuh: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
  Suricata: 'bg-red-500/10 text-red-400 border-red-500/20',
  CloudTrail: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  CrowdStrike: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
  Defender: 'bg-blue-600/10 text-blue-300 border-blue-600/20',
  VPN_Gateway: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
};

const FALLBACK_EVENTS = [
  { id: 'SIEM-001', timestamp: new Date(Date.now() - 10000).toISOString(), sourceCategory: 'Windows_WEF', hostName: 'DC-SRV-01.corp.internal', severity: 'High', eventId: '4625', mitreTechnique: 'T1110.001 (Password Guessing)', summary: 'Multiple failed logon attempts for Administrator from 192.168.1.155.', dedupCount: 14 },
  { id: 'SIEM-002', timestamp: new Date(Date.now() - 6000).toISOString(), sourceCategory: 'Linux_Auditd', hostName: 'web-prod-01.corp.internal', severity: 'Critical', eventId: 'SUDO_EXEC', mitreTechnique: 'T1548.003 (Sudo Caching)', summary: 'Sudo exec by deploy piping curl script from external C2 host.', dedupCount: 1 },
  { id: 'SIEM-003', timestamp: new Date(Date.now() - 3000).toISOString(), sourceCategory: 'CloudTrail', hostName: 'aws-us-east-1', severity: 'Medium', eventId: 'IAM_POLICY_CHANGE', mitreTechnique: 'T1098 (Account Manipulation)', summary: 'AttachRolePolicy API called for AdminRole from unmapped IP 185.220.101.5.', dedupCount: 2 },
  { id: 'SIEM-004', timestamp: new Date(Date.now() - 2000).toISOString(), sourceCategory: 'Sysmon', hostName: 'workstation-win11-04', severity: 'High', eventId: 'Sysmon-1', mitreTechnique: 'T1059.001 (PowerShell)', summary: 'Encoded PowerShell command execution with -EncodedCommand parameter.', dedupCount: 1 },
];

export default function SiemEventConsole() {
  const { t, language } = useLanguage();
  const isZh = language === 'zh-TW';

  const [events, setEvents] = useState(FALLBACK_EVENTS);
  const [correlation, setCorrelation] = useState(null);
  const [sevFilter, setSevFilter] = useState('ALL');
  const [catFilter, setCatFilter] = useState('ALL');
  const [hostSearch, setHostSearch] = useState('');
  const [showIngestModal, setShowIngestModal] = useState(false);
  const [rawLogInput, setRawLogInput] = useState('');
  const [ingestStatus, setIngestStatus] = useState('');
  const [wsStatus, setWsStatus] = useState(isZh ? '連線中…' : 'Connecting…');
  const [lastUpdate, setLastUpdate] = useState(new Date());
  const [escalatingId, setEscalatingId] = useState(null);
  const [escalatedMap, setEscalatedMap] = useState({});
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const wsRef = useRef(null);

  const severityBarData = [
    { name: isZh ? '極高' : 'Critical', count: events.filter(e => e.severity === 'Critical').length },
    { name: isZh ? '高' : 'High', count: events.filter(e => e.severity === 'High').length },
    { name: isZh ? '中' : 'Medium', count: events.filter(e => e.severity === 'Medium').length },
    { name: isZh ? '低' : 'Low', count: events.filter(e => e.severity === 'Low').length },
    { name: isZh ? '資訊' : 'Info', count: events.filter(e => e.severity === 'Info').length },
  ];

  useEffect(() => {
    fetchSiemEvents().then(data => { if (data?.events?.length > 0) setEvents(data.events); });
    fetchMultiVectorCorrelation().then(c => { if (c) setCorrelation(c); });

    wsRef.current = connectLiveTelemetryStream(
      (msg) => {
        if (msg.type === 'SIEM_EVENT') {
          setEvents(prev => [msg.event, ...prev].slice(0, 100));
          setLastUpdate(new Date());
        }
        if (msg.type === 'HEARTBEAT') { setWsStatus(isZh ? '實時串流中' : 'Live'); setLastUpdate(new Date()); }
      },
      () => setWsStatus(isZh ? '實時串流中' : 'Live'),
      () => setWsStatus(isZh ? '演練模式' : 'Demo Mode')
    );

    return () => { if (wsRef.current) wsRef.current.close(); };
  }, [isZh]);

  const handleBulkIngest = async () => {
    if (!rawLogInput.trim()) return;
    setIngestStatus(isZh ? '正在注入與正規化日誌…' : 'Ingesting and normalizing…');

    try {
      const lines = rawLogInput.split('\n').filter(l => l.trim());
      const payloadEvents = lines.map((line, idx) => ({
        sourceCategory: line.includes('Auditd') ? 'Linux_Auditd' : line.includes('Sysmon') ? 'Sysmon' : 'Windows_WEF',
        hostName: line.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/) ? line.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/)[0] : 'host-ingested-log',
        severity: line.toLowerCase().includes('failed') || line.toLowerCase().includes('sudo') ? 'High' : 'Medium',
        eventId: `INGEST-${idx + 1}`,
        summary: line
      }));

      const res = await authFetch('/api/siem/ingest/bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ events: payloadEvents })
      });

      if (res.ok) {
        setIngestStatus(isZh ? `成功注入 ${lines.length} 條日誌事件！` : `Ingested ${lines.length} events!`);
        fetchSiemEvents().then(d => { if (d?.events) setEvents(d.events); });
        setTimeout(() => { setShowIngestModal(false); setIngestStatus(''); setRawLogInput(''); }, 1500);
      } else {
        setIngestStatus(isZh ? '注入失敗' : 'Ingest failed');
      }
    } catch (e) {
      setIngestStatus(isZh ? '連線後端錯誤' : 'Error connecting to backend');
    }
  };

  const handleEscalate = async (event) => {
    const key = event.id || event.eventId || event.summary;
    setEscalatingId(key);
    try {
      const res = await escalateEventToIncident(event);
      if (res && res.incident) {
        setEscalatedMap(prev => ({ ...prev, [key]: res.incident.id }));
      }
    } catch (err) {
      alert(isZh ? `升級失敗: ${err.message}` : `Escalation failed: ${err.message}`);
    } finally {
      setEscalatingId(null);
    }
  };

  const allFiltered = events.filter(e =>
    (sevFilter === 'ALL' || e.severity === sevFilter) &&
    (catFilter === 'ALL' || e.sourceCategory === catFilter) &&
    (!hostSearch || e.hostName.toLowerCase().includes(hostSearch.toLowerCase()) || e.summary.toLowerCase().includes(hostSearch.toLowerCase()))
  );

  const totalPages = Math.max(1, Math.ceil(allFiltered.length / pageSize));
  const safeCurrentPage = Math.min(currentPage, totalPages);
  const paginatedEvents = allFiltered.slice((safeCurrentPage - 1) * pageSize, safeCurrentPage * pageSize);

  const criticalCount = events.filter(e => e.severity === 'Critical').length;
  const highCount = events.filter(e => e.severity === 'High').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-cyan-400" />
            {t('sidebar.siemEvents', 'SIEM Event Console')}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {isZh
              ? '集中式企業日誌聚合中心 — 整合 WEF, Sysmon, Auditd, Zeek, Wazuh, CloudTrail, Suricata, Defender。'
              : 'Centralized enterprise log aggregation — WEF, Sysmon, Auditd, Zeek, Wazuh, CloudTrail, Suricata, Defender.'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowIngestModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-mono text-xs font-bold transition-all shadow-md"
          >
            <PlusCircle className="w-4 h-4" /> {isZh ? '注入原始日誌' : 'Ingest Raw Logs'}
          </button>
          <span className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold border ${wsStatus.includes('Live') || wsStatus.includes('實時') ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-amber-500/10 text-amber-400 border-amber-500/30'}`}>
            <span className={`w-2 h-2 rounded-full ${wsStatus.includes('Live') || wsStatus.includes('實時') ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
            {wsStatus}
          </span>
        </div>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: isZh ? '日誌事件總數' : 'Total Events', value: events.length, color: 'cyan', icon: <Activity className="w-4 h-4" /> },
          { label: isZh ? '極高風險 (Critical)' : 'Critical', value: criticalCount, color: 'red', icon: <AlertTriangle className="w-4 h-4" /> },
          { label: isZh ? '高風險 (High)' : 'High', value: highCount, color: 'amber', icon: <Zap className="w-4 h-4" /> },
          { label: isZh ? '綜合威脅評分' : 'Composite Risk', value: correlation?.compositeRiskScore ?? '—', color: 'purple', icon: <Shield className="w-4 h-4" />, suffix: '/100' },
        ].map((kpi, i) => (
          <div key={i} className={`glass-panel p-4 rounded-2xl border ${kpi.color === 'red' && kpi.value > 0 ? 'border-red-500/30' : 'border-slate-800'} flex items-center gap-3`}>
            <div className={`p-2.5 rounded-xl bg-${kpi.color}-500/10 text-${kpi.color}-400`}>{kpi.icon}</div>
            <div>
              <div className="text-xs text-slate-400">{kpi.label}</div>
              <div className={`text-lg font-black font-mono ${kpi.color === 'red' && kpi.value > 0 ? 'text-red-400' : 'text-white'}`}>
                {kpi.value}{kpi.suffix}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Dynamic Attack Timeline Card */}
      {correlation?.timeline?.length > 0 && (
        <div className="glass-panel p-5 rounded-2xl space-y-3">
          <h3 className="font-bold text-sm text-cyan-300 flex items-center gap-2">
            <Layers className="w-4 h-4" /> {isZh ? '動態多階段攻擊事件時間軸' : 'Dynamic Multi-Stage Incident Timeline'}
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {correlation.timeline.map((step, idx) => (
              <div key={idx} className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1 text-xs font-mono">
                <div className="flex items-center justify-between text-[10px]">
                  <span className="px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">{step.stage}</span>
                  <span className="text-slate-500">{step.time}</span>
                </div>
                <div className="font-bold text-white text-xs line-clamp-2">{step.headline}</div>
                <div className="text-[10px] text-slate-400 flex items-center justify-between pt-1">
                  <span>MITRE: {step.mitreId}</span>
                  <span className="text-cyan-400 font-bold">{step.confidenceScore}% {isZh ? '信賴度' : 'Conf'}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Charts + Correlation Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution Chart */}
        <div className="glass-panel p-5 rounded-2xl">
          <h3 className="font-bold text-sm text-slate-200 mb-4 flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" /> {isZh ? '告警風險等級分佈' : 'Alert Severity Distribution'}
          </h3>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={severityBarData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
              <XAxis dataKey="name" stroke="#64748b" fontSize={10} />
              <YAxis stroke="#64748b" fontSize={10} />
              <Tooltip contentStyle={{ backgroundColor: '#090d16', borderRadius: '8px' }} />
              <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* AI Multi-Vector Correlation */}
        <div className="lg:col-span-2 glass-panel p-5 rounded-2xl space-y-3">
          <h3 className="font-bold text-sm text-slate-200 flex items-center gap-2">
            <Shield className="w-4 h-4 text-purple-400" /> {isZh ? 'AI 多維向量關聯引擎' : 'AI Multi-Vector Correlation Engine'}
          </h3>
          {correlation ? (
            <>
              <div className="flex items-center gap-3">
                <div className="flex-1 bg-slate-950 rounded-full h-2">
                  <div className="h-2 rounded-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all" style={{ width: `${correlation.compositeRiskScore}%` }} />
                </div>
                <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded ${correlation.overallThreatLevel === 'CRITICAL_ALERT' ? 'text-red-400 bg-red-500/10 border border-red-500/30' : correlation.overallThreatLevel === 'ELEVATED_THREAT' ? 'text-amber-400 bg-amber-500/10 border border-amber-500/30' : 'text-emerald-400 bg-emerald-500/10 border border-emerald-500/30'}`}>
                  {correlation.overallThreatLevel}
                </span>
              </div>
              <div className="grid grid-cols-4 gap-2 text-center text-[10px] font-mono">
                {[
                  { label: isZh ? '端點主機' : 'Endpoint', val: correlation.correlatedVectors?.endpointCount },
                  { label: isZh ? '網路流量' : 'Network Flows', val: correlation.correlatedVectors?.networkFlowCount },
                  { label: isZh ? '弱點數量' : 'Vulns', val: correlation.correlatedVectors?.vulnerabilityCount },
                  { label: isZh ? 'SIEM 事件' : 'SIEM Events', val: correlation.correlatedVectors?.siemEventCount },
                ].map((v, i) => (
                  <div key={i} className="bg-slate-950 rounded-lg p-2 border border-slate-900">
                    <div className="font-bold text-cyan-400 text-sm">{v.val}</div>
                    <div className="text-slate-500">{v.label}</div>
                  </div>
                ))}
              </div>
              <div className="space-y-1.5 pt-1">
                <div className="text-[11px] text-slate-400 font-semibold uppercase tracking-wider">
                  {isZh ? 'SOC 分析師處置建議' : 'SOC Analyst Playbook'}
                </div>
                {(correlation.socAnalystPlaybook || []).map((step, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs text-slate-300 font-mono">
                    <CheckCircle className="w-3.5 h-3.5 text-cyan-500 shrink-0 mt-0.5" />
                    {step}
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="text-xs text-slate-500 font-mono">
              {isZh ? '正在載入 AI 關聯分析引擎…' : 'Loading AI correlation engine…'}
            </div>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="glass-panel p-4 rounded-2xl flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center gap-2 flex-wrap">
          <input
            type="text"
            value={hostSearch}
            onChange={e => { setHostSearch(e.target.value); setCurrentPage(1); }}
            placeholder={isZh ? "搜尋主機名稱或日誌摘要..." : "Search host or summary..."}
            className="bg-slate-950 border border-slate-800 text-slate-300 text-xs font-mono rounded-lg px-3 py-1 focus:outline-none focus:border-cyan-500 w-48"
          />
          <span className="text-xs font-mono text-slate-400 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" /> {isZh ? '風險等級:' : 'Severity:'}
          </span>
          {['ALL', 'Critical', 'High', 'Medium', 'Low'].map(s => (
            <button key={s} onClick={() => { setSevFilter(s); setCurrentPage(1); }}
              className={`px-2.5 py-1 rounded-lg text-xs font-mono font-semibold transition-all ${sevFilter === s ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white'}`}>
              {s === 'ALL' ? t('common.all', 'ALL') : s}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-mono text-slate-400">{isZh ? '日誌來源:' : 'Source:'}</span>
          {['ALL', 'Windows_WEF', 'Sysmon', 'Linux_Auditd', 'Zeek', 'Wazuh', 'Suricata'].map(c => (
            <button key={c} onClick={() => { setCatFilter(c); setCurrentPage(1); }}
              className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold transition-all ${catFilter === c ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white'}`}>
              {c === 'ALL' ? t('common.all', 'ALL') : c.replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>

      {/* SIEM Event Stream */}
      <div className="space-y-3">
        {allFiltered.length === 0 ? (
          <div className="glass-panel p-8 text-center rounded-2xl border border-slate-800">
            <CheckCircle className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
            <p className="text-sm font-bold text-white">
              {isZh ? '無符合目前篩選條件之日誌事件' : 'No Events Match Active Filters'}
            </p>
            <p className="text-xs text-slate-400 font-mono mt-1">
              {isZh ? '所有遙測資料來源均處於正常運維基線內。' : 'All telemetry sources are within operational baseline.'}
            </p>
          </div>
        ) : paginatedEvents.map((event, i) => (
          <div key={i} className={`glass-panel p-4 rounded-2xl border transition-all hover:border-cyan-500/20 ${event.severity === 'Critical' ? 'border-red-500/30' : event.severity === 'High' ? 'border-amber-500/30' : 'border-slate-800'}`}>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${SEV_BG[event.severity]}`}>{event.severity}</span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${SOURCE_BADGE[event.sourceCategory] || 'bg-slate-800 text-slate-400'}`}>{event.sourceCategory?.replace('_', ' ')}</span>
                <span className="text-xs font-mono text-cyan-400 font-bold">{event.hostName}</span>
                <span className="text-[10px] font-mono text-slate-600">EventID: {event.eventId}</span>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                {event.dedupCount > 1 && (
                  <span className="px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/30 text-purple-400 text-[10px] font-mono font-bold">
                    ×{event.dedupCount} {isZh ? '筆重複聚合' : 'deduplicated'}
                  </span>
                )}
                <span className="text-[10px] font-mono text-slate-500 flex items-center gap-1">
                  <Clock className="w-3 h-3" /> {new Date(event.timestamp).toLocaleTimeString()}
                </span>
              </div>
            </div>
            <p className="text-xs text-slate-300 font-mono mt-2 leading-relaxed">{event.summary}</p>
            <div className="flex items-center justify-between mt-2 pt-2 border-t border-slate-800/60">
              <div className="text-[10px] text-slate-500 font-mono flex items-center gap-1">
                <Shield className="w-3 h-3 text-slate-600" /> MITRE: {event.mitreTechnique}
              </div>
              <div>
                {escalatedMap[event.id || event.eventId || event.summary] ? (
                  <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                    <Check className="w-3 h-3" /> {isZh ? `已成案 ${escalatedMap[event.id || event.eventId || event.summary]}` : `Escalated (${escalatedMap[event.id || event.eventId || event.summary]})`}
                  </span>
                ) : (
                  <button
                    onClick={() => handleEscalate(event)}
                    disabled={escalatingId === (event.id || event.eventId || event.summary)}
                    className={`inline-flex items-center gap-1 text-[10px] font-mono font-bold px-2 py-0.5 rounded border transition-all ${
                      event.severity === 'Critical' || event.severity === 'High'
                        ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 hover:bg-amber-500/30'
                        : 'bg-slate-850 text-slate-400 border-slate-800 hover:text-white hover:border-slate-700'
                    } disabled:opacity-50`}
                    title={isZh ? '將此警報提升至資安事件工單進行閉環追蹤' : 'Escalate this alert to an incident ticket'}
                  >
                    <ArrowUpRight className="w-3 h-3" />
                    {escalatingId === (event.id || event.eventId || event.summary)
                      ? (isZh ? '成案中…' : 'Escalating…')
                      : (isZh ? '提升為工單' : 'Escalate to Incident')}
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}

        {/* Pagination Controls */}
        {allFiltered.length > 0 && (
          <div className="glass-panel p-3 rounded-xl border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-xs text-slate-400">
            <div className="flex items-center gap-2">
              <span>
                {isZh
                  ? `顯示第 ${(safeCurrentPage - 1) * pageSize + 1} - ${Math.min(safeCurrentPage * pageSize, allFiltered.length)} 筆 (共 ${allFiltered.length} 筆)`
                  : `Showing ${(safeCurrentPage - 1) * pageSize + 1} - ${Math.min(safeCurrentPage * pageSize, allFiltered.length)} of ${allFiltered.length}`}
              </span>
              <span className="text-slate-600">|</span>
              <div className="flex items-center gap-1.5">
                <span>{isZh ? '每頁:' : 'Per page:'}</span>
                <select
                  value={pageSize}
                  onChange={e => { setPageSize(Number(e.target.value)); setCurrentPage(1); }}
                  aria-label={isZh ? '每頁顯示筆數' : 'Items per page'}
                  className="bg-slate-950 border border-slate-800 rounded px-2 py-0.5 text-cyan-400 focus:outline-none focus:border-cyan-500"
                >
                  <option value={10}>10</option>
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                </select>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                disabled={safeCurrentPage <= 1}
                aria-label={isZh ? '上一頁' : 'Previous page'}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white disabled:opacity-30 disabled:hover:text-slate-300 transition-all"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="text-slate-300 font-bold px-1">
                {safeCurrentPage} / {totalPages}
              </span>
              <button
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                disabled={safeCurrentPage >= totalPages}
                aria-label={isZh ? '下一頁' : 'Next page'}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white disabled:opacity-30 disabled:hover:text-slate-300 transition-all"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Raw Log Ingest Modal */}
      {showIngestModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="glass-panel p-6 rounded-2xl max-w-xl w-full border border-cyan-500/30 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <PlusCircle className="w-5 h-5 text-cyan-400" /> {isZh ? '注入原始日誌資料行' : 'Ingest Raw Log Lines'}
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              {isZh
                ? '請在下方貼上原始 Syslog / WEF 日誌行。後端正規化管線將自動擷取 IP、風險等級與對齊 MITRE ATT&CK 戰術手法。'
                : 'Paste raw syslog / WEF lines below. The backend normalization pipeline will extract IPs, severity, and MITRE ATT&CK techniques automatically.'}
            </p>
            <textarea
              rows={6}
              value={rawLogInput}
              onChange={e => setRawLogInput(e.target.value)}
              placeholder={isZh ? "在此貼上原始日誌行..." : "Paste raw log lines here..."}
              className="w-full bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 p-3 rounded-xl focus:outline-none focus:border-cyan-500"
            />
            {ingestStatus && <div className="text-xs font-mono text-cyan-400">{ingestStatus}</div>}
            <div className="flex justify-end gap-2">
              <button onClick={() => setShowIngestModal(false)} className="px-4 py-2 rounded-xl bg-slate-900 text-xs font-mono text-slate-400">{isZh ? '取消' : 'Cancel'}</button>
              <button onClick={handleBulkIngest} className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-xs font-mono font-bold text-slate-950">{isZh ? '注入並執行關聯分析' : 'Ingest & Correlate'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
