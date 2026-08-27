import React, { useState, useEffect } from 'react';
import {
  Server,
  Activity,
  Shield,
  Play,
  Pause,
  RotateCcw,
  Square,
  AlertTriangle,
  Radio,
  CheckCircle,
  Clock,
  Layers,
  Search,
  Filter,
  Eye,
  RefreshCw,
  Zap,
} from 'lucide-react';
import {
  fetchCollectorStatus,
  fetchCollectorMetrics,
  fetchCollectorEvents,
  controlCollectorState,
} from '../services/apiClient';
import TelemetrySourceBadge from './TelemetrySourceBadge';
import LiveEmptyState from './LiveEmptyState';
import { useLanguage } from '../contexts/LanguageContext';

export default function CollectorManagementView() {
  const { t, language } = useLanguage();
  const isZh = language === 'zh-TW';

  const [collectors, setCollectors] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [events, setEvents] = useState([]);
  const [totalEventsCount, setTotalEventsCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(null);

  // Filters for Live Events Inspector
  const [filterCollector, setFilterCollector] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEvent, setSelectedEvent] = useState(null);

  const loadData = async () => {
    const [statusData, metricsData, eventsData] = await Promise.all([
      fetchCollectorStatus(),
      fetchCollectorMetrics(),
      fetchCollectorEvents({
        collector: filterCollector,
        severity: filterSeverity,
        q: searchQuery,
        limit: 50,
      }),
    ]);

    if (statusData?.collectors) setCollectors(statusData.collectors);
    if (metricsData) setMetrics(metricsData);
    if (eventsData?.events) {
      setEvents(eventsData.events);
      setTotalEventsCount(eventsData.total);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, [filterCollector, filterSeverity, searchQuery]);

  const handleAction = async (collectorName, action) => {
    setActionLoading(`${collectorName}-${action}`);
    await controlCollectorState(collectorName, action);
    await loadData();
    setActionLoading(null);
  };

  const getBadgeStyle = (state) => {
    switch (state) {
      case 'Running':
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
      case 'Degraded':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40 animate-pulse';
      case 'Paused':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
      case 'Failed':
        return 'bg-rose-500/20 text-rose-400 border-rose-500/40';
      case 'Initializing':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/40 animate-spin';
      case 'Stopped':
      default:
        return 'bg-slate-700/50 text-slate-400 border-slate-600/40';
    }
  };

  const getSeverityBadge = (severity) => {
    switch (severity) {
      case 'Critical':
        return 'bg-rose-500/20 text-rose-400 border-rose-500/40';
      case 'High':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
      case 'Medium':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'Low':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
      default:
        return 'bg-slate-700/40 text-slate-300 border-slate-600/30';
    }
  };

  return (
    <div className="p-6 space-y-6 text-slate-100 min-h-screen">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-slate-800/60 p-6 rounded-xl border border-slate-700/60 backdrop-blur-md">
        <div>
          <div className="flex items-center gap-3">
            <Radio className="w-7 h-7 text-cyan-400 animate-pulse" />
            <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              {t('sidebar.collectorMgmt', 'Telemetry Collector Management')}
            </h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            {isZh
              ? '企業級實時日誌擷取層：Syslog (RFC 3164/5424), Windows Event Collector (WEF/WinRM XML), 以及 NetFlow v5/v9/IPFIX。'
              : 'Enterprise Live Ingestion Layer: Syslog (RFC 3164/5424), Windows Event Collector (WEF/WinRM XML), and NetFlow v5/v9/IPFIX'}
          </p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-400 rounded-lg border border-cyan-500/30 transition-all font-medium text-sm"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          {isZh ? '重新整理狀態' : 'Refresh Status'}
        </button>
      </div>

      {/* Aggregate Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-800/40 p-5 rounded-xl border border-slate-700/50 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              {isZh ? '總日誌擷取速率' : 'Total Ingestion Rate'}
            </span>
            <div className="text-2xl font-black text-cyan-400 mt-1">
              {metrics?.aggregateEventsPerSec || 0} <span className="text-xs text-slate-400 font-normal">events/sec</span>
            </div>
          </div>
          <Zap className="w-8 h-8 text-cyan-400/60" />
        </div>

        <div className="bg-slate-800/40 p-5 rounded-xl border border-slate-700/50 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              {isZh ? '已處理事件總數' : 'Total Events Processed'}
            </span>
            <div className="text-2xl font-black text-blue-400 mt-1">
              {(metrics?.totalEventsProcessed || 0).toLocaleString()}
            </div>
          </div>
          <Activity className="w-8 h-8 text-blue-400/60" />
        </div>

        <div className="bg-slate-800/40 p-5 rounded-xl border border-slate-700/50 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              {isZh ? '丟棄封包數' : 'Dropped Packets'}
            </span>
            <div className="text-2xl font-black text-amber-400 mt-1">
              {(metrics?.totalDroppedPackets || 0).toLocaleString()}
            </div>
          </div>
          <AlertTriangle className="w-8 h-8 text-amber-400/60" />
        </div>

        <div className="bg-slate-800/40 p-5 rounded-xl border border-slate-700/50 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              {isZh ? '活動中收集器' : 'Active Collectors'}
            </span>
            <div className="text-2xl font-black text-emerald-400 mt-1">
              {collectors.filter((c) => c.liveness).length} / {collectors.length}
            </div>
          </div>
          <CheckCircle className="w-8 h-8 text-emerald-400/60" />
        </div>
      </div>

      {/* Collector Status & Controls Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {collectors.map((c) => {
          const colMetrics = metrics?.collectors?.find((m) => m.name === c.name);
          return (
            <div
              key={c.name}
              className="bg-slate-800/50 p-6 rounded-xl border border-slate-700/60 flex flex-col justify-between space-y-4 hover:border-slate-600 transition-all"
            >
              <div>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Server className="w-5 h-5 text-cyan-400" />
                    <h3 className="font-bold text-lg text-slate-100">{c.name}</h3>
                  </div>
                  <span
                    className={`px-2.5 py-1 rounded-full text-xs font-semibold border ${getBadgeStyle(
                      c.state
                    )}`}
                  >
                    {c.state}
                  </span>
                </div>

                <p className="text-xs text-slate-400 mb-4">{c.healthMessage}</p>

                <div className="space-y-2 text-xs text-slate-300 bg-slate-900/60 p-3.5 rounded-lg border border-slate-800">
                  <div className="flex justify-between">
                    <span className="text-slate-400">{isZh ? '監聽通訊埠：' : 'Listening Ports:'}</span>
                    <span className="font-mono text-cyan-400 font-medium">
                      {c.listeningPorts.length > 0 ? c.listeningPorts.join(', ') : 'None'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">{isZh ? '活動連線數：' : 'Active Connections:'}</span>
                    <span className="font-mono">{c.activeConnections}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">{isZh ? '事件通量：' : 'Events / Sec:'}</span>
                    <span className="font-mono font-bold text-emerald-400">
                      {colMetrics?.eventsPerSecond || 0} eps
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">{isZh ? '平均延遲：' : 'Avg Latency:'}</span>
                    <span className="font-mono">{colMetrics?.averageLatencyMs || 0} ms</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">{isZh ? '佇列水位：' : 'Queue Watermark:'}</span>
                    <span className="font-mono text-amber-400 font-semibold">
                      {colMetrics?.watermarkStatus || 'NORMAL'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2 pt-2 border-t border-slate-700/50">
                {c.state === 'Paused' ? (
                  <button
                    onClick={() => handleAction(c.name, 'resume')}
                    disabled={actionLoading === `${c.name}-resume`}
                    className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-semibold transition-all"
                  >
                    <Play className="w-3.5 h-3.5" /> {isZh ? '恢復運作' : 'Resume'}
                  </button>
                ) : (
                  <button
                    onClick={() => handleAction(c.name, 'pause')}
                    disabled={c.state !== 'Running' || actionLoading === `${c.name}-pause`}
                    className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 border border-amber-500/30 rounded-lg text-xs font-semibold transition-all disabled:opacity-40"
                  >
                    <Pause className="w-3.5 h-3.5" /> {isZh ? '暫停' : 'Pause'}
                  </button>
                )}

                <button
                  onClick={() => handleAction(c.name, 'restart')}
                  disabled={actionLoading === `${c.name}-restart`}
                  className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded-lg text-xs font-semibold transition-all"
                >
                  <RotateCcw className="w-3.5 h-3.5" /> {isZh ? '重啟' : 'Restart'}
                </button>

                {c.state === 'Stopped' ? (
                  <button
                    onClick={() => handleAction(c.name, 'start')}
                    disabled={actionLoading === `${c.name}-start`}
                    className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-semibold transition-all"
                  >
                    <Play className="w-3.5 h-3.5" /> {isZh ? '啟動' : 'Start'}
                  </button>
                ) : (
                  <button
                    onClick={() => handleAction(c.name, 'stop')}
                    disabled={actionLoading === `${c.name}-stop`}
                    className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 bg-rose-600/20 hover:bg-rose-600/30 text-rose-400 border border-rose-500/30 rounded-lg text-xs font-semibold transition-all"
                  >
                    <Square className="w-3.5 h-3.5" /> {isZh ? '停止' : 'Stop'}
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Live Normalized Event Stream Inspector */}
      <div className="bg-slate-800/50 p-6 rounded-xl border border-slate-700/60 space-y-4">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
          <div>
            <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <Layers className="w-5 h-5 text-cyan-400" /> {isZh ? '實時遙測資料串流檢閱器' : 'Live Telemetry Stream Inspector'}
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              {isZh ? `跨所有活動收集器正規化輸出之實時資安日誌 (${totalEventsCount} 筆事件)` : `Real-time normalized security events outputted across all active collectors (${totalEventsCount} events)`}
            </p>
          </div>

          {/* Controls */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="text"
                placeholder={isZh ? "搜尋主機、IP、事件類型..." : "Search host, IP, event type..."}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 pr-4 py-1.5 bg-slate-900/80 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 w-52 font-mono"
              />
            </div>

            <select
              value={filterCollector}
              onChange={(e) => setFilterCollector(e.target.value)}
              className="px-3 py-1.5 bg-slate-900/80 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="">{isZh ? '所有收集器' : 'All Collectors'}</option>
              <option value="syslog">Syslog</option>
              <option value="wef">Windows WEF</option>
              <option value="netflow">NetFlow</option>
            </select>

            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="px-3 py-1.5 bg-slate-900/80 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="">{isZh ? '所有風險等級' : 'All Severities'}</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
              <option value="Info">Info</option>
            </select>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto rounded-lg border border-slate-700/60 bg-slate-900/50">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="bg-slate-800/80 text-slate-400 font-semibold border-b border-slate-700/60 uppercase tracking-wider">
                <th className="p-3">{isZh ? '時間戳記' : 'Timestamp'}</th>
                <th className="p-3">{isZh ? '收集器' : 'Collector'}</th>
                <th className="p-3">{isZh ? '風險等級' : 'Severity'}</th>
                <th className="p-3">{isZh ? '廠商 / 產品' : 'Vendor / Product'}</th>
                <th className="p-3">{isZh ? '主機 / 來源 IP' : 'Host / Source IP'}</th>
                <th className="p-3">{isZh ? '事件類型' : 'Event Type'}</th>
                <th className="p-3">{isZh ? '分類' : 'Category'}</th>
                <th className="p-3 text-right">{isZh ? '檢視' : 'Inspect'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {events.length === 0 ? (
                <tr>
                  <td colSpan={8} className="p-6 text-center text-slate-500 italic">
                    {isZh ? '無符合查詢條件之事件。遙測串流運作中，正在等待新封包…' : 'No live events matching query. Telemetry stream is active and awaiting incoming packets.'}
                  </td>
                </tr>
              ) : (
                events.map((evt) => (
                  <tr key={evt.id} className="hover:bg-slate-800/40 transition-colors font-mono">
                    <td className="p-3 whitespace-nowrap text-slate-400">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="p-3">
                      <TelemetrySourceBadge provenance={evt.provenance} sourceText={evt.collector} />
                    </td>
                    <td className="p-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                          evt.severity
                        )}`}
                      >
                        {evt.severity}
                      </span>
                    </td>
                    <td className="p-3 font-sans">
                      <span className="font-medium text-slate-200">{evt.vendor}</span>{' '}
                      <span className="text-slate-500 text-[11px]">({evt.product})</span>
                    </td>
                    <td className="p-3">
                      <span className="text-slate-200 font-semibold">{evt.host}</span>
                      <div className="text-[10px] text-slate-500">{evt.ip}</div>
                    </td>
                    <td className="p-3 font-semibold text-cyan-300">{evt.event_type}</td>
                    <td className="p-3 text-slate-400 font-sans">{evt.category}</td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => setSelectedEvent(evt)}
                        className="px-2.5 py-1 bg-cyan-600/20 hover:bg-cyan-600/40 text-cyan-400 rounded border border-cyan-500/30 text-[11px] font-sans font-medium transition-all"
                      >
                        {isZh ? '檢視詳情' : 'Inspect'}
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Raw & Normalized Event Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-800 border border-slate-700 rounded-xl max-w-4xl w-full max-h-[85vh] overflow-hidden flex flex-col shadow-2xl">
            <div className="p-5 border-b border-slate-700 flex justify-between items-center bg-slate-800/80">
              <div className="flex items-center gap-3">
                <Shield className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-lg text-slate-100">
                  {isZh ? '事件詳情剖析' : 'Event Inspection'} [{selectedEvent.id}]
                </h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-slate-200 font-bold px-2 text-lg"
              >
                ✕
              </button>
            </div>

            <div className="p-6 overflow-y-auto space-y-4 text-xs font-mono">
              <div>
                <h4 className="text-slate-400 uppercase tracking-wider font-semibold mb-2 font-sans">
                  {isZh ? '原始注入事件載荷 (Raw Payload)' : 'Raw Ingested Event Payload (Sanitized)'}
                </h4>
                <pre className="bg-slate-900 p-4 rounded-lg border border-slate-800 text-slate-300 whitespace-pre-wrap break-all">
                  {selectedEvent.raw}
                </pre>
              </div>

              <div>
                <h4 className="text-slate-400 uppercase tracking-wider font-semibold mb-2 font-sans">
                  {isZh ? '正規化鍵值欄位 (Normalized Fields)' : 'Normalized Key-Value Fields'}
                </h4>
                <pre className="bg-slate-900 p-4 rounded-lg border border-slate-800 text-cyan-300 whitespace-pre-wrap">
                  {JSON.stringify(selectedEvent.normalized, null, 2)}
                </pre>
              </div>

              <div>
                <h4 className="text-slate-400 uppercase tracking-wider font-semibold mb-2 font-sans">
                  {isZh ? '元數據與標籤 (Metadata & Tags)' : 'Metadata & Tags'}
                </h4>
                <pre className="bg-slate-900 p-4 rounded-lg border border-slate-800 text-purple-300 whitespace-pre-wrap">
                  {JSON.stringify(selectedEvent.metadata, null, 2)}
                </pre>
              </div>
            </div>

            <div className="p-4 border-t border-slate-700 bg-slate-900/60 text-right">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-xs font-semibold font-sans transition-all"
              >
                {isZh ? '關閉' : 'Close'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
