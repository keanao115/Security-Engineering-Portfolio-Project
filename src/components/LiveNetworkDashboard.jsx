import React, { useState, useEffect, useRef } from 'react';
import { Activity, Wifi, AlertTriangle, Shield, Zap, Globe, TrendingUp, RefreshCw, X, ArrowUpRight, ArrowDownLeft, ArrowRightLeft } from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, BarChart, Bar
} from 'recharts';
import { fetchLiveNetworkFlows, connectLiveTelemetryStream } from '../services/apiClient';
import { useLanguage } from '../contexts/LanguageContext';

const PROTOCOL_COLORS = { TCP: '#06b6d4', UDP: '#8b5cf6', ICMP: '#f59e0b', OTHER: '#64748b' };

const SAMPLE_FLOWS = [
  { id: 'FLOW-101', timestamp: new Date(Date.now() - 5000).toISOString(), sourceType: 'NetFlow_v9', srcIp: '192.168.1.105', srcPort: 54320, destIp: '192.168.1.10', destPort: 445, protocol: 'TCP', bytes: 14200, packets: 28, flags: 'SYN-ACK', direction: 'LATERAL', geoCountry: 'INTERNAL', anomalyFlag: false },
  { id: 'FLOW-102', timestamp: new Date(Date.now() - 2000).toISOString(), sourceType: 'SPAN_Mirror', srcIp: '192.168.1.50', srcPort: 443, destIp: '192.168.1.120', destPort: 58912, protocol: 'TCP', bytes: 1048576, packets: 820, flags: 'ACK-PUSH', direction: 'INBOUND', geoCountry: 'INTERNAL', anomalyFlag: false },
  { id: 'FLOW-103', timestamp: new Date().toISOString(), sourceType: 'IPFIX', srcIp: '185.220.101.5', srcPort: 4444, destIp: '192.168.1.105', destPort: 49152, protocol: 'TCP', bytes: 512, packets: 4, flags: 'SYN', direction: 'INBOUND', geoCountry: 'RU', anomalyFlag: true, anomalyReason: 'High-risk external C2 IP connection on non-standard port 4444', riskScore: 90 },
  { id: 'FLOW-104', timestamp: new Date().toISOString(), sourceType: 'sFlow', srcIp: '192.168.1.10', srcPort: 53, destIp: '8.8.8.8', destPort: 53, protocol: 'UDP', bytes: 128, packets: 2, flags: '', direction: 'OUTBOUND', geoCountry: 'US', anomalyFlag: false },
];

const SAMPLE_BANDWIDTH_HISTORY = [
  { time: '00:00', InboundMbps: 12, OutboundMbps: 8 },
  { time: '04:00', InboundMbps: 5, OutboundMbps: 3 },
  { time: '08:00', InboundMbps: 45, OutboundMbps: 28 },
  { time: '12:00', InboundMbps: 88, OutboundMbps: 62 },
  { time: '16:00', InboundMbps: 102, OutboundMbps: 75 },
  { time: '20:00', InboundMbps: 67, OutboundMbps: 44 },
  { time: 'Now', InboundMbps: 84, OutboundMbps: 58 },
];

const TOP_TALKERS_DATA = [
  { ip: '192.168.1.50', bytes: 1048576, display: '1.0 MB' },
  { ip: '192.168.1.105', bytes: 524288, display: '512 KB' },
  { ip: '192.168.1.10', bytes: 262144, display: '256 KB' },
  { ip: '185.220.101.5', bytes: 65536, display: '64 KB' },
  { ip: '8.8.8.8', bytes: 16384, display: '16 KB' },
];

const PROTOCOL_DIST = [
  { name: 'TLS/HTTPS', value: 59, color: '#06b6d4' },
  { name: 'DNS/UDP', value: 22, color: '#8b5cf6' },
  { name: 'HTTP', value: 13, color: '#f59e0b' },
  { name: 'Other', value: 6, color: '#64748b' },
];

export default function LiveNetworkDashboard() {
  const { t, language } = useLanguage();
  const isZh = language === 'zh-TW';

  const [flows, setFlows] = useState(SAMPLE_FLOWS);
  const [metrics, setMetrics] = useState({ activeFlowCount: 4, totalMbps: '84.2', packetsPerSec: 920, anomalyCount: 1 });
  const [wsStatus, setWsStatus] = useState(isZh ? '連線中...' : 'Connecting...');
  const [lastUpdate, setLastUpdate] = useState(new Date().toISOString());
  const [filter, setFilter] = useState('ALL');
  const [directionFilter, setDirectionFilter] = useState('ALL');
  const [selectedAnomaly, setSelectedAnomaly] = useState(null);
  const wsRef = useRef(null);

  useEffect(() => {
    fetchLiveNetworkFlows().then(data => {
      if (data?.flows) { setFlows(data.flows); setMetrics(data.metrics); }
    });

    wsRef.current = connectLiveTelemetryStream(
      (msg) => {
        if (msg.type === 'NETFLOW_RECORD') {
          setFlows(prev => [msg.record, ...prev].slice(0, 50));
          setLastUpdate(new Date().toISOString());
        }
        if (msg.type === 'HEARTBEAT') setLastUpdate(msg.timestamp);
      },
      () => setWsStatus(isZh ? '實時串流' : 'Live'),
      () => setWsStatus(isZh ? '離線 (展示模式)' : 'Offline (Demo Mode)')
    );

    const ticker = setInterval(() => {
      setLastUpdate(new Date().toISOString());
    }, 5000);

    return () => {
      if (wsRef.current) wsRef.current.close();
      clearInterval(ticker);
    };
  }, [isZh]);

  const displayFlows = flows.filter(f => {
    const protoMatch = filter === 'ALL' || (filter === 'ANOMALY' ? f.anomalyFlag : f.protocol === filter);
    const dirMatch = directionFilter === 'ALL' || f.direction === directionFilter;
    return protoMatch && dirMatch;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Activity className="w-6 h-6 text-cyan-400" />
            {t('sidebar.liveNetwork', 'Live Network Flow Monitor')}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {isZh
              ? '即時 NetFlow v9 / IPFIX / sFlow / SPAN 流量遙測擷取與頻寬深度分析。'
              : 'Real-time NetFlow v9 / IPFIX / sFlow / SPAN telemetry ingestion and bandwidth analysis.'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold border ${wsStatus.includes('Live') || wsStatus.includes('實時') ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-amber-500/10 text-amber-400 border-amber-500/30'}`}>
            <span className={`w-2 h-2 rounded-full ${wsStatus.includes('Live') || wsStatus.includes('實時') ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
            WebSocket: {wsStatus}
          </span>
          <span className="text-[10px] font-mono text-slate-500">{isZh ? '更新時間：' : 'Updated:'} {new Date(lastUpdate).toLocaleTimeString()}</span>
        </div>
      </div>

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: isZh ? '活動流量數' : 'Active Flows', value: metrics.activeFlowCount, icon: <Wifi className="w-4 h-4" />, color: 'cyan', unit: '' },
          { label: isZh ? '即時頻寬吞吐' : 'Live Bandwidth', value: `${metrics.totalMbps}`, icon: <TrendingUp className="w-4 h-4" />, color: 'blue', unit: 'Mbps' },
          { label: isZh ? '每秒封包數' : 'Packets / sec', value: metrics.packetsPerSec?.toLocaleString(), icon: <Zap className="w-4 h-4" />, color: 'purple', unit: 'pkt/s' },
          { label: isZh ? '異常流量告警' : 'Anomalous Flows', value: metrics.anomalyCount, icon: <AlertTriangle className="w-4 h-4" />, color: 'red', unit: '' },
        ].map((kpi, i) => (
          <div key={i} className={`glass-panel p-4 rounded-2xl border ${kpi.color === 'red' && metrics.anomalyCount > 0 ? 'border-red-500/30' : 'border-slate-800'} flex items-center gap-3`}>
            <div className={`p-2.5 rounded-xl bg-${kpi.color}-500/10 text-${kpi.color}-400`}>{kpi.icon}</div>
            <div>
              <div className="text-xs text-slate-400">{kpi.label}</div>
              <div className={`text-lg font-black font-mono ${kpi.color === 'red' && metrics.anomalyCount > 0 ? 'text-red-400' : 'text-white'}`}>
                {kpi.value} <span className="text-xs font-normal text-slate-500">{kpi.unit}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Bandwidth Timeline */}
        <div className="lg:col-span-2 glass-panel p-5 rounded-2xl">
          <h3 className="font-bold text-sm text-slate-200 mb-4 flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" /> {isZh ? '網路頻寬吞吐時序趨勢 (24h)' : 'Network Bandwidth Timeline (24h)'}
          </h3>
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={SAMPLE_BANDWIDTH_HISTORY}>
                <defs>
                  <linearGradient id="inbound" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="outbound" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip contentStyle={{ backgroundColor: '#090d16', borderColor: '#06b6d4', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="InboundMbps" stroke="#06b6d4" fill="url(#inbound)" name={isZh ? '入站頻寬 (Mbps)' : 'Inbound Mbps'} />
                <Area type="monotone" dataKey="OutboundMbps" stroke="#8b5cf6" fill="url(#outbound)" name={isZh ? '出站頻寬 (Mbps)' : 'Outbound Mbps'} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Talkers & Protocol Distribution */}
        <div className="glass-panel p-5 rounded-2xl flex flex-col justify-between space-y-4">
          <div>
            <h3 className="font-bold text-sm text-slate-200 mb-2 flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-400" /> {isZh ? '最高流量主機 (Top Talkers)' : 'Top Talkers (Volume)'}
            </h3>
            <div className="space-y-2">
              {TOP_TALKERS_DATA.map((t, i) => (
                <div key={i} className="flex items-center justify-between text-xs font-mono">
                  <span className="text-cyan-300">{t.ip}</span>
                  <span className="text-slate-400">{t.display}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="pt-2 border-t border-slate-900">
            <h3 className="font-bold text-xs text-slate-400 mb-2 flex items-center gap-2">
              <Globe className="w-3.5 h-3.5 text-purple-400" /> {isZh ? '協定分佈佔比' : 'Protocol Share'}
            </h3>
            <div className="flex gap-2 text-[10px] font-mono flex-wrap">
              {PROTOCOL_DIST.map((p, i) => (
                <span key={i} style={{ color: p.color }} className="bg-slate-950 px-2 py-1 rounded border border-slate-900">
                  {p.name}: {p.value}%
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Live Flow Stream Table */}
      <div className="glass-panel p-5 rounded-2xl space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <h3 className="font-bold text-sm text-white flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" /> {isZh ? '實時網路流量串流' : 'Live Flow Stream'}
          </h3>
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-1">
              <span className="text-[10px] text-slate-500 font-mono">{isZh ? '流向：' : 'DIRECTION:'}</span>
              {['ALL', 'INBOUND', 'OUTBOUND', 'LATERAL'].map(d => (
                <button key={d} onClick={() => setDirectionFilter(d)}
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold transition-all ${directionFilter === d ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'bg-slate-900 text-slate-500 hover:text-slate-300'}`}>
                  {d === 'ALL' ? t('common.all', 'ALL') : d}
                </button>
              ))}
            </div>
            <div className="flex items-center gap-1">
              {['ALL', 'TCP', 'UDP', 'ANOMALY'].map(f => (
                <button key={f} onClick={() => setFilter(f)}
                  className={`px-2.5 py-1 rounded-lg text-xs font-mono font-semibold transition-all ${filter === f ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white'}`}>
                  {f === 'ALL' ? t('common.all', 'ALL') : f === 'ANOMALY' ? (isZh ? '異常' : 'ANOMALY') : f}
                </button>
              ))}
            </div>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-mono border-collapse text-left">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 uppercase text-[10px]">
                <th className="py-2.5 px-3">{isZh ? '時間' : 'Time'}</th>
                <th className="py-2.5 px-3">{isZh ? '來源技術' : 'Source'}</th>
                <th className="py-2.5 px-3">{isZh ? '方向' : 'Direction'}</th>
                <th className="py-2.5 px-3">Src IP:Port</th>
                <th className="py-2.5 px-3">Dst IP:Port</th>
                <th className="py-2.5 px-3">{isZh ? '協定' : 'Proto'}</th>
                <th className="py-2.5 px-3">{isZh ? '傳輸量' : 'Bytes'}</th>
                <th className="py-2.5 px-3">{isZh ? '地理位置' : 'Geo'}</th>
                <th className="py-2.5 px-3">{isZh ? '狀態' : 'Status'}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900">
              {displayFlows.map((flow, i) => (
                <tr key={i} onClick={() => flow.anomalyFlag && setSelectedAnomaly(flow)} className={`hover:bg-slate-900/40 transition-colors ${flow.anomalyFlag ? 'bg-red-500/5 cursor-pointer' : ''}`}>
                  <td className="py-2.5 px-3 text-slate-400">{new Date(flow.timestamp).toLocaleTimeString()}</td>
                  <td className="py-2.5 px-3">
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">{flow.sourceType}</span>
                  </td>
                  <td className="py-2.5 px-3">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] flex items-center gap-1 w-fit ${flow.direction === 'INBOUND' ? 'text-cyan-400 bg-cyan-500/10' : flow.direction === 'OUTBOUND' ? 'text-purple-400 bg-purple-500/10' : 'text-amber-400 bg-amber-500/10'}`}>
                      {flow.direction === 'INBOUND' ? <ArrowDownLeft className="w-3 h-3" /> : flow.direction === 'OUTBOUND' ? <ArrowUpRight className="w-3 h-3" /> : <ArrowRightLeft className="w-3 h-3" />}
                      {flow.direction}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300">{flow.srcIp}<span className="text-slate-600">:{flow.srcPort}</span></td>
                  <td className="py-2.5 px-3 text-slate-300">{flow.destIp}<span className="text-slate-600">:{flow.destPort}</span></td>
                  <td className="py-2.5 px-3">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold"
                      style={{ background: PROTOCOL_COLORS[flow.protocol] + '20', color: PROTOCOL_COLORS[flow.protocol], border: `1px solid ${PROTOCOL_COLORS[flow.protocol]}40` }}>
                      {flow.protocol}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300">{(flow.bytes / 1024).toFixed(1)}KB</td>
                  <td className="py-2.5 px-3 text-slate-500">{flow.geoCountry || 'US'}</td>
                  <td className="py-2.5 px-3">
                    {flow.anomalyFlag
                      ? <span className="flex items-center gap-1 text-red-400 font-bold"><AlertTriangle className="w-3 h-3" /> {isZh ? '異常偵測' : 'ANOMALY'}</span>
                      : <span className="text-emerald-400">{isZh ? '正常' : 'Normal'}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Anomaly Detail Modal */}
      {selectedAnomaly && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="glass-panel p-6 rounded-2xl max-w-lg w-full border border-red-500/40 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-red-400 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5" /> {isZh ? '異常流量偵測細節' : 'Flow Anomaly Detection Detail'}
              </h3>
              <button onClick={() => setSelectedAnomaly(null)} className="text-slate-400 hover:text-white"><X className="w-5 h-5" /></button>
            </div>
            <div className="space-y-2 text-xs font-mono">
              <div className="bg-red-500/10 text-red-300 p-3 rounded-xl border border-red-500/30 font-semibold">
                {selectedAnomaly.anomalyReason || (isZh ? '規則違規：識別出高風險連線特徵' : 'Rule Violation: High-risk connection pattern identified')}
              </div>
              <div className="grid grid-cols-2 gap-2 text-slate-300 pt-2">
                <div>{isZh ? '來源 IP' : 'Source IP'}: <span className="text-cyan-400">{selectedAnomaly.srcIp}:{selectedAnomaly.srcPort}</span></div>
                <div>{isZh ? '目的 IP' : 'Dest IP'}: <span className="text-cyan-400">{selectedAnomaly.destIp}:{selectedAnomaly.destPort}</span></div>
                <div>{isZh ? '協定' : 'Protocol'}: <span className="text-white">{selectedAnomaly.protocol}</span></div>
                <div>{isZh ? '方向' : 'Direction'}: <span className="text-white">{selectedAnomaly.direction}</span></div>
                <div>{isZh ? '傳輸大小' : 'Bytes'}: <span className="text-white">{(selectedAnomaly.bytes / 1024).toFixed(1)} KB</span></div>
                <div>{isZh ? '風險評分' : 'Risk Score'}: <span className="text-red-400 font-bold">{selectedAnomaly.riskScore || 90} / 100</span></div>
              </div>
            </div>
            <div className="pt-3 border-t border-slate-900 flex justify-end">
              <button onClick={() => setSelectedAnomaly(null)} className="px-4 py-2 rounded-xl bg-slate-800 text-xs font-mono font-bold text-white hover:bg-slate-700">
                {isZh ? '關閉' : 'Close'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
