import React, { useState, useEffect } from 'react';
import { Search, Upload, ShieldAlert, Globe, Lock, FileText, AlertTriangle, CheckCircle, Download, Network, Share2 } from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { fetchPcapSample } from '../services/apiClient';
import { useLanguage } from '../contexts/LanguageContext';

const SEVERITY_COLOR = { Critical: '#ef4444', High: '#f59e0b', Medium: '#06b6d4', Low: '#10b981' };

async function uploadRealPcapFile(file) {
  const formData = new FormData();
  formData.append('pcapFile', file);
  const res = await fetch('/api/packets/upload', { method: 'POST', body: formData });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `Upload failed: ${res.status}`);
  return data.summary;
}

export default function PacketInspectorView() {
  const { t, language } = useLanguage();
  const isZh = language === 'zh-TW';

  const [pcapData, setPcapData] = useState(null);
  const [activeTab, setActiveTab] = useState('dns');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [copiedIoc, setCopiedIoc] = useState(false);

  useEffect(() => {
    setIsAnalyzing(true);
    fetchPcapSample().then(data => {
      if (data) setPcapData(data);
      setIsAnalyzing(false);
    }).catch(() => setIsAnalyzing(false));
  }, []);

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setIsAnalyzing(true);
    try {
      const summary = await uploadRealPcapFile(file);
      if (summary) setPcapData(summary);
    } catch (err) {
      console.error('[PCAP Upload]', err.message);
      alert(`${isZh ? 'PCAP 解析錯誤' : 'PCAP Parse Error'}: ${err.message}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleExportIocs = () => {
    if (!pcapData) return;
    const iocExport = {
      pcapFile: pcapData.pcapFileName,
      generatedAt: new Date().toISOString(),
      flaggedThreats: pcapData.flaggedThreats || [],
      suspiciousDns: (pcapData.dnsQueries || []).filter(q => q.isSuspicious || q.dgaScore > 5),
      deprecatedTls: (pcapData.tlsHandshakes || []).filter(t => t.certAlert)
    };
    navigator.clipboard.writeText(JSON.stringify(iocExport, null, 2));
    setCopiedIoc(true);
    setTimeout(() => setCopiedIoc(false), 3000);
  };

  const pieData = pcapData?.protocolDistribution?.map(p => ({ name: p.protocol, value: p.count })) || [];
  const PIE_COLORS = ['#06b6d4', '#8b5cf6', '#f59e0b', '#10b981'];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Search className="w-6 h-6 text-cyan-400" />
            {t('sidebar.packetInspector', 'Packet Inspector & PCAP Analyzer')}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {isZh
              ? '防禦性協定元數據擷取 — 解析 DNS 查詢、TLS SNI 指紋、HTTP 會話與威脅指標。'
              : 'Defensive protocol metadata extraction — DNS queries, TLS SNI fingerprints, HTTP sessions, and threat indicators.'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {pcapData && (
            <button onClick={handleExportIocs} className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-cyan-500/30 text-xs text-cyan-300 font-mono transition-all">
              <Download className="w-3.5 h-3.5 text-cyan-400" /> {copiedIoc ? (isZh ? 'IOC 已複製！' : 'IOCs Copied!') : (isZh ? '匯出 IOC' : 'Export IOCs')}
            </button>
          )}
          <label className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 border border-cyan-500/30 text-xs text-white font-mono font-bold cursor-pointer transition-all shadow-md">
            <Upload className="w-4 h-4 text-white" /> {isZh ? '上傳 PCAP 封包' : 'Upload PCAP'}
            <input type="file" onChange={handleFileUpload} className="hidden" accept=".pcap,.pcapng,.cap" />
          </label>
        </div>
      </div>

      {isAnalyzing && (
        <div className="p-4 rounded-xl bg-cyan-950/30 border border-cyan-500/30 text-xs font-mono text-cyan-300 flex items-center gap-2 animate-pulse">
          <Search className="w-4 h-4" /> {isZh ? '正在分析 PCAP 元數據並擷取協定特徵…' : 'Analyzing PCAP metadata and extracting protocol artifacts…'}
        </div>
      )}

      {pcapData && (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: isZh ? '總封包數' : 'Total Packets', value: pcapData.totalPackets?.toLocaleString(), icon: <FileText className="w-4 h-4" />, color: 'cyan' },
              { label: isZh ? '擷取時長' : 'Capture Duration', value: `${pcapData.captureDurationSec}s`, icon: <Globe className="w-4 h-4" />, color: 'blue' },
              { label: isZh ? 'TLS 握手連線' : 'TLS Handshakes', value: pcapData.tlsHandshakes?.length, icon: <Lock className="w-4 h-4" />, color: 'purple' },
              { label: isZh ? '標記威脅指標' : 'Flagged Threats', value: pcapData.flaggedThreats?.length, icon: <AlertTriangle className="w-4 h-4" />, color: 'red' },
            ].map((card, i) => (
              <div key={i} className={`glass-panel p-4 rounded-2xl border ${card.color === 'red' && card.value > 0 ? 'border-red-500/30' : 'border-slate-800'} flex items-center gap-3`}>
                <div className={`p-2.5 rounded-xl bg-${card.color}-500/10 text-${card.color}-400`}>{card.icon}</div>
                <div>
                  <div className="text-xs text-slate-400">{card.label}</div>
                  <div className={`text-lg font-black font-mono ${card.color === 'red' && card.value > 0 ? 'text-red-400' : 'text-white'}`}>{card.value}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Flagged Threats Banner */}
          {pcapData.flaggedThreats?.length > 0 && (
            <div className="glass-panel p-4 rounded-2xl border border-amber-500/30 space-y-2">
              <h3 className="text-sm font-bold text-amber-300 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" /> {isZh ? '自 PCAP 擷取之威脅特徵指標' : 'Threat Indicators Extracted from PCAP'}
              </h3>
              {pcapData.flaggedThreats.map((threat, i) => (
                <div key={i} className="flex items-start gap-3 p-3 rounded-xl bg-slate-950 border border-slate-900">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono"
                    style={{ background: SEVERITY_COLOR[threat.severity] + '20', color: SEVERITY_COLOR[threat.severity] }}>
                    {threat.severity}
                  </span>
                  <div>
                    <div className="text-xs font-bold text-white">{threat.category}</div>
                    <div className="text-xs text-slate-400 font-mono">{threat.details}</div>
                  </div>
                  <span className="ml-auto text-[10px] text-slate-600 font-mono shrink-0">{threat.timestamp}</span>
                </div>
              ))}
            </div>
          )}

          {/* Charts + Tabs */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Protocol Pie */}
            <div className="glass-panel p-5 rounded-2xl">
              <h3 className="font-bold text-sm text-slate-200 mb-4">{isZh ? '協定分佈佔比' : 'Protocol Distribution'}</h3>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={4} dataKey="value">
                    {pieData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#090d16', borderRadius: '8px' }} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>

            {/* Detail Tab Panel */}
            <div className="lg:col-span-2 glass-panel p-5 rounded-2xl space-y-4">
              <div className="flex gap-2 flex-wrap">
                {['dns', 'http', 'tls', 'tcp'].map(tab => (
                  <button key={tab} onClick={() => setActiveTab(tab)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold uppercase transition-all ${activeTab === tab ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white'}`}>
                    {tab === 'dns' ? (isZh ? 'DNS 查詢' : 'DNS Queries') : tab === 'http' ? (isZh ? 'HTTP 會話' : 'HTTP Sessions') : tab === 'tls' ? (isZh ? 'TLS 握手' : 'TLS Handshakes') : (isZh ? 'TCP 串流' : 'TCP Flows')}
                  </button>
                ))}
              </div>

              <div className="overflow-x-auto text-xs font-mono max-h-64 overflow-y-auto">
                {activeTab === 'dns' && (
                  <table className="w-full text-left border-collapse">
                    <thead><tr className="border-b border-slate-800 text-slate-500 text-[10px] uppercase">
                      <th className="py-2 px-2">{isZh ? '時間' : 'Time'}</th>
                      <th className="py-2 px-2">{isZh ? '用戶端' : 'Client'}</th>
                      <th className="py-2 px-2">{isZh ? '查詢網域名稱' : 'Query Domain'}</th>
                      <th className="py-2 px-2">DGA Score</th>
                      <th className="py-2 px-2">{isZh ? '解析 IP' : 'Resolved IP'}</th>
                    </tr></thead>
                    <tbody className="divide-y divide-slate-900">
                      {(pcapData.dnsQueries || []).map((r, i) => (
                        <tr key={i} className={`hover:bg-slate-900/40 ${r.isSuspicious || r.dgaScore > 5 ? 'bg-red-500/5' : ''}`}>
                          <td className="py-2 px-2 text-slate-500">{r.timestamp}</td>
                          <td className="py-2 px-2 text-slate-300">{r.clientIp}</td>
                          <td className={`py-2 px-2 font-bold ${r.isSuspicious ? 'text-red-400' : 'text-cyan-300'}`}>{r.queryDomain}</td>
                          <td className="py-2 px-2">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] ${r.dgaScore > 5 ? 'bg-red-500/20 text-red-400 font-bold' : 'bg-slate-900 text-slate-400'}`}>
                              {r.dgaScore ? `${r.dgaScore}/10` : '1.0/10'}
                            </span>
                          </td>
                          <td className="py-2 px-2 text-slate-400">{r.resolvedIp || 'NXDOMAIN'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {activeTab === 'http' && (
                  <table className="w-full text-left border-collapse">
                    <thead><tr className="border-b border-slate-800 text-slate-500 text-[10px] uppercase">
                      <th className="py-2 px-2">{isZh ? '時間' : 'Time'}</th>
                      <th className="py-2 px-2">{isZh ? '方法' : 'Method'}</th>
                      <th className="py-2 px-2">Host / URI</th>
                      <th className="py-2 px-2">{isZh ? '狀態碼' : 'Status'}</th>
                      <th className="py-2 px-2">User-Agent</th>
                    </tr></thead>
                    <tbody className="divide-y divide-slate-900">
                      {(pcapData.httpRequests || []).map((r, i) => (
                        <tr key={i} className="hover:bg-slate-900/40">
                          <td className="py-2 px-2 text-slate-500">{r.timestamp}</td>
                          <td className="py-2 px-2 text-cyan-400 font-bold">{r.method}</td>
                          <td className="py-2 px-2 text-slate-300">{r.host}{r.uri}</td>
                          <td className="py-2 px-2 text-emerald-400">{r.responseStatus}</td>
                          <td className="py-2 px-2 text-slate-500 truncate max-w-xs">{r.userAgent}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {activeTab === 'tls' && (
                  <table className="w-full text-left border-collapse">
                    <thead><tr className="border-b border-slate-800 text-slate-500 text-[10px] uppercase">
                      <th className="py-2 px-2">SNI</th>
                      <th className="py-2 px-2">Version</th>
                      <th className="py-2 px-2">Cipher Suite</th>
                      <th className="py-2 px-2">{isZh ? '憑證狀態' : 'Cert Status'}</th>
                    </tr></thead>
                    <tbody className="divide-y divide-slate-900">
                      {(pcapData.tlsHandshakes || []).map((r, i) => (
                        <tr key={i} className="hover:bg-slate-900/40">
                          <td className="py-2 px-2 text-cyan-300 font-bold">{r.serverNameIndication || 'N/A'}</td>
                          <td className="py-2 px-2 text-slate-400">{r.tlsVersion}</td>
                          <td className="py-2 px-2 text-slate-500 truncate max-w-xs">{r.cipherSuite}</td>
                          <td className="py-2 px-2">
                            {r.certAlert
                              ? <span className="text-red-400 font-bold flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> {r.certAlert}</span>
                              : <span className="text-emerald-400 flex items-center gap-1"><CheckCircle className="w-3 h-3" /> {isZh ? '有效憑證' : 'Valid'}</span>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {activeTab === 'tcp' && (
                  <table className="w-full text-left border-collapse">
                    <thead><tr className="border-b border-slate-800 text-slate-500 text-[10px] uppercase">
                      <th className="py-2 px-2">Src IP:Port</th>
                      <th className="py-2 px-2">Dst IP:Port</th>
                      <th className="py-2 px-2">Flags</th>
                      <th className="py-2 px-2">{isZh ? '重傳' : 'Retrans'}</th>
                      <th className="py-2 px-2">{isZh ? '傳輸大小' : 'Bytes'}</th>
                    </tr></thead>
                    <tbody className="divide-y divide-slate-900">
                      {(pcapData.tcpStreams || []).map((r, i) => (
                        <tr key={i} className="hover:bg-slate-900/40">
                          <td className="py-2 px-2 text-slate-300">{r.srcIp}:{r.srcPort}</td>
                          <td className="py-2 px-2 text-slate-300">{r.dstIp}:{r.dstPort}</td>
                          <td className="py-2 px-2 text-cyan-400">{r.flags}</td>
                          <td className="py-2 px-2 text-slate-500">{r.retransmissions || 0}</td>
                          <td className="py-2 px-2 text-slate-400">{(r.bytes / 1024).toFixed(1)} KB</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
