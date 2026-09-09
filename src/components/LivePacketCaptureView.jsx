import React, { useState, useEffect } from 'react';
import { Radio, Play, Square, Activity, Filter, ShieldCheck, Cpu } from 'lucide-react';
import TelemetrySourceBadge from './TelemetrySourceBadge';
import LiveEmptyState from './LiveEmptyState';
import { useLanguage } from '../contexts/LanguageContext';
import { authFetch } from '../services/apiClient';

export default function LivePacketCaptureView() {
  const { t, language } = useLanguage();
  const isZh = language === 'zh-TW';

  const [interfaces, setInterfaces] = useState([]);
  const [selectedIface, setSelectedIface] = useState('');
  const [bpfFilter, setBpfFilter] = useState('tcp or udp');
  const [activeSession, setActiveSession] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchCaptureStatus = async () => {
    try {
      const resIf = await authFetch('/api/capture/interfaces');
      if (resIf.ok) {
        const data = await resIf.json();
        setInterfaces(data.interfaces || []);
        if (data.interfaces?.length > 0 && !selectedIface) {
          setSelectedIface(data.interfaces[0].id);
        }
      }

      const resSt = await authFetch('/api/capture/status');
      if (resSt.ok) {
        const data = await resSt.json();
        setActiveSession(data.activeSession);
      }
    } catch (err) {
      console.warn('[LivePacketCaptureView] Fetch failed:', err);
    }
  };

  useEffect(() => {
    fetchCaptureStatus();
    const interval = setInterval(fetchCaptureStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleStart = async () => {
    if (!selectedIface) return;
    setLoading(true);
    try {
      const res = await authFetch('/api/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interfaceId: selectedIface, bpfFilter }),
      });
      if (res.ok) {
        await fetchCaptureStatus();
      }
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    setLoading(true);
    try {
      const res = await authFetch('/api/capture/stop', { method: 'POST' });
      if (res.ok) {
        await fetchCaptureStatus();
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-cyan-500/20 pb-4">
        <div>
          <h2 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent flex items-center gap-2">
            <Radio className="w-6 h-6 text-cyan-400" /> {isZh ? '實時網路封包擷取引擎 (Npcap / libpcap)' : 'Live Packet Capture Engine (Npcap / libpcap)'}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {isZh
              ? '即時防禦性資料框擷取、BPF 封包過濾規則以及零拷貝環形緩衝區指標。'
              : 'Real-time defensive frame capture, BPF packet filtering, and zero-copy ring buffer metrics'}
          </p>
        </div>
      </div>

      {/* Interface & Controller Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" /> {isZh ? '網路介面選擇器' : 'Network Interface Selector'}
          </h3>

          <select
            value={selectedIface}
            onChange={(e) => setSelectedIface(e.target.value)}
            disabled={activeSession?.status === 'Running'}
            className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none font-mono"
          >
            {interfaces.map((iface) => (
              <option key={iface.id} value={iface.id}>
                {iface.name} ({iface.ipAddresses.ipv4 || 'No IPv4'})
              </option>
            ))}
          </select>

          <div className="space-y-1.5 text-xs text-slate-400 font-mono bg-slate-950 p-3 rounded-lg border border-slate-800">
            <div className="flex justify-between">
              <span>{isZh ? '網路卡：' : 'Adapter:'}</span>
              <span className="text-slate-200">{interfaces.find((i) => i.id === selectedIface)?.name || 'N/A'}</span>
            </div>
            <div className="flex justify-between">
              <span>MAC {isZh ? '位址：' : 'Address:'}</span>
              <span className="text-slate-200">{interfaces.find((i) => i.id === selectedIface)?.macAddress || 'N/A'}</span>
            </div>
            <div className="flex justify-between">
              <span>{isZh ? '混雜模式：' : 'Promiscuous:'}</span>
              <span className="text-emerald-400">{isZh ? '支援' : 'Supported'}</span>
            </div>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4 md:col-span-2">
          <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
            <Filter className="w-4 h-4 text-cyan-400" /> {isZh ? 'BPF 擷取過濾器與控制器' : 'BPF Capture Filter & Controller'}
          </h3>

          <div className="flex items-center gap-3">
            <input
              type="text"
              value={bpfFilter}
              onChange={(e) => setBpfFilter(e.target.value)}
              disabled={activeSession?.status === 'Running'}
              placeholder={isZh ? "例: tcp port 443 or udp port 53" : "e.g. tcp port 443 or udp port 53"}
              className="flex-1 bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-xs font-mono text-cyan-300 focus:border-cyan-500 focus:outline-none"
            />

            {activeSession?.status === 'Running' ? (
              <button
                onClick={handleStop}
                disabled={loading}
                className="px-5 py-2.5 bg-rose-600/20 hover:bg-rose-600/30 text-rose-400 border border-rose-500/40 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5"
              >
                <Square className="w-4 h-4" /> {isZh ? '停止擷取' : 'Stop Capture'}
              </button>
            ) : (
              <button
                onClick={handleStart}
                disabled={loading}
                className="px-5 py-2.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/40 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5"
              >
                <Play className="w-4 h-4" /> {isZh ? '開始擷取' : 'Start Capture'}
              </button>
            )}
          </div>

          <div className="grid grid-cols-3 gap-4 pt-2">
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-center">
              <span className="text-[10px] text-slate-400 block uppercase">{isZh ? '狀態' : 'Status'}</span>
              <span className={`text-sm font-bold font-mono ${activeSession?.status === 'Running' ? 'text-emerald-400' : 'text-slate-400'}`}>
                {activeSession?.status === 'Running' ? (isZh ? '運作中' : 'Running') : (isZh ? '已停止' : 'Stopped')}
              </span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-center">
              <span className="text-[10px] text-slate-400 block uppercase">{isZh ? '已擷取封包' : 'Packets Captured'}</span>
              <span className="text-sm font-bold font-mono text-cyan-400">{activeSession?.packetsCaptured || 0}</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-center">
              <span className="text-[10px] text-slate-400 block uppercase">{isZh ? '已擷取位元組' : 'Bytes Captured'}</span>
              <span className="text-sm font-bold font-mono text-amber-400">{activeSession?.bytesCaptured || 0} B</span>
            </div>
          </div>
        </div>
      </div>

      {!activeSession || activeSession.packetsCaptured === 0 ? (
        <LiveEmptyState
          title={isZh ? "目前無活動之封包擷取任務" : "No live packet capture active"}
          description={isZh ? "在網路介面上啟動基於 Npcap 或 libpcap 之封包擷取連線以串流即時資料框。" : "Start a capture session on a network interface using Npcap or libpcap to stream raw frames."}
          suggestedAction={isZh ? "請在上方選取網路介面，填寫 BPF 過濾表達式後點擊「開始擷取」。" : "Select an interface above, enter a BPF filter, and click 'Start Capture'."}
        />
      ) : null}
    </div>
  );
}
