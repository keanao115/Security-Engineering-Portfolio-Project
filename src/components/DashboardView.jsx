import React from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  Activity,
  Cpu,
  HardDrive,
  Server,
  Zap,
  CheckCircle,
  TrendingUp,
  Clock,
  ExternalLink
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts';
import { useLanguage } from '../contexts/LanguageContext';

const attackTimelineData = [
  { time: '00:00', BruteForce: 0, Scans: 12, C2Traffic: 0 },
  { time: '04:00', BruteForce: 0, Scans: 8, C2Traffic: 0 },
  { time: '08:00', BruteForce: 0, Scans: 15, C2Traffic: 0 },
  { time: '12:00', BruteForce: 0, Scans: 20, C2Traffic: 0 },
  { time: '16:00', BruteForce: 0, Scans: 14, C2Traffic: 0 },
  { time: '20:00', BruteForce: 0, Scans: 10, C2Traffic: 0 },
];

export default function DashboardView({ onNavigate, nmapScan, anomalies = [] }) {
  const { t } = useLanguage();

  const severityData = [
    { name: t('common.critical', 'Critical'), value: 0, color: '#ef4444' },
    { name: t('common.high', 'High'), value: 0, color: '#f59e0b' },
    { name: t('common.medium', 'Medium'), value: 2, color: '#06b6d4' },
    { name: t('common.low', 'Low'), value: 98, color: '#10b981' },
  ];

  const hasRealScan = nmapScan && Array.isArray(nmapScan.openPorts);
  const openPortCount = hasRealScan ? nmapScan.openPorts.length : 0;

  const dynamicScores = [
    { label: t('dashboard.overallScore', 'Overall Security Score'), score: hasRealScan ? Math.max(60, 94 - openPortCount * 5) : 94, color: 'from-emerald-400 to-cyan-500' },
    { label: t('dashboard.networkProt', 'Network Protection'), score: hasRealScan ? Math.max(50, 90 - openPortCount * 8) : 90, color: 'from-cyan-400 to-blue-500' },
    { label: t('dashboard.endpointSec', 'Endpoint Security'), score: 88, color: 'from-blue-400 to-indigo-500' },
    { label: t('dashboard.identityAccess', 'Identity & Access'), score: 96, color: 'from-emerald-400 to-teal-500' },
    { label: t('dashboard.cloudPosture', 'Cloud Posture'), score: 92, color: 'from-purple-400 to-cyan-400' },
    { label: t('dashboard.emailSec', 'Email Security'), score: 98, color: 'from-teal-400 to-emerald-400' },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner Status */}
      {hasRealScan ? (
        <div className="p-4 rounded-2xl bg-gradient-to-r from-cyan-950/60 via-slate-900/80 to-slate-950 border border-cyan-500/40 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-lg shadow-cyan-950/30">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/20 text-cyan-400">
              <Activity className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm text-cyan-300">REAL NETWORK SCAN TELEMETRY: ACTIVE HOST PROBE</span>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  Target: {nmapScan.host}
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-0.5 font-mono">
                Discovered <strong className="text-cyan-400">{openPortCount} open ports</strong> on host {nmapScan.host}. Dashboard metrics updated from real socket scan results.
              </p>
            </div>
          </div>
          <button
            onClick={() => onNavigate('network')}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-semibold font-mono transition-all shrink-0"
          >
            {t('common.viewDetails', '檢視真實掃描報告')} <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>
      ) : (
        <div className="p-4 rounded-2xl bg-gradient-to-r from-emerald-950/40 via-slate-900/80 to-slate-950 border border-emerald-500/30 flex items-center justify-between shadow-lg shadow-emerald-950/20">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-emerald-500/20 text-emerald-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm text-emerald-300">SYSTEM SECURITY POSTURE: NORMAL OPERATIONAL STATUS</span>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  Active Telemetry & Defense Online
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                All defensive scanning engines, log pipelines, and host integrity monitors are running smoothly. Zero unhandled live threats.
              </p>
            </div>
          </div>
          <button
            onClick={() => onNavigate('simulation')}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-xs font-semibold font-mono transition-all shrink-0"
          >
            {t('sidebar.simulation', '前往攻擊模擬 (Attack Simulation)')} <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Real Scan Summary Cards Bar */}
      {hasRealScan && openPortCount > 0 && (
        <div className="glass-panel p-5 rounded-2xl border border-cyan-500/20 space-y-3">
          <h3 className="text-sm font-bold text-cyan-300 flex items-center gap-2 font-mono">
            <Server className="w-4 h-4 text-cyan-400" />
            真實掃描發現之開放服務 (Real Open Port Services on {nmapScan.host}):
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2 font-mono text-xs">
            {nmapScan.openPorts.map((p, idx) => (
              <div key={idx} className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 space-y-0.5">
                <div className="text-[10px] text-slate-400">PORT {p.port} ({p.protocol?.toUpperCase()})</div>
                <div className="font-bold text-cyan-300 truncate">{p.service}</div>
                <div className="text-[10px] text-emerald-400">{p.state}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Security Score Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        {dynamicScores.map((item, idx) => (
          <div key={idx} className="glass-panel p-4 rounded-2xl flex flex-col items-center justify-between text-center relative overflow-hidden group hover:border-cyan-500/40 transition-all">
            <span className="text-[11px] font-medium text-slate-400">{item.label}</span>
            <div className="my-2 relative flex items-center justify-center">
              {/* Glowing Circle */}
              <div className="w-16 h-16 rounded-full border-4 border-slate-800 flex items-center justify-center relative">
                <div className={`absolute inset-0 rounded-full border-4 border-transparent bg-gradient-to-tr ${item.color} [mask:linear-gradient(#fff_0_0)_content-box,linear-gradient(#fff_0_0)] [mask-composite:exclude]`}></div>
                <span className="text-xl font-black font-mono text-white">{item.score}</span>
              </div>
            </div>
            <span className="text-[10px] text-emerald-400 font-mono font-semibold flex items-center gap-1">
              <TrendingUp className="w-3 h-3" /> {t('common.optimal', 'Optimal')}
            </span>
          </div>
        ))}
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Attack Timeline */}
        <div className="lg:col-span-2 glass-panel p-5 rounded-2xl flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-bold text-sm text-slate-200 flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                {t('dashboard.liveAttackTimeline', 'Live Cyber Attack Timeline (24 Hours)')}
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                {t('dashboard.realTimeVectors', 'Real-time threat vectors detected across network perimeter')}
              </p>
            </div>
            <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 px-2.5 py-1 rounded-md border border-cyan-500/20">
              {t('dashboard.liveFeed', 'Live Feed')}
            </span>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={attackTimelineData}>
                <defs>
                  <linearGradient id="colorBrute" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorC2" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip contentStyle={{ backgroundColor: '#090d16', borderColor: '#06b6d4', borderRadius: '8px' }} />
                <Area type="monotone" dataKey="BruteForce" stroke="#ef4444" fillOpacity={1} fill="url(#colorBrute)" name={t('dashboard.bruteForceSeries', 'RDP/SSH Brute Force')} />
                <Area type="monotone" dataKey="Scans" stroke="#06b6d4" fillOpacity={1} fill="url(#colorScans)" name={t('dashboard.scansSeries', 'Port Scans')} />
                <Area type="monotone" dataKey="C2Traffic" stroke="#8b5cf6" fillOpacity={1} fill="url(#colorC2)" name={t('dashboard.c2Series', 'C2 Beacon Attempts')} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Breakdown */}
        <div className="glass-panel p-5 rounded-2xl flex flex-col justify-between">
          <div>
            <h3 className="font-bold text-sm text-slate-200 mb-1 flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-400" />
              {t('dashboard.threatSeverity', 'Threat Severity Breakdown')}
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              {t('dashboard.severityDistDesc', 'Distribution of active alerts')}
            </p>
          </div>
          <div className="h-52 w-full flex items-center justify-center my-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={severityData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={5} dataKey="value">
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#090d16', borderRadius: '8px' }} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 text-center text-xs font-mono pt-2 border-t border-slate-800">
            <div className="bg-emerald-500/10 p-2 rounded-lg border border-emerald-500/20 text-emerald-300">
              <span className="block font-bold text-sm">0</span> {t('common.critical', 'Critical')}
            </div>
            <div className="bg-emerald-500/10 p-2 rounded-lg border border-emerald-500/20 text-emerald-300">
              <span className="block font-bold text-sm">0</span> {t('common.high', 'High')}
            </div>
          </div>
        </div>
      </div>

      {/* Network & Infrastructure Health */}
      <div className="glass-panel p-5 rounded-2xl">
        <h3 className="font-bold text-sm text-slate-200 mb-4 flex items-center gap-2">
          <Server className="w-4 h-4 text-emerald-400" />
          {t('dashboard.telemetryHealth', 'SOC Infrastructure & Telemetry Health')}
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400"><Cpu className="w-4 h-4" /></div>
            <div>
              <div className="text-xs text-slate-400">{t('dashboard.siemCpu', 'SIEM Engine CPU')}</div>
              <div className="text-sm font-bold font-mono text-white">24% <span className="text-[10px] text-emerald-400 font-normal">({t('dashboard.normal', 'Normal')})</span></div>
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400"><Activity className="w-4 h-4" /></div>
            <div>
              <div className="text-xs text-slate-400">{t('dashboard.ramUsage', 'RAM Usage')}</div>
              <div className="text-sm font-bold font-mono text-white">48% <span className="text-[10px] text-emerald-400 font-normal">(15.3 GB)</span></div>
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400"><HardDrive className="w-4 h-4" /></div>
            <div>
              <div className="text-xs text-slate-400">{t('dashboard.diskUsage', 'Log Buffer Disk')}</div>
              <div className="text-sm font-bold font-mono text-white">32% <span className="text-[10px] text-emerald-400 font-normal">(512 GB Free)</span></div>
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400"><ShieldCheck className="w-4 h-4" /></div>
            <div>
              <div className="text-xs text-slate-400">{t('dashboard.paloAltoFw', 'PaloAlto Firewall')}</div>
              <div className="text-sm font-bold font-mono text-emerald-400 flex items-center gap-1">
                <CheckCircle className="w-3 h-3" /> {t('dashboard.activeBlocking', 'Active / Blocking')}
              </div>
            </div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center gap-3">
            <div className="p-2 rounded-lg bg-teal-500/10 text-teal-400"><CheckCircle className="w-4 h-4" /></div>
            <div>
              <div className="text-xs text-slate-400">{t('dashboard.avStatus', 'Antivirus Status')}</div>
              <div className="text-sm font-bold font-mono text-emerald-400 flex items-center gap-1">
                <CheckCircle className="w-3 h-3" /> {t('dashboard.updated', 'Updated (v4.18)')}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
