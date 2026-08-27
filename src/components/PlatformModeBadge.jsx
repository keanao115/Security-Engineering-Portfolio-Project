import React from 'react';
import { ShieldCheck, AlertCircle, RefreshCw } from 'lucide-react';
import { usePlatformMode } from '../contexts/PlatformModeContext';
import { useLanguage } from '../contexts/LanguageContext';

export default function PlatformModeBadge() {
  const { platformMode, runtimeModeSwitchAllowed, switchMode, loading } = usePlatformMode();
  const { language } = useLanguage();
  const isZh = language === 'zh-TW';

  if (loading) {
    return (
      <div className="flex items-center gap-1.5 px-3 py-1 bg-slate-800 text-slate-400 rounded-full text-xs font-semibold border border-slate-700 font-mono">
        <RefreshCw className="w-3 h-3 animate-spin" /> {isZh ? '模式載入中...' : 'Mode: Loading...'}
      </div>
    );
  }

  const isLive = platformMode === 'LIVE';

  return (
    <div className="flex items-center gap-2 font-mono">
      <div
        title={
          isLive
            ? (isZh ? '實時模式 (LIVE)：僅顯示真實收集、接收或上傳之遙測數據。' : 'LIVE MODE: Only genuine collected, received, or uploaded telemetry is displayed. Synthetic generation disabled.')
            : (isZh ? '展示模式 (DEMO)：包含模擬或預設之展示遙測數據。' : 'DEMO MODE: Environment contains simulated or seeded telemetry for demonstration purposes.')
        }
        className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold border shadow-sm transition-all ${
          isLive
            ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40 shadow-emerald-950/20'
            : 'bg-amber-500/15 text-amber-400 border-amber-500/40 shadow-amber-950/20 animate-pulse'
        }`}
      >
        {isLive ? (
          <>
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>{isZh ? '實時防禦模式' : 'LIVE MODE'}</span>
          </>
        ) : (
          <>
            <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
            <span>{isZh ? '示範演練模式' : 'DEMO MODE'}</span>
          </>
        )}
      </div>

      {runtimeModeSwitchAllowed && (
        <button
          onClick={() => switchMode(isLive ? 'DEMO' : 'LIVE')}
          className="text-[11px] font-semibold text-slate-400 hover:text-cyan-400 underline underline-offset-2 transition-colors px-1"
        >
          {isLive ? (isZh ? '切換至展示模式' : 'Switch to Demo') : (isZh ? '切換至實時模式' : 'Switch to Live')}
        </button>
      )}
    </div>
  );
}
