import React, { useState } from 'react';
import { Bot, CheckSquare, Square, ShieldAlert, ArrowRight, CheckCircle, ShieldCheck } from 'lucide-react';
import { useLanguage } from '../contexts/LanguageContext';
import SoarActionModal from './SoarActionModal';

const PLAYBOOKS_DATA = [
  {
    id: 'pb-1',
    title: {
      'zh-TW': 'PowerShell 與惡意命令列稽核 SOP 應變程序',
      'en-US': 'PowerShell & Command Line Audit SOP Procedure'
    },
    steps: {
      'zh-TW': [
        '稽核事件 ID 4688 命令列中是否包含 -enc、DownloadString 或 Bypass 關鍵字',
        '向 VirusTotal 與 AbuseIPDB 查詢涉案之遠端 C2 IP 位址信譽評分',
        '確認父子行程層級關係 (cmd.exe / winword.exe / wmiprvse.exe 是否有異常衍生)',
        '檢查記憶體傾印 (Memory Dump) 與現行活動行程樹是否有隱蔽惡意處理程序',
        '驗證主機網絡隔離策略與端點防護軟體 (EDR) 即時攔截狀態'
      ],
      'en-US': [
        'Inspect Event ID 4688 Command Line for -enc or DownloadString strings',
        'Query remote IP addresses against VirusTotal & AbuseIPDB reputation feeds',
        'Identify parent process hierarchy (cmd.exe / winword.exe / wmiprvse.exe)',
        'Check endpoint memory dump & running process tree for suspicious processes',
        'Verify host network isolation policies and endpoint security status'
      ]
    }
  },
  {
    id: 'pb-2',
    title: {
      'zh-TW': '本機後門帳號與高特權群組異動排查 SOP',
      'en-US': 'Local User Account & Privilege Audit SOP'
    },
    steps: {
      'zh-TW': [
        '檢查事件 ID 4720 目標建立帳號與主體操作管理員之身分合法性',
        '稽核該帳號獲派之高風險特權群組 (如 SeDebugPrivilege, SeTakeOwnershipPrivilege)',
        '對照內部已核准之 IAM 清單確認該管理員帳戶是否為非授權影子帳號',
        '檢查網域控制器 (DC) Kerberos TGT 票證核發紀錄與稽核日誌留存狀態'
      ],
      'en-US': [
        'Check Event ID 4720 target user name and subject administrator user',
        'Audit assigned privilege groups (SeDebugPrivilege, SeTakeOwnershipPrivilege)',
        'Verify administrative accounts against approved IAM inventory',
        'Check Domain Controller Kerberos TGT ticket requests & log retention'
      ]
    }
  }
];

export default function SocCopilotView() {
  const { t, language } = useLanguage();
  const langKey = language === 'en-US' ? 'en-US' : 'zh-TW';

  const [selectedPlaybookId, setSelectedPlaybookId] = useState(PLAYBOOKS_DATA[0].id);
  const [completedSteps, setCompletedSteps] = useState({ 0: true, 1: true });
  const [showSoarModal, setShowSoarModal] = useState(false);

  const activePlaybook = PLAYBOOKS_DATA.find(p => p.id === selectedPlaybookId) || PLAYBOOKS_DATA[0];
  const activeTitle = activePlaybook.title[langKey] || activePlaybook.title['zh-TW'];
  const activeSteps = activePlaybook.steps[langKey] || activePlaybook.steps['zh-TW'];

  const toggleStep = (idx) => {
    setCompletedSteps(prev => ({ ...prev, [idx]: !prev[idx] }));
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Bot className="w-6 h-6 text-cyan-400" />
            {t('copilot.title', 'SOC Analyst Copilot & Incident Response Procedures')}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {t('copilot.subtitle', 'Guided incident triage procedures with investigation checklists and host isolation triggers.')}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Response Procedures list */}
        <div className="space-y-3">
          <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
            {t('copilot.availablePlaybooks', 'Available IR Procedures:')}
          </span>
          {PLAYBOOKS_DATA.map((pb) => {
            const isSelected = selectedPlaybookId === pb.id;
            const pbTitle = pb.title[langKey] || pb.title['zh-TW'];
            const stepCount = (pb.steps[langKey] || pb.steps['zh-TW']).length;
            return (
              <button
                key={pb.id}
                onClick={() => { setSelectedPlaybookId(pb.id); setCompletedSteps({}); }}
                className={`w-full p-4 rounded-2xl text-left border font-mono transition-all ${
                  isSelected
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 shadow-lg shadow-cyan-500/10'
                    : 'glass-panel text-slate-300 border-slate-800 hover:border-cyan-500/30'
                }`}
              >
                <div className="text-xs font-bold">{pbTitle}</div>
                <div className="text-[10px] text-slate-400 mt-1">
                  {stepCount} {t('copilot.stepsCount', 'Step Guided Investigation')}
                </div>
              </button>
            );
          })}
        </div>

        {/* Selected Response Procedure Step Checklist */}
        <div className="md:col-span-2 glass-panel p-6 rounded-2xl space-y-5">
          <div className="flex items-center justify-between border-b border-slate-900 pb-3">
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              {activeTitle}
            </h3>
            <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded border border-emerald-500/20">
              {t('copilot.activeResponse', 'Active Incident Response')}
            </span>
          </div>

          <div className="space-y-3">
            {activeSteps.map((stepText, idx) => {
              const isDone = !!completedSteps[idx];
              return (
                <div
                  key={idx}
                  onClick={() => toggleStep(idx)}
                  className={`p-3.5 rounded-xl border text-xs font-mono flex items-center gap-3 cursor-pointer transition-all ${
                    isDone
                      ? 'bg-slate-950/60 border-slate-900 text-slate-400 line-through'
                      : 'bg-slate-900/60 border-slate-800 text-slate-200 hover:border-cyan-500/30'
                  }`}
                >
                  {isDone ? (
                    <CheckSquare className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : (
                    <Square className="w-4 h-4 text-slate-500 shrink-0" />
                  )}
                  <span>
                    <strong>{language === 'zh-TW' ? `步驟 ${idx + 1}` : `Step ${idx + 1}`}:</strong> {stepText}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Isolation Action Trigger */}
          <div className="pt-4 border-t border-slate-900 flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">
              {t('copilot.emergencyTrigger', 'Emergency Action Trigger:')}
            </span>
            <button
              onClick={() => setShowSoarModal(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 font-mono text-xs font-bold transition-all"
            >
              <ShieldCheck className="w-4 h-4" /> {t('copilot.isolateHostBtn', 'Isolate Target Host DC-SRV-01')}
            </button>
          </div>
        </div>
      </div>

      <SoarActionModal
        isOpen={showSoarModal}
        initialData={{
          ip: '192.168.1.105',
          summary: activeTitle,
          severity: 'Critical',
          incidentId: 'INC-2026-001',
          mitreTechnique: 'T1059.001',
        }}
        onClose={() => setShowSoarModal(false)}
      />
    </div>
  );
}
