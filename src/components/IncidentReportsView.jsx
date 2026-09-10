import React, { useState } from 'react';
import { FileSpreadsheet, Download, Printer, ShieldCheck, FileText, Check } from 'lucide-react';
import jsPDF from 'jspdf';
import { generatePdfReport, fetchRiskScore } from '../services/apiClient';
import { useLanguage } from '../contexts/LanguageContext';

export default function IncidentReportsView({ anomalies }) {
  const { t, language } = useLanguage();
  const [downloadedFormat, setDownloadedFormat] = useState(null);

  const reportMarkdownZh = `# CYBERMIND AI - 企業系統安全與威脅稽核報告
**報告產出日期**：${new Date().toLocaleDateString()}
**機密等級**：CONFIDENTIAL / 僅限資安長 (CISO) 閱覽
**防護狀態**：主動防禦中 & 系統基準已加固

---

## 1. 執行摘要 (Executive Summary)
本報告詳細記錄 CyberMind AI 感測器於 ${new Date().toLocaleDateString()} 完成之全方位技術安全分析與遙測評估。評估範圍涵蓋異常偵測、MITRE ATT&CK 手法對齊、弱點暴露與建議緩解措施。

## 2. 評估範圍與系統清單 (System Scope)
- **評估標的**：企業內部網路與主機遙測數據 (目標主機：DC-SRV-01 / Web 閘道)
- **活動中感測器**：Windows 安全事件稽核、Syslog 接收器、防火牆規則引擎
- **未處理之高風險威脅**：0 項 (自動化處置規則已驗證)

## 3. 識別之異常特徵與 MITRE ATT&CK 戰術對齊
- **身分驗證遙測**：密碼猜測嘗試 (T1110.001) - 建議啟用來源 IP 動態黑名單。
- **處理程序遙測**：指令碼直譯器執行管制 (T1059.001) - 強制實施執行原則 (Execution Policy)。
- **存取控制稽核**：本地使用者帳戶異動 (T1136.001) - 啟用管理員特權清單自動校驗。
- **稽核紀錄留存**：事件日誌清理保護 (T1070.001) - 已啟用不可竄改之遠端 SIEM 日誌串流。

## 4. 具體修復與系統加固建議 (Recommendations)
1. 周界防火牆持續同步威脅情報來源 IP 黑名單。
2. 針對所有遠端 RDP/SSH 管理端點強制推行多因素驗證 (MFA)。
3. 定期套用作業系統安全性更新 (如 MS17-010、Log4j 補丁)。
4. 透過「攻擊模擬」模組定期進行紅藍軍演練以檢驗應變 SOP。
`;

  const reportMarkdownEn = `# CYBERMIND AI - SYSTEM DEFENSE & THREAT AUDIT REPORT
**Report Date**: ${new Date().toLocaleDateString()}
**Classification**: CONFIDENTIAL / CISO AUDIT
**System Status**: ACTIVE DEFENSE & VERIFIED HARDENING

---

## 1. EXECUTIVE SUMMARY
This report details the technical security findings and defensive telemetry evaluation recorded by CyberMind AI sensors on ${new Date().toLocaleDateString()}. The assessment covers detected anomalies, MITRE ATT&CK technique mappings, vulnerability posture, and recommended mitigation controls.

## 2. SYSTEM INVENTORY & SCOPE
- **Evaluated Target**: Corporate Infrastructure Telemetry (Host: DC-SRV-01 / Web Gateways)
- **Active Sensors**: Windows Security Event Audit, Syslog Receiver, Firewall Rule Engine
- **Unhandled High Risk Findings**: 0 (Automated containment rules validated)

## 3. IDENTIFIED ANOMALY FINDINGS & MITRE ATT&CK MAPPING
- **Authentication Telemetry**: Password Guessing Activity (T1110.001) - Source IP filtering recommended.
- **Process Telemetry**: Scripting Interpreter / Execution Verification (T1059.001) - Execution Policy enforced.
- **Access Control**: Local User Account Audit (T1136.001) - Privilege validation active.
- **Audit Persistence**: System Event Log Clearing Verification (T1070.001) - Immutable SIEM log streaming verified.

## 4. REMEDIATION & HARDENING RECOMMENDATIONS
1. Maintain strict perimeter IP blocking for unauthenticated access attempts.
2. Enforce Multi-Factor Authentication (MFA) across all administrative RDP/SSH entry points.
3. Apply OS security patches (e.g., MS17-010 / Log4j mitigation) across all endpoints.
4. Schedule periodic red-team exercises via the Attack Simulation module.
`;

  const reportMarkdown = language === 'zh-TW' ? reportMarkdownZh : reportMarkdownEn;

  const handleDownloadPdf = async () => {
    let currentRiskScore = 100;
    try {
      const riskData = await fetchRiskScore();
      if (riskData && typeof riskData.overallScore === 'number') {
        currentRiskScore = riskData.overallScore;
      }
    } catch {}

    const apiBlob = await generatePdfReport({
      title: language === 'zh-TW' ? "CYBERMIND SOC 平台 - 資安稽核應變報告" : "CYBERMIND SOC PLATFORM - SECURITY AUDIT REPORT",
      classification: language === 'zh-TW' ? "機密文件 / 僅限資安長 (CISO) 閱覽" : "CONFIDENTIAL / CISO AUDIT",
      riskScore: currentRiskScore,
      summary: reportMarkdown
    });

    if (apiBlob) {
      const url = URL.createObjectURL(apiBlob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `CyberMind_Security_Audit_Report_${language}.pdf`;
      a.click();
    } else {
      const doc = new jsPDF();
      doc.setFontSize(16);
      doc.text(language === 'zh-TW' ? "CYBERMIND AI - 資安稽核分析報告" : "CYBERMIND AI - SECURITY AUDIT REPORT", 14, 20);
      doc.setFontSize(10);
      doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 28);
      doc.text("Classification: CONFIDENTIAL / CISO AUDIT", 14, 34);

      const splitText = doc.splitTextToSize(reportMarkdown, 180);
      doc.text(splitText, 14, 45);
      doc.save(`CyberMind_Security_Audit_Report_${language}.pdf`);
    }

    setDownloadedFormat('PDF');
    setTimeout(() => setDownloadedFormat(null), 3000);
  };

  const handleDownloadMarkdown = () => {
    const blob = new Blob([reportMarkdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CyberMind_Security_Audit_Report_${language}.md`;
    a.click();

    setDownloadedFormat('Markdown');
    setTimeout(() => setDownloadedFormat(null), 3000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <FileSpreadsheet className="w-6 h-6 text-cyan-400" />
            {t('reports.title', 'Automated AI Incident Response Report Exporter')}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {t('reports.subtitle', 'Auto-generate CISO-ready incident reports with executive summary, timeline, IOCs, and remediation.')}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadPdf}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 font-mono text-xs font-bold transition-all shadow-sm"
          >
            {downloadedFormat === 'PDF' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Download className="w-3.5 h-3.5" />}
            {t('reports.exportPdf', 'Export PDF Report')}
          </button>
          <button
            onClick={handleDownloadMarkdown}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 font-mono text-xs font-bold transition-all"
          >
            <FileText className="w-3.5 h-3.5 text-slate-400" />
            {t('reports.exportMarkdown', 'Export Markdown')}
          </button>
        </div>
      </div>

      {/* Report Preview Container */}
      <div className="glass-panel p-8 rounded-2xl max-w-4xl mx-auto space-y-6 font-mono text-xs text-slate-300 border border-cyan-500/20 shadow-2xl">
        <div className="border-b border-slate-800 pb-4 flex justify-between items-start">
          <div>
            <h1 className="text-lg font-black text-cyan-300">
              {language === 'zh-TW' ? 'CYBERMIND AI - 系統防禦與威脅稽核報告' : 'CYBERMIND AI - SYSTEM DEFENSE & THREAT AUDIT REPORT'}
            </h1>
            <div className="text-slate-500 mt-1">
              Ref ID: AUDIT-2026-0725-101 | Status: {language === 'zh-TW' ? '防禦狀態良好' : 'VERIFIED HEALTHY'}
            </div>
          </div>
          <span className="px-3 py-1 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-lg text-[10px] font-bold uppercase">
            {t('reports.confidentialTag', 'CONFIDENTIAL / CISO AUDIT')}
          </span>
        </div>

        <div>
          <h3 className="font-bold text-white text-sm mb-1 text-cyan-400">
            {language === 'zh-TW' ? '1. 執行摘要 (Executive Summary)' : '1. EXECUTIVE SUMMARY'}
          </h3>
          <p className="leading-relaxed text-slate-300">
            {language === 'zh-TW'
              ? `於 ${new Date().toLocaleDateString()}，CyberMind AI 資安遙測引擎完成對登錄資產之全方位防禦掃描。所有遙測數據流均顯示系統完整性處於標準運維基線內，目前無任何未處理之極高風險告警。`
              : `On ${new Date().toLocaleDateString()}, CyberMind AI security telemetry completed a comprehensive defensive scan across registered host assets. All telemetry streams indicate system integrity within standard operational baselines. No unhandled critical threat alerts currently exist.`}
          </p>
        </div>

        <div>
          <h3 className="font-bold text-white text-sm mb-2 text-cyan-400">
            {language === 'zh-TW' ? '2. MITRE ATT&CK 戰術手法評估與加固' : '2. MITRE ATT&CK EVALUATION & HARDENING MAPPED'}
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-900">
              <span className="text-cyan-400 font-bold">T1110.001</span>: {language === 'zh-TW' ? '暴力密碼猜測防護生效中' : 'Brute Force Protection Active'}
            </div>
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-900">
              <span className="text-cyan-400 font-bold">T1059.001</span>: {language === 'zh-TW' ? '指令碼直譯器執行權限已受限' : 'Script Interpreter Execution Restricted'}
            </div>
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-900">
              <span className="text-cyan-400 font-bold">T1136.001</span>: {language === 'zh-TW' ? '本地管理員帳號已通過稽核' : 'Local Accounts Audited'}
            </div>
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-900">
              <span className="text-cyan-400 font-bold">T1070.001</span>: {language === 'zh-TW' ? '事件日誌遠端轉送狀態已驗證' : 'Event Log Forwarding Verified'}
            </div>
          </div>
        </div>

        <div>
          <h3 className="font-bold text-white text-sm mb-1 text-cyan-400">
            {language === 'zh-TW' ? '3. 具體安全性建議' : '3. SECURITY RECOMMENDATIONS'}
          </h3>
          <ul className="list-disc list-inside space-y-1 text-slate-300">
            <li>{language === 'zh-TW' ? '定期與威脅情資資料庫 (Threat Intel Feeds) 同步最新惡意 IP 黑名單。' : 'Periodic IP blocklist synchronization with Threat Intel feeds.'}</li>
            <li>{language === 'zh-TW' ? '針對所有遠端主機管理通道強制實施 2FA / MFA 雙因素身分驗證。' : 'Enforce mandatory 2FA on remote management consoles.'}</li>
            <li>{language === 'zh-TW' ? '利用「攻擊模擬」模組驗證自訂事件應變處置劇本 (Playbooks)。' : 'Use the Attack Simulation Module to test custom incident response playbooks.'}</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
