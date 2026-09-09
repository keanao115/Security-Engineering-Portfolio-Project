# CyberMind AI — Security Engineering Portfolio Project

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Stack: React + Vite](https://img.shields.io/badge/Frontend-React%20%2B%20Vite-06b6d4)](https://vitejs.dev/)
[![Backend: Node.js + TypeScript](https://img.shields.io/badge/Backend-Node.js%20%2B%20TypeScript-3178c6)](https://www.typescriptlang.org/)
[![CI: GitHub Actions](https://img.shields.io/badge/CI-GitHub%20Actions-2088ff)](https://github.com/features/actions)
[![Security: RBAC Enforced](https://img.shields.io/badge/Security-Strict%20JWT%20%26%20RBAC-10b981)]()

**CyberMind AI** is a comprehensive, defensive security engineering platform and SOC (Security Operations Center) workspace designed for real-time telemetry ingestion, deep packet inspection, threat hunting, and automated incident response.

Built as a hands-on cybersecurity engineering portfolio, this project emphasizes **truthful telemetry implementation**, **transparent explainable risk scoring**, and **strict defense-in-depth principles**.

---

## 🌟 Core Functional Architecture

The platform provides 11 streamlined, high-value security modules divided into three operational categories:

### 1. 🛡️ SOC Operations & Telemetry (核心運維與遙測)
- **戰情總覽 (Executive Dashboard)**: 可解釋動態資安評分模型（基於 CVSS 加權公式）、即時 24 小時威脅向量時序圖與採集器健康狀態。
- **SIEM 即時事件主控台 (SIEM Event Console)**: 支援 Windows Event Forwarding (WEF)、Linux Syslog (RFC 3164/5424)、防火牆日誌的多來源統一日誌處理與關聯檢索。
- **主動資產發現與網路掃描 (Asset Discovery & Nmap)**: 串接後端真實 Nmap XML 解析、本機網卡介面枚舉、ARP 表與 Netstat 活躍連線分析。
- **弱點管理引擎 (Vulnerability Management & NVD API)**: 串接美國國家弱點資料庫 (NIST NVD) API v2.0，提供即時 CVE 檢索、CVSS v3.1 評估、CWE 分類與修補建議。
- **網路遙測與封包解構中心 (Network Telemetry & PCAP Hub)**: 整合 Npcap 即時網卡抓包 (BPF 過濾)、二進位 PCAP 上傳解構 (JA3/JA4 TLS 指紋) 與 NetFlow v5/v9/IPFIX 收集。
- **IDS 聯防與事件調查中心 (Threat Investigation Hub)**: 彙整 Zeek 協定日誌、Suricata EVE IDS 告警流與多來源事件時序關聯證據鏈 (Evidence Timeline)。

### 2. 🤖 AI Intelligence & Incident Response (AI 智能與事件處置)
- **AI 資安副手 (AI SOC Copilot & Playbooks)**: 整合 Google Gemini 1.5 Flash 自由研判對話與標準化資安事件處置應變 (Incident Response) 引導式劇本。
- **資安事件調查報告 (Incident Reports)**: 一鍵匯出符合 CISO 稽核規範的資安事件調查報告 (支援 PDF 輸出)。

### 3. 📚 Threat Intel & Controlled Simulation (情報知識與模擬演練)
- **威脅情報與防禦框架知識庫 (Threat Intel & MITRE ATT&CK)**: 明確標記之靜態情報參考庫，包含 MITRE ATT&CK 戰術矩陣、高危 IOC 清單與 RAG 知識庫。
- **攻擊演練情境模擬 (Attack Simulation)**: 受控情境演練劇本（暴力破解、混淆 PowerShell、勒索軟體行為與 SQL 注入）。
- **系統設定與存取控制 (Settings & RBAC)**: 支援即時切換 LIVE / DEMO 運行模式，並提供 Admin / Analyst / Viewer 權限即時驗證。

---

## 🛡️ Truthful Implementation Status Matrix

為落實 `PROJECT_RULES.md` 的資安誠信原則，本專案誠實區分真實實作與展示環境：

| 模組功能 | 實作狀態 | 數據來源 / 協定 | 處理路徑 |
|---|---|---|---|
| **Live Packet Capture** | **真實實作** | `LIVE_CAPTURE` (Npcap) | Raw Socket / BPF Frame Engine |
| **PCAP Binary Parser** | **真實實作** | `PCAP_UPLOAD` | 二進位 PCAP 解析器 / JA3/JA4 TLS 指紋 |
| **Zeek JSON Log Ingestion** | **真實實作** | `ZEEK_LOG` | JSON 中繼串流 (`conn`, `dns`, `ssl`) |
| **Suricata EVE IDS Ingestion** | **真實實作** | `SURICATA_EVE` | EVE JSON Alert 串流解析 |
| **Syslog RFC 3164 / 5424** | **真實實作** | `SYSLOG_COLLECTOR` | UDP 5514 / TCP 5515 專用 Receiver |
| **Windows Event Forwarding** | **真實實作** | `WEF_COLLECTOR` | HTTP 5516 WinRM XML 正規化引擎 |
| **NetFlow v5 / v9 / IPFIX** | **真實實作** | `NETFLOW_COLLECTOR` | UDP 2055 二進位流解碼器 |
| **NIST NVD CVE API** | **真實實作** | `NVD_API` | NIST 官方 REST API v2.0 (具 LRU 快取) |
| **Local Host Discovery** | **真實實作** | `OS_DISCOVERY` | 系統級 ARP 表、網卡、Netstat 連線 |
| **AI Threat Hunting** | **真實實作** | Google Gemini 1.5 Flash | REST API 整合 (具離線規則回退) |
| **Attack Simulation** | **受控劇本** | `SCENARIO_SIMULATION` | 教學與面試專用展示腳本 |

---

## 🔍 Security Audit & Engineering Remediation (資安體檢與工程演化歷程)

在專案演化過程中，我們主動實施全盤資安代碼審計（Code Audit），發現並徹底修復了數項關鍵架構弱點：

### 1. 徹底修復「未授權請求預設放行 Admin」漏洞 (P0)
- **問題現況**: 原先 `auth.ts` 中，若請求未攜帶 Bearer Token，程式會回退賦予 `role: 'Admin'` 並放行，形成嚴重的認證繞過安全隱患。
- **修復實作**: 移除任何預設身分放行機制，嚴格執行無 Token 或無效 Token 立即拒絕並回傳 `401 Unauthorized`；前端改採標準 JWT Bearer 注入機制。

### 2. 強制執行 RBAC 最小權限原則 (Least Privilege) (P1)
- **問題現況**: 原先各敏感路由缺乏角色存取控制，任何通過驗證的使用者均能執行高危操作。
- **修復實作**: 全面套用 `requireRole()` 中介軟體。模式切換與採集器生命週期限制 `Admin`；主動掃描、抓包與報告產製限制 `Admin` / `Analyst`；一般查詢開放 `Viewer`。並在前端提供動態角色切換器，可親自測試觸發 `403 Forbidden` 的防禦行為。

### 3. 根除硬編碼金鑰 (Secret Hygiene) (P0)
- **問題現況**: 原先 `JWT_SECRET` 寫死固定預設字串作為 fallback。
- **修復實作**: 移除寫死預設值。系統啟動時若偵測不到環境變數即拋出致命錯誤終止服務，杜絕金鑰偽造風險；提供 `.env.example` 規範配置。

### 4. Git 版本控制衛生清理 (Repository Hygiene) (P1)
- **問題現況**: 歷史版本曾錯誤追蹤 `node_modules/` (160MB+)、建置產物 `dist/` 與機密 `.env`。
- **修復實作**: 建立標準 `.gitignore`，使用 `git rm -r --cached` 從 Git 索引徹底移除追蹤（保留本機運作檔案），大幅瘦身倉庫。

### 5. 消除黑箱假數據，導入可解釋風險評分 (Data Authenticity) (P2)
- **問題現況**: 儀表板評分曾使用寫死的基線魔術數字進行簡單扣減。
- **修復實作**: 改用透明可解釋的 CVSS v3.1 加權模型：`Score = 100 - (Critical×18 + High×9 + Medium×3 + OpenPorts×2)`，並於 UI 清楚揭露計算邏輯，杜絕虛構數字。

### 6. 建置自動化 CI/CD 與完整單元測試 (P3)
- **問題現況**: 缺乏自動化持續整合測試管線。
- **修復實作**: 建立 GitHub Actions CI 工作流程（TypeScript 型別檢查、前後端建置、測試執行）；擴充包含 Auth/RBAC、NVD API 與遙測管線在內的 40 項自動化測試套件（100% 通過）。

---

## ⚡ Quick Start & Local Setup

### 1. 安裝前後端相依套件

```bash
# 安裝前端相依套件
npm install

# 安裝後端相依套件
npm --prefix server install
```

### 2. 配置環境變數

```bash
# 複製後端環境設定檔範本
cp server/.env.example server/.env
```
編輯 `server/.env`，設置您的 `JWT_SECRET`（生產/本機運行必填）及可選的 `GEMINI_API_KEY`。

### 3. 執行自動化測試與檢查

```bash
# 執行後端 40 項單元與資安測試
npm --prefix server test

# 驗證前端打包
npm run build
```

### 4. 啟動前後端服務

#### 方式 A：Windows 一鍵雙開腳本 (推薦)
直接在專案根目錄雙擊執行 [`start_all.bat`](file:///e:/IT/AI%20Project/Security%20Engineering%20Portfolio%20Project/start_all.bat) 即可自動檢查環境、安裝遺失相依套件並在獨立視窗啟動前後端服務：
```cmd
start_all.bat
```

#### 方式 B：手動分開啟動
```bash
# 啟動後端 SOC Telemetry Engine (Port 5000)
npm --prefix server run dev

# 另開終端機啟動前端戰情儀表板 (Port 3000)
npm run dev
```

瀏覽器訪問 `http://localhost:3000` 即可進入戰情主控台。右上角可隨時切換 `Admin`、`Analyst`、`Viewer` 角色以即時體驗 RBAC 存取控制。

---

## 📜 授權條款 (License)

本專案採用 **MIT License** 授權，歡迎作為資安工程研究、藍隊防禦演練與技術交流之用。
