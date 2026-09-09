# CyberMind AI (Security-Engineering-Portfolio-Project) 專案體檢報告

**倉庫**: github.com/keanao115/Security-Engineering-Portfolio-Project
**分析方式**: 實際 clone 原始碼並檢視前後端邏輯(非僅讀 README)
**目的**: 作為資安求職作品集,列出需要修正的問題與優先順序

---

## 一、專案現況總覽

CyberMind AI 是一個模擬 SOC(資安維運中心)平台:

- **前端**: React + Vite,共 28 個元件、21 個導覽頁籤
- **後端**: Node.js + TypeScript,共 90 個原始碼檔案,分層為 adapters / collectors / parsers / services / routes
- **特色**: 支援 syslog、NetFlow、Windows Event Forwarding、pcap 等多種遙測來源解析,並整合 Google Gemini 做 AI 分析

**值得肯定的地方**:
- 後端有真實的協定解析邏輯(Windows/Linux log、Nmap、Suricata、Zeek、NetFlow),不是全空殼
- `PROJECT_RULES.md` 明確規定「不可捏造漏洞/CVE/ATT&CK 對應」,工程紀律意識好
- README 的「Truthful Implementation Status Matrix」誠實區分真實實作 vs Demo 模式,方向正確,值得延伸到整份文件

---

## 二、關鍵問題清單(依嚴重度排序)

### 🔴 1. 認證機制形同虛設(最高優先)

**位置**: `server/src/middleware/auth.ts`

```ts
export function authenticateJwt(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    // Default system fallback context for frontend API calls
    req.user = { id: 1, username: 'soc_analyst', role: 'Admin' };
    return next();
  }
  ...
}
```

**問題**: 請求沒帶 JWT token 時,程式不拒絕,而是直接把來源當成 `role: 'Admin'` 放行。等於任何人不需要登入就能以管理員身分呼叫所有受保護的 API。

**修正方向**:
- 沒有合法 token 時應該回傳 `401 Unauthorized`,不應該給予任何預設身分
- 前端若需要「未登入的訪客模式」,應該用明確、權限受限的 `role: 'Guest'`,而不是預設成 Admin
- 修完之後,建議在 README / 面試時主動提起「我發現並修復了預設放行的漏洞」,這是很好的資安故事,比藏著不提更有說服力

### 🔴 2. RBAC(角色權限)只是裝飾,沒有真的被強制執行

**位置**: `server/src/middleware/auth.ts` 定義了 `requireRole()`,但搜尋整個 `server/src/routes/` 目錄,沒有任何路由實際使用它。

**問題**: README 與 `PROJECT_RULES.md` 都宣稱「Enforce RBAC」,但實際上所有通過 JWT 驗證的使用者都能存取所有路由,沒有分級。

**修正方向**:
- 針對敏感操作(例如刪除資料、切換 LIVE/DEMO 模式、產生報告)加上 `requireRole(['Admin'])` 之類的限制
- 至少定義 2–3 種角色(Admin / Analyst / Viewer)並在路由上實際套用,展示你理解「最小權限原則」

### 🔴 3. Secret 寫死在程式碼裡

**位置**: `server/src/middleware/auth.ts`

```ts
const JWT_SECRET = process.env.JWT_SECRET || 'cybermind_soc_super_secret_jwt_key_2026';
```

**問題**: 即使沒設定環境變數,也會用這組寫死在原始碼裡的固定字串簽發 JWT。任何看過原始碼的人都能偽造合法 token。

**修正方向**:
- secret 永遠不該有預設值 fallback。啟動時若偵測不到 `JWT_SECRET` 環境變數,應該直接讓伺服器啟動失敗並印出明確錯誤訊息
- 可以額外加一個啟動檢查腳本,確保必要的環境變數都存在才允許服務啟動

### 🟠 4. Git 版本控管衛生問題

**現況**:
- 整個 repo 沒有 `.gitignore`
- `node_modules/`(165MB、21,000+ 個檔案)被整包 commit 進版本控制
- 前端 `dist/` 與後端 `server/dist/` 建置產物也被 commit
- `server/.env` 檔案本身被 commit(雖然目前敏感欄位是空的,但這個習慣本身在資安領域是大忌)

**修正方向**:
```gitignore
node_modules/
dist/
server/dist/
.env
*.log
```
- 把上述路徑加入 `.gitignore`,並用 `git rm -r --cached node_modules dist server/dist server/.env` 從版本歷史中清掉
- 只保留 `.env.demo.example` / `.env.live.example` 這種範本檔,不要保留真正的 `.env`

### 🟠 5. 「數據真實性」承諾與實作有落差

**位置**: `src/components/DashboardView.jsx`

```js
{ label: 'Overall Security Score', score: hasRealScan ? Math.max(60, 94 - openPortCount * 5) : 94, ... }
{ label: 'Network Protection', score: hasRealScan ? Math.max(50, 90 - openPortCount * 8) : 90, ... }
```

**問題**: 首頁展示的「Overall 94 / Network 90...」這些分數,基準值是寫死的魔術數字,再用一個簡單的線性公式(開放埠數 × 固定係數)微調,並非真正的風險評分模型。這與 `PROJECT_RULES.md` 裡「Never generate fictional vulnerabilities / Always explain uncertainty」的精神有落差。

**修正方向**:
- 若要保留評分機制,至少要能說明分數是怎麼算出來的(例如基於 CVSS 加權平均、已知漏洞數量、修補率等可解釋的公式),並在 UI 上標示「本分數為示範用簡化模型」
- 或者乾脆先移除評分卡片,換成「目前已知漏洞數 / 嚴重度分佈」這種可直接對應到真實資料的呈現方式

### 🟡 6. 測試與 CI/CD 幾乎空白

**現況**:
- 只有 3 個測試檔(`server/src/tests/*.test.ts`),使用 Node.js 內建的 `node:test`,沒有覆蓋率報告
- 沒有 `.github/workflows`,也就是沒有任何自動化 CI
- 但 `deploy/` 資料夾底下卻有完整的 Docker / Kubernetes / Prometheus / Grafana 設定 —— 部署基礎設施的成熟度跟測試基礎設施明顯不對稱

**修正方向**:
- 先加一個最基本的 GitHub Actions workflow,PR 時自動跑 `tsc --noEmit` + `npm test`
- 針對核心邏輯(例如 `sigmaRuleEngine.ts`、各種 log parser)補單元測試,這些是最容易寫也最能展示程式能力的部分

---

## 三、功能重複度分析:哪些該砍、哪些該合併

追蹤 `Sidebar.jsx` 的 21 個導覽頁籤與各元件實際的資料來源後,發現專案內其實**同時存在兩代功能**,大部分互相重複:

| 概念 | 舊版(純前端假資料,SOC NAVIGATION 分組) | 新版(真的打後端 API,LIVE MONITORING 分組) |
|---|---|---|
| 總覽儀表板 | Dashboard(分數是寫死的 94/90/88...) | Live Network Monitor |
| Log 分析 | Log Analyzer(解析 `sampleData.js` 裡的假 log) | SIEM Event Console / Zeek & Suricata IDS |
| 網路掃描 | Network Scanner(解析寫死的 `SAMPLE_NMAP_XML`) | Asset Discovery(真的呼叫後端 `nmapParser.ts`) |
| 威脅分析 | Threat Analysis(`src/utils/threatEngine.js` 前端跑簡化邏輯) | Investigation Timeline / Evidence Timeline |
| 漏洞掃描 | Vulnerability Scanner(0 個 API 呼叫,純展示) | 後端已有 `nvdCveService.ts` 真的串接 NVD CVE API,但前端這頁沒有接上 |

**根本原因**: 專案裡其實已經設計了一套很專業的解法 —— `src/contexts/PlatformModeContext.jsx`,用來切換 LIVE / DEMO 資料來源並顯示 provenance badge(README 第 7 節「Zero Fake Data 架構」講的就是這個)。但實際檢查發現,這個 context 目前只被 3 個小元件使用(`DemoWarningBanner`、`LiveEmptyState`、`PlatformModeBadge`),**完全沒有被拿來統一上面這些重複頁面**。也就是說,正確的架構已經存在,只是沒有被用在該用的地方。

### 具體處理建議

**直接刪除**(功能已被 Live 版取代,留著只會拖累可信度):
- Log Analyzer(前端純假資料版)
- Network Scanner(前端純假資料版)
- Threat Analysis(前端純假資料版)

**合併為單一頁面 + 資料來源開關**(用既有的 `PlatformModeContext` 驅動):
- Dashboard + Live Network Monitor → 一個首頁,`platformMode === 'LIVE'` 時打真實 API,否則顯示 DEMO badge + 說明性假資料
- Vulnerability Scanner → 改接後端已經寫好的 `nvdCveService.ts`,不要維持獨立的靜態展示頁

**保留,但需要清楚標示定位**:
- MITRE ATT&CK Matrix、IOC Database、RAG 知識庫:這幾個本質上是「參考資料庫」而非「即時資料」,不需要接即時 API,只要在 UI 上明確標示「靜態參考資料」即可,不算造假
- Attack Simulation(864 行,全部是寫死的劇本,沒有任何 API 呼叫):明確定位為「模擬 / 教學展示」,適合當面試 demo 的敘事工具,只要不與其他真實功能混在一起呈現即可保留
- AI Chat Assistant 與 SOC Copilot:兩者概念重疊(自由對話 vs 引導式 playbook),建議合併成一個「AI 助手」頁面,裡面用分頁籤區分「自由對話」與「事件應變 Playbook」,而不是兩個獨立的導覽項目

**目標**: 把 21 個導覽頁籤砍到 10 個以內,每一個都經得起「這是真的還是假的」這個問題。

---

## 四、優先順序路線圖

| 階段 | 項目 | 預估工作量 |
|---|---|---|
| Phase 1(必修,面試前一定要修) | 修正 auth 預設放行 Admin 的漏洞;移除 JWT_SECRET 硬編碼 fallback | 半天內可完成,影響最大 |
| Phase 2(結構清理) | 補 `.gitignore`,清掉 `node_modules` / `dist` / `.env` 的版本歷史;實際套用 `requireRole` 到敏感路由 | 1 天 |
| Phase 3(功能瘦身) | 砍掉 3 個純假資料前端頁面;把 Dashboard 與 Vulnerability Scanner 接上既有的 `PlatformModeContext` 與 `nvdCveService.ts` | 2–3 天 |
| Phase 4(工程成熟度) | 加最小 GitHub Actions CI(`tsc --noEmit` + `npm test`);為核心 parser / rule engine 補單元測試 | 2–3 天 |
| Phase 5(包裝) | 依照「Truthful Implementation Status Matrix」的精神,重新調整 README 用詞(拿掉「enterprise-grade」這類與實際規模不符的形容詞,誠實描述這是個人學習型專案) | 半天 |

**面試敘事建議**: 完成 Phase 1–2 之後,這兩個修復本身就是很好的面試素材 —— 「我在自己的資安專案裡發現並修復了一個認證繞過漏洞」遠比一個看起來完美但經不起檢視的 demo 更有說服力。
