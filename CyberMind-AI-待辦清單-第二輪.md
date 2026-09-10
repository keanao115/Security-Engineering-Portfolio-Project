# CyberMind AI 專案待辦清單(第二輪複查後)

**版本**: 針對使用者上傳的 `Security-Engineering-Portfolio-Project-main.zip`(第一輪回饋後的修改版)
**性質**: 本文件只列「還需要處理」的項目,不重複列已經修好的部分(已修好的項目見文末附錄)

---

## 一、🔴 最高優先:未授權存取漏洞(新發現)

**位置**: `server/src/index.ts`,第 166–167 行

```ts
app.use('/api/threats', authenticateJwt, threatRouter);   // 有驗證
app.use('/api/scan', threatRouter);                       // 相容性路由 — 沒有驗證！
```

**問題說明**:
`threatRouter` 被掛載了兩次。`/api/threats/*` 有 `authenticateJwt` 保護,但同一個 router 又以「相容性路由」的名義掛在 `/api/scan/*`,完全沒有任何驗證中介層。這代表以下兩個端點任何人不需要登入就能呼叫:

- `POST /api/scan/analyze` — 直接呼叫 Gemini AI 分析服務,沒有速率限制以外的任何存取控制,可能被拿來耗盡你的 API 額度
- `GET /api/scan/scan?target=<任意主機>` — 對使用者指定的任意 host 做 TCP port scan(涵蓋 21/22/23/25/53/80/110/135/139/143/443/445/1433/1521/3306/3389/5432/6379/8080 等埠),沒有對 `target` 做任何白名單或內網位址過濾

**風險**:
1. 未授權即可消耗你的 AI API 額度(成本風險)
2. `target` 參數沒有過濾,理論上可以把你的伺服器當成掃描跳板去探測其他內網主機(SSRF / 掃描代理風險),這對一個「安全工程」專案來說是相當諷刺的漏洞類型

**修正方式(擇一)**:
```ts
// 方案 A:直接補上驗證,與 /api/threats 一致
app.use('/api/scan', authenticateJwt, threatRouter);

// 方案 B(建議):既然 /api/threats 已經是正式路徑,直接刪掉這個相容性掛載
// app.use('/api/scan', threatRouter);  // 移除此行
```
若刪除會影響前端還在呼叫 `/api/scan` 的地方,先用 `grep -rn "/api/scan" src/` 確認前端呼叫點,一併改成 `/api/threats`。

---

## 二、🟡 中優先:RBAC 覆蓋範圍不完整

目前 `requireRole()` 只套用在 5 個路由檔案(`collectorRoutes`、`platformRoutes`、`discoveryRoutes`、`captureRoutes`、`reportRoutes`)。以下路由檔案目前只要求「登入」,沒有角色區分,建議逐一檢視是否有需要限制角色的操作:

| 路由檔案 | 建議檢視的操作 |
|---|---|
| `ingestRoutes.ts` | `POST /logs`、`POST /nmap`、`POST /zap`、`POST /sigma/scan` — 誰能把外部資料餵進系統,建議至少限 `Admin`/`Analyst` |
| `vulnerabilityRoutes.ts` | `POST /lookup` 若會觸發外部 NVD API 呼叫,建議限制角色避免被濫用查詢額度 |
| `aiRoutes.ts` | `POST /chat`、`POST /analyze`、`POST /test-connection` — 同樣涉及 AI API 成本,建議至少限已登入角色都可用,但 `test-connection`(可能觸及金鑰設定)建議限 `Admin` |
| `assetRoutes.ts`、`networkFlowRoutes.ts`、`packetRoutes.ts`、`siemRoutes.ts`、`suricataRoutes.ts`、`zeekRoutes.ts`、`investigationRoutes.ts`、`pipelineRoutes.ts` | 目前以「讀取為主」的端點維持 Viewer 也能看是合理的,但若裡面有刪除/清空/設定類操作,建議個別加上 `requireRole(['Admin'])` |

**建議做法**: 不需要每個都改,但至少把「會寫入資料、觸發外部 API 呼叫、或改變系統設定」的端點加上角色限制,純讀取的端點維持現狀即可。這樣可以在面試時清楚說明你的角色分級邏輯,而不是全有全無。

---

## 三、🟡 中優先:待確認/待註記的設計決策

**`server/src/routes/platformRoutes.ts` 第 13 行**:
```ts
platformRouter.get('/status', (_req: Request, res: Response) => { ... });
```
這個端點沒有掛 `authenticateJwt`,而同檔案的 `/mode` 和 `/audit-logs` 都有驗證。如果 `/status` 是刻意設計成公開的健康檢查端點(給監控系統用),沒有問題,但建議:
1. 確認回傳內容不包含敏感資訊(例如內部設定、使用者清單等)
2. 在程式碼加一行註解明講「此端點刻意公開,供健康檢查使用」,避免日後被誤認為遺漏

---

## 四、🟢 低優先:程式碼清理

以下檔案在新版導覽結構精簡後,已經沒有任何元件引用,屬於死碼,可以直接刪除以保持專案乾淨:

- `src/utils/logParsers.js`(舊版 Log Analyzer 專用,已無引用)
- `src/utils/threatEngine.js`(舊版 Threat Analysis 專用,已無引用)

確認方式:
```bash
grep -rl "logParsers\|threatEngine" src/components src/App.jsx
```
若指令沒有回傳結果,代表確實無人引用,可安全刪除。

`src/data/sampleData.js` 目前只被 `IocDatabaseView.jsx` 使用(作為靜態參考資料),這個用途合理,不需要刪除,但建議在檔案開頭加註解說明「本檔案僅供 IOC 資料庫頁面之靜態參考資料使用,非即時資料來源」,呼應專案本身強調的資料誠實性原則。

---

## 五、驗收清單

修改完成後,逐項確認:

- [ ] `/api/scan` 已加上驗證或已移除,且前端沒有殘留呼叫舊路徑
- [ ] `ingestRoutes.ts`、`aiRoutes.ts`、`vulnerabilityRoutes.ts` 中會寫入資料或觸發外部 API 的端點,已評估並視需要加上 `requireRole`
- [ ] `platformRoutes.ts` 的 `/status` 端點行為已確認並加上說明註解
- [ ] `logParsers.js`、`threatEngine.js` 已刪除(或確認保留理由)
- [ ] CI(`.github/workflows/ci.yml`)重新跑過一次,確保上述修改沒有破壞現有測試
- [ ] 針對 `/api/scan` 這個漏洞,補一個類似 `auth_rbac.test.ts` 的回歸測試,驗證未授權請求會被拒絕

---

## 附錄:第一輪回饋已修復項目(供紀錄)

以下項目在這一版已確認修復,不需要再處理:

- Auth 中介層不再於缺少 token 時預設放行 Admin,改為回傳 401
- `JWT_SECRET` 不再有硬編碼 fallback,未設定時直接拒絕啟動(測試環境除外)
- `.gitignore` 已正確排除 `node_modules`、`dist`、`.env`
- Dashboard 分數改為基於真實漏洞數與開放埠數的透明公式,不再是寫死數字
- Vulnerability Scanner 已串接真實的 NVD CVE 服務
- 導覽頁籤從 21 個精簡到 11 個,移除純假資料的 Log Analyzer / Network Scanner / Threat Analysis,並以資料來源標籤(PROD/NPCAP/EVE/REF/DEMO)標示真實性
- 已建立 GitHub Actions CI(前後端 build + test),測試檔案從 3 個增加到 5 個,並新增針對認證與 RBAC 的專屬回歸測試
