// ─── Data Honesty & Provenance Notice ──────────────────────────────────────────
// NOTE: 本檔案僅供 IOC 資料庫頁面之靜態參考資料使用，非即時遙測資料來源 (Referential Static Data Only)。
// 符合 CyberMind AI 作品集「資料誠實性原則」，避免靜態示範資料與即時生產遙測混淆。
// ─────────────────────────────────────────────────────────────────────────────



export const SAMPLE_IOC_LIST = [
  { ip: "185.220.101.5", type: "IP Address", threat: "Cobalt Strike C2 Node", confidence: 99, country: "RU", lastSeen: "2026-07-25 14:30", source: "AbuseIPDB / AlienVault" },
  { ip: "45.33.32.156", type: "IP Address", threat: "Masscan Port Scanner", confidence: 88, country: "US", lastSeen: "2026-07-25 14:11", source: "Shodan Intelligence" },
  { hash: "e2c569be17396eca2a2e30e19444bc9a10d0f507b5a5b5b292f7c00e12345678", type: "SHA256", threat: "LockBit 3.0 Ransomware Payload", confidence: 100, country: "Global", lastSeen: "2026-07-24 18:00", source: "VirusTotal" },
  { domain: "update-microsoft-auth.ru", type: "Domain", threat: "Credential Harvesting Phishing", confidence: 94, country: "RU", lastSeen: "2026-07-25 10:15", source: "Cisco Talos" }
];
