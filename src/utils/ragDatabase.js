// RAG Knowledge Base Database & Search Engine (Bilingual: zh-TW / en-US)

export const RAG_KNOWLEDGE_BASE = [
  {
    id: "NIST-800-61",
    category: {
      "zh-TW": "資安標準規範",
      "en-US": "Security Standard"
    },
    title: {
      "zh-TW": "NIST SP 800-61 Rev. 2: 電腦資安事件處置指南",
      "en-US": "NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide"
    },
    summary: {
      "zh-TW": "資安事件應變標準生命週期架構：準備階段、偵測與分析、遏阻根除與復原、事後檢討活動。",
      "en-US": "Standard framework for incident response lifecycle: Preparation, Detection & Analysis, Containment Eradication & Recovery, Post-Incident Activity."
    },
    content: {
      "zh-TW": "遏阻策略因事件類型而異（例如：隔離受害主機、停用受入侵帳號、於周界防火牆阻擋惡意 IP 網段）。根除階段包含刪除惡意程式碼、重設受害憑證並修補弱點。",
      "en-US": "Containment strategies vary by incident type (e.g. isolating endpoints, disabling compromised user accounts, blocking IP ranges at perimeter firewall). Eradication includes deleting malware, disabling compromised accounts, and closing vulnerabilities."
    }
  },
  {
    id: "WIN-4625",
    category: {
      "zh-TW": "Windows 事件日誌",
      "en-US": "Windows Event"
    },
    title: {
      "zh-TW": "事件 ID 4625：帳戶登入失敗 (An account failed to log on)",
      "en-US": "Event ID 4625: An account failed to log on"
    },
    summary: {
      "zh-TW": "當使用者因密碼錯誤、帳號被鎖定或權限不足導致登入失敗時於本機或網域控制器觸發。",
      "en-US": "Generated on domain controllers or local workstations when a user attempt fails due to bad credentials, locked account, or expired login."
    },
    content: {
      "zh-TW": "關鍵稽核欄位：TargetUserName (目標帳號)、WorkstationName (工作站)、IpAddress (來源 IP)、FailureReason (失敗原因碼：0xC000006A 密碼錯誤、0xC0000234 帳號遭鎖定)。短時間高頻率發生通常代表 RDP / SMB 暴力破解攻擊。",
      "en-US": "Key fields to audit: TargetUserName, WorkstationName, IpAddress, FailureReason (0xC000006A = bad password, 0xC0000072 = account disabled, 0xC0000234 = account locked out). High frequency indicates RDP or SMB brute force attacks."
    }
  },
  {
    id: "WIN-4688",
    category: {
      "zh-TW": "Windows 事件日誌",
      "en-US": "Windows Event"
    },
    title: {
      "zh-TW": "事件 ID 4688：新處理程序已建立 (A new process has been created)",
      "en-US": "Event ID 4688: A new process has been created"
    },
    summary: {
      "zh-TW": "記錄處理程序啟動詳細資訊。透過 GPO 啟用「包含命令列資訊」時具備極高資安鑑識價值。",
      "en-US": "Logs process execution details. Extremely valuable when Command Line Auditing is enabled via GPO."
    },
    content: {
      "zh-TW": "重點關注可疑的父子行程關聯（例如：cmd.exe 啟動 powershell.exe、winword.exe 啟動 cmd.exe、wmiprvse.exe 執行帶有 -enc 或 -nop 之 PowerShell 命令列）。",
      "en-US": "Look for suspicious parent-child process relationships (e.g., cmd.exe launching powershell.exe, winword.exe launching cmd.exe, wmiprvse.exe launching powershell.exe with -enc or -nop)."
    }
  },
  {
    id: "MITRE-T1110",
    category: {
      "zh-TW": "MITRE ATT&CK 手法",
      "en-US": "MITRE ATT&CK"
    },
    title: {
      "zh-TW": "T1110: 密碼暴力破解 (Brute Force)",
      "en-US": "T1110: Brute Force"
    },
    summary: {
      "zh-TW": "攻擊者在密碼未知的情況下，透過自動化工具進行重複嘗試以獲取帳號存取權限。",
      "en-US": "Adversaries may use brute force tactics to gain access to accounts when passwords are unknown."
    },
    content: {
      "zh-TW": "子手法包含：T1110.001 密碼猜測、T1110.002 密碼破解、T1110.003 密碼噴灑 (Password Spraying)、T1110.004 撞庫攻擊。防護建議：強制多因素驗證 (MFA) 與帳號鎖定閾值機制。",
      "en-US": "Techniques: T1110.001 Password Guessing, T1110.002 Password Cracking, T1110.003 Password Spraying, T1110.004 Credential Stuffing. Mitigation: Multi-Factor Authentication (MFA), account lockout threshold."
    }
  },
  {
    id: "MITRE-T1059",
    category: {
      "zh-TW": "MITRE ATT&CK 手法",
      "en-US": "MITRE ATT&CK"
    },
    title: {
      "zh-TW": "T1059: 命令與指令碼直譯器濫用 (Command & Scripting Interpreter)",
      "en-US": "T1059: Command and Scripting Interpreter"
    },
    summary: {
      "zh-TW": "攻擊者濫用系統內建之指令碼環境執行任意指令或下載外部遠端載荷。",
      "en-US": "Adversaries may abuse command and script interpreters to execute arbitrary commands or malicious stagers."
    },
    content: {
      "zh-TW": "子手法：T1059.001 PowerShell、T1059.003 Windows 命令提示字元、T1059.004 Unix Shell。防護建議：啟用 Script Block Logging、約束語言模式 (Constrained Language Mode) 與 AMSI 整合防護。",
      "en-US": "Sub-techniques: T1059.001 PowerShell, T1059.003 Windows Command Shell, T1059.004 Unix Shell. Mitigation: Script Block Logging, Constrained Language Mode, AMSI."
    }
  },
  {
    id: "OWASP-A01",
    category: {
      "zh-TW": "OWASP Top 10",
      "en-US": "OWASP Top 10"
    },
    title: {
      "zh-TW": "A01:2021 - 權限控制失效 (Broken Access Control)",
      "en-US": "A01:2021 - Broken Access Control"
    },
    summary: {
      "zh-TW": "系統未嚴格限制使用者操作範圍，導致一般帳戶得以存取未授權之機密功能或資料。",
      "en-US": "Failures that allow users to act outside of their intended permissions."
    },
    content: {
      "zh-TW": "常見範例：水平/垂直權限提升、修改 URL 參數繞過存取檢查、目錄遍歷。防禦建議：實施最小權限原則 (Least Privilege) 與伺服器端嚴格存取控管清單。",
      "en-US": "Examples: Elevation of privilege, bypassing access checks by modifying URL or request state, viewing someone else's account. Mitigation: Enforce least privilege, disable directory listing."
    }
  },
  {
    id: "OWASP-A03",
    category: {
      "zh-TW": "OWASP Top 10",
      "en-US": "OWASP Top 10"
    },
    title: {
      "zh-TW": "A03:2021 - 注入式攻擊 (Injection: SQLi, XSS, Command)",
      "en-US": "A03:2021 - Injection (SQLi, XSS, Command)"
    },
    summary: {
      "zh-TW": "應用程式未對使用者輸入之惡意字串進行足夠驗證與過濾，導致直接在後端直譯器被當作指令執行。",
      "en-US": "User-supplied data is not validated, filtered, or sanitized by the application before execution."
    },
    content: {
      "zh-TW": "SQL 注入發生於動態字串拼接 SQL 查詢。防禦建議：強制使用參數化查詢 (Parameterized Queries / Prepared Statements) 與輸入白名單正規表達式過濾。",
      "en-US": "SQL Injection occurs when untrusted input is concatenated into dynamic SQL queries. Mitigation: Parameterized queries / Prepared statements, Input validation regex."
    }
  }
];

export function searchRagKnowledge(query, language = 'zh-TW') {
  const langKey = language === 'en-US' ? 'en-US' : 'zh-TW';
  
  const localizedData = RAG_KNOWLEDGE_BASE.map(item => ({
    id: item.id,
    category: typeof item.category === 'object' ? (item.category[langKey] || item.category['zh-TW']) : item.category,
    title: typeof item.title === 'object' ? (item.title[langKey] || item.title['zh-TW']) : item.title,
    summary: typeof item.summary === 'object' ? (item.summary[langKey] || item.summary['zh-TW']) : item.summary,
    content: typeof item.content === 'object' ? (item.content[langKey] || item.content['zh-TW']) : item.content,
  }));

  if (!query || query.trim() === "") return localizedData;
  const q = query.toLowerCase();

  return localizedData.filter(item => 
    item.title.toLowerCase().includes(q) ||
    item.summary.toLowerCase().includes(q) ||
    item.category.toLowerCase().includes(q) ||
    item.content.toLowerCase().includes(q) ||
    item.id.toLowerCase().includes(q)
  );
}
