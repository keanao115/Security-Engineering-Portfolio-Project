import React, { useState } from 'react';
import { Grid, ShieldAlert, CheckCircle, Info, Zap, Terminal, Activity, FileCode, Server } from 'lucide-react';
import { useLanguage } from '../contexts/LanguageContext';

const TACTICS_DATA = [
  {
    nameZh: '偵察 (Reconnaissance)',
    nameEn: 'Reconnaissance',
    techniques: [
      {
        id: 'T1595',
        nameZh: '主動掃描 (Active Scanning)',
        nameEn: 'Active Scanning',
        tacticZh: '偵察階段',
        tacticEn: 'Reconnaissance',
        ports: [80, 443, 3389, 445, 22, 21, 53, 8080],
        descZh: '攻擊者針對目標 IP 網段發起自動化 TCP SYN/Connect 連線埠掃描或弱點探測，以識別活動中的網路服務與存在漏洞的監聽處理程序。',
        descEn: 'Adversaries execute automated TCP SYN/Connect port scans or vulnerability probing against host IP ranges to identify active network services and vulnerable listening daemons.',
        logSourcesZh: '網路防火牆日誌、路由器 NetFlow、IDS/IPS TCP 握手遙測',
        logSourcesEn: 'Network Firewall Logs, Router NetFlow, IDS/IPS TCP Handshake Telemetry',
        mitigationZh: '實施連線速率限制 (Rate-Limiting)、部署網站應用程式防火牆 (WAF)、動態阻擋惡意掃描 IP 網段。',
        mitigationEn: 'Implement Rate-Limiting, Deploy Web Application Firewall (WAF), block scanning IP ranges.',
        detectionRule: 'Sigma: Selection port_scan_threshold > 50 connections/min'
      },
      {
        id: 'T1592',
        nameZh: '收集主機資訊 (Gather Host Info)',
        nameEn: 'Gather Host Info',
        tacticZh: '偵察階段',
        tacticEn: 'Reconnaissance',
        ports: [80, 443, 8080],
        descZh: '攻擊者收集目標主機系統架構、作業系統核心版本、活動軟體 Banner 標頭與主機名稱命名規則。',
        descEn: 'Adversaries collect details about target host system architecture, operating system kernel build, active software banner headers, and hostname structures.',
        logSourcesZh: '網頁伺服器存取日誌、Banner 擷取遙測、DNS 查詢紀錄',
        logSourcesEn: 'Web Server Access Logs, Banner Grabbing Telemetry, DNS Queries',
        mitigationZh: '停用詳細之 HTTP Server 標頭回傳 (例如 Server: Apache/2.4.41)。',
        mitigationEn: 'Disable verbose HTTP Server response headers (e.g. Server: Apache/2.4.41).',
        detectionRule: 'Sigma: HTTP Request User-Agent contains Nmap / Masscan / Nikto'
      }
    ]
  },
  {
    nameZh: '初始存取 (Initial Access)',
    nameEn: 'Initial Access',
    techniques: [
      {
        id: 'T1190',
        nameZh: '利用公開應用程式漏洞 (Exploit Public App)',
        nameEn: 'Exploit Public App',
        tacticZh: '初始存取',
        tacticEn: 'Initial Access',
        ports: [80, 443, 8080, 8443],
        descZh: '攻擊者利用公開 Web 應用程式之軟體漏洞、未修補 CVE 或輸入驗證缺陷 (如 SQLi、RCE、Log4Shell)。',
        descEn: 'Adversaries exploit software vulnerabilities, unpatched CVEs, or input parameter flaws (SQLi, RCE, Log4Shell) in public-facing web applications.',
        logSourcesZh: 'Nginx / Apache HTTP 存取日誌、WAF 攔截稽核紀錄',
        logSourcesEn: 'Nginx / Apache HTTP Access Logs, WAF Interception Audit Logs',
        mitigationZh: '建立修補程式管理 SLA、強制輸入驗證與過濾、啟用 ModSecurity WAF 防護規則。',
        mitigationEn: 'Apply patch management SLAs, enforce input sanitization, enable ModSecurity WAF rules.',
        detectionRule: 'Snort: alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 80 (msg:"SQLi Attempt";)'
      },
      {
        id: 'T1566',
        nameZh: '釣魚郵件 (Phishing)',
        nameEn: 'Phishing',
        tacticZh: '初始存取',
        tacticEn: 'Initial Access',
        ports: [25, 587, 993],
        descZh: '發送帶有惡意 Office 巨集附件或憑證竊取連結的魚叉式釣魚郵件，以在企業內部端點獲得初始執行權限。',
        descEn: 'Adversaries send spear-phishing emails containing malicious document attachments or credential harvesting links to obtain initial execution on internal endpoints.',
        logSourcesZh: '電子郵件閘道日誌、附件沙箱分析報告、郵件伺服器稽核',
        logSourcesEn: 'Email Gateway Logs, Attachment Sandbox Reports, Mail Server Audit',
        mitigationZh: '強制實施 SPF/DKIM/DMARC 驗證政策，於郵件閘道封鎖高危險附件副檔名 (.exe, .vbs, .ps1)。',
        mitigationEn: 'Enforce SPF/DKIM/DMARC policies, block dangerous email attachment extensions (.exe, .vbs, .ps1).',
        detectionRule: 'Yara: rule Phishing_Macro_Doc { strings: $a = "AutoOpen" condition: $a }'
      }
    ]
  },
  {
    nameZh: '執行 (Execution)',
    nameEn: 'Execution',
    techniques: [
      {
        id: 'T1059.001',
        nameZh: 'PowerShell 下載載荷 (PowerShell Stager)',
        nameEn: 'PowerShell Stager',
        tacticZh: '執行階段',
        tacticEn: 'Execution',
        ports: [],
        descZh: '濫用 powershell.exe 命令列直譯器執行 Base64 編碼載荷、下載二階段木馬或於記憶體中進行反射式 DLL 注入。',
        descEn: 'Adversaries abuse powershell.exe command-line interpreter to run Base64 encoded stagers, download secondary payloads, or perform in-memory DLL injection.',
        logSourcesZh: 'Windows 安全事件 ID 4688、PowerShell 腳本區塊記錄事件 ID 4104',
        logSourcesEn: 'Windows Security Event ID 4688, PowerShell Script Block Logging Event ID 4104',
        mitigationZh: '強制施行約束語言模式 (Constrained Language Mode)，要求 AppLocker / WDAC 程式碼簽章驗證。',
        mitigationEn: 'Enforce Constrained Language Mode, require AppLocker / WDAC binary code signing.',
        detectionRule: 'Sigma: CommandLine contains "-ExecutionPolicy Bypass" or "-enc"'
      },
      {
        id: 'T1059.003',
        nameZh: 'Windows 命令提示字元執行 (Cmd Execution)',
        nameEn: 'Windows Cmd Execution',
        tacticZh: '執行階段',
        tacticEn: 'Execution',
        ports: [],
        descZh: '利用命令提示字元 cmd.exe 執行系統環境探測指令、批次檔或由惡意 Office 巨集衍生之行程。',
        descEn: 'Adversaries leverage command prompt cmd.exe to launch system discovery commands, batch scripts, or process spawned by malicious Office macros.',
        logSourcesZh: 'Windows 事件 ID 4688 行程建立 (含命令列稽核)',
        logSourcesEn: 'Windows Event ID 4688 Process Creation with Command-Line Auditing',
        mitigationZh: '透過群組原則 (GPO) 限制非管理者存取 cmd.exe。',
        mitigationEn: 'Restrict non-administrative access to cmd.exe via Group Policy Object (GPO).',
        detectionRule: 'Sigma: ParentImage endswith "\\winword.exe" and Image endswith "\\cmd.exe"'
      }
    ]
  },
  {
    nameZh: '持久化 (Persistence)',
    nameEn: 'Persistence',
    techniques: [
      {
        id: 'T1136.001',
        nameZh: '建立本機帳戶 (Create Local Account)',
        nameEn: 'Create Local Account',
        tacticZh: '持久化',
        tacticEn: 'Persistence',
        ports: [],
        descZh: '建立隱蔽的本機管理者帳戶 (如 shadow_admin)，以便在初始連線中斷後仍能維持長久存取權限。',
        descEn: 'Adversaries create covert local administrative accounts (e.g. shadow_admin) to maintain persistent access after initial compromise.',
        logSourcesZh: 'Windows 安全事件 ID 4720 (使用者帳戶已建立)、事件 ID 4732 (已加入安全性群組)',
        logSourcesEn: 'Windows Security Event ID 4720 (User Account Created), Event ID 4732 (Group Membership Added)',
        mitigationZh: '強制實施 LAPS 本機管理員密碼方案，定期稽核本機群組成員名冊。',
        mitigationEn: 'Enforce LAPS (Local Administrator Password Solution), audit local group memberships.',
        detectionRule: 'Sigma: EventID: 4720 and TargetUserName not in Authorized_Provisioning_List'
      },
      {
        id: 'T1053',
        nameZh: '排程工作 (Scheduled Task)',
        nameEn: 'Scheduled Task',
        tacticZh: '持久化',
        tacticEn: 'Persistence',
        ports: [],
        descZh: '利用 Windows 工作排程器 (schtasks.exe) 或 Linux cron 排程，在系統開機或指定時間自動重新觸發惡意執行。',
        descEn: 'Adversaries abuse Windows Task Scheduler (schtasks.exe) or Linux cron daemon to trigger recurring malicious execution upon system boot or fixed schedules.',
        logSourcesZh: 'Windows TaskScheduler 事件 ID 4698、Linux Auditd /var/log/cron',
        logSourcesEn: 'Windows TaskScheduler Event ID 4698, Linux Auditd /var/log/cron',
        mitigationZh: '限制工作排程建立權限僅限系統管理員，嚴密監控 C:\\Windows\\System32\\Tasks。',
        mitigationEn: 'Restrict task creation privileges to System Administrators, monitor C:\\Windows\\System32\\Tasks.',
        detectionRule: 'Sigma: EventID: 4698 and TaskName contains "\\AppData\\Local\\Temp"'
      }
    ]
  },
  {
    nameZh: '權限提升 (Privilege Escalation)',
    nameEn: 'Privilege Escalation',
    techniques: [
      {
        id: 'T1548.003',
        nameZh: 'Sudo 特權濫用 (Sudo Abuse)',
        nameEn: 'Sudo & Privilege Abuse',
        tacticZh: '權限提升',
        tacticEn: 'Privilege Escalation',
        ports: [22],
        descZh: '利用設定錯誤之 /etc/sudoers 規則或 NOPASSWD 指令，自一般低權限使用者躍升至 root 超級使用者。',
        descEn: 'Adversaries exploit misconfigured /etc/sudoers rules or NOPASSWD directives to escalate privileges from unprivileged user to root.',
        logSourcesZh: 'Linux Syslog /var/log/auth.log、Auditd SYSCALL 稽核紀錄',
        logSourcesEn: 'Linux Syslog /var/log/auth.log, Auditd SYSCALL records',
        mitigationZh: '落實嚴格的 sudoers 設定，禁止在敏感指令中使用 NOPASSWD 通配符。',
        mitigationEn: 'Enforce strict sudoers configuration without NOPASSWD wildcards.',
        detectionRule: 'Sigma: Syslog message contains "COMMAND=/bin/bash" or "COMMAND=/usr/bin/python"'
      },
      {
        id: 'T1068',
        nameZh: '利用核心弱點提權 (Exploit Vulnerability)',
        nameEn: 'Exploit Vulnerability',
        tacticZh: '權限提升',
        tacticEn: 'Privilege Escalation',
        ports: [445, 139],
        descZh: '利用未修補之作業系統核心弱點執行本地提權 (LPE) 攻擊以取得 SYSTEM 或 root 最高存取權限。',
        descEn: 'Adversaries execute local privilege escalation (LPE) exploits targeting unpatched OS kernel vulnerabilities to gain SYSTEM or root access.',
        logSourcesZh: 'Windows 系統事件日誌、核心崩潰傾印、EDR 核心驅動遙測',
        logSourcesEn: 'Windows System Event Log, Kernel Exception Dumps, EDR Telemetry',
        mitigationZh: '每月定期發布與套用作業系統核心安全性更新與 CVE 弱點修正。',
        mitigationEn: 'Deploy monthly OS kernel security updates and CVE patches.',
        detectionRule: 'Sigma: Process creation by SYSTEM user originating from temp folder'
      }
    ]
  },
  {
    nameZh: '防禦逃避 (Defense Evasion)',
    nameEn: 'Defense Evasion',
    techniques: [
      {
        id: 'T1070.001',
        nameZh: '清除事件日誌 (Clear Event Logs)',
        nameEn: 'Clear Event Logs',
        tacticZh: '防禦逃避',
        tacticEn: 'Defense Evasion',
        ports: [],
        descZh: '執行 wevtutil.exe cl Security 或 PowerShell 指令清除 Windows 安全日誌，試圖抹除入侵鑑識數位痕跡。',
        descEn: 'Adversaries execute wevtutil.exe cl Security or PowerShell commands to purge Windows Event Logs and erase forensic traces of intrusion.',
        logSourcesZh: 'Windows 安全事件 ID 1102 (稽核日誌已被清除)',
        logSourcesEn: 'Windows Security Event ID 1102 (The audit log was cleared)',
        mitigationZh: '即時將事件日誌串流至外部不可竄改之遠端 SIEM 收集器保存。',
        mitigationEn: 'Stream Event Logs immediately to an offsite immutable SIEM collector.',
        detectionRule: 'Sigma: EventID: 1102 or CommandLine contains "wevtutil cl"'
      },
      {
        id: 'T1027',
        nameZh: '混淆檔案或資訊 (Obfuscated Files)',
        nameEn: 'Obfuscated Files',
        tacticZh: '防禦逃避',
        tacticEn: 'Defense Evasion',
        ports: [],
        descZh: '透過壓縮、動態加密或 Base64 編碼惡意指令碼與執行檔，以規避傳統基於特徵碼之防毒軟體偵測。',
        descEn: 'Adversaries compress, encrypt, or Base64 encode script payloads and binaries to bypass signature-based antivirus scanners.',
        logSourcesZh: '防毒軟體遙測日誌、AMSI (反惡意軟體掃描介面) 稽核',
        logSourcesEn: 'AV Scan Telemetry, AMSI (Antimalware Scan Interface) Audit Logs',
        mitigationZh: '啟用深度 AMSI 記憶體動態解碼檢測，部署基於行為分析之 EDR 端點防護。',
        mitigationEn: 'Enable deep AMSI inspection, deploy behavior-based Endpoint Detection and Response (EDR).',
        detectionRule: 'Yara: rule High_Entropy_Payload { condition: math.entropy(0, filesize) > 7.5 }'
      }
    ]
  },
  {
    nameZh: '憑證存取 (Credential Access)',
    nameEn: 'Credential Access',
    techniques: [
      {
        id: 'T1110.001',
        nameZh: '密碼猜測 (Password Guessing)',
        nameEn: 'Password Guessing',
        tacticZh: '憑證存取',
        tacticEn: 'Credential Access',
        ports: [3389, 22, 445],
        descZh: '針對暴露之 RDP 3389 或 SSH 22 服務發起高速自動化字典檔密碼暴力猜測，以攻破有效使用者帳戶。',
        descEn: 'Adversaries automate rapid password dictionary attacks against exposed RDP port 3389 or SSH port 22 to compromise valid user credentials.',
        logSourcesZh: 'Windows 安全事件 ID 4625 (登入失敗)、Linux sshd 驗證日誌',
        logSourcesEn: 'Windows Security Event ID 4625 (Failed Logon), Linux sshd Auth Logs',
        mitigationZh: '實施嚴格的帳號鎖定閾值機制 (例如連續失敗 5 次鎖定)，並全面啟用多因素驗證 (MFA)。',
        mitigationEn: 'Enforce Account Lockout Thresholds (5 failed attempts), mandate Multi-Factor Authentication (MFA).',
        detectionRule: 'Sigma: EventID: 4625 | count() > 20 per minute'
      },
      {
        id: 'T1003',
        nameZh: 'OS 憑證傾印 (LSASS Memory Dump)',
        nameEn: 'OS Credential Dump',
        tacticZh: '憑證存取',
        tacticEn: 'Credential Access',
        ports: [],
        descZh: '傾印 LSASS 處理程序記憶體以擷取明文密碼、NTLM 雜湊密碼值或 Kerberos 票證。',
        descEn: 'Adversaries extract plaintext credentials, NTLM hashes, and Kerberos tickets stored in Local Security Authority Subsystem Service (LSASS) memory.',
        logSourcesZh: 'Windows 行程存取事件 ID 10 (請求 LSASS 控制代碼)、EDR 驅動遙測',
        logSourcesEn: 'Windows Process Access Event ID 10 (LSASS Handle Requested), EDR Driver Telemetry',
        mitigationZh: '啟用 Windows Credential Guard (LSA 保護機制)，收回非必要之 SeDebugPrivilege 特權。',
        mitigationEn: 'Enable Credential Guard (LSA Protection), restrict SeDebugPrivilege.',
        detectionRule: 'Sigma: TargetImage endswith "\\lsass.exe" and GrantedAccess includes 0x1410'
      }
    ]
  },
  {
    nameZh: '命令與控制 (C2)',
    nameEn: 'Command & Control',
    techniques: [
      {
        id: 'T1071.001',
        nameZh: 'Web 協定 C2 連線 (Web Protocols C2)',
        nameEn: 'Web Protocols C2',
        tacticZh: '命令與控制',
        tacticEn: 'Command & Control',
        ports: [80, 443, 4444, 8443],
        descZh: '透過標準 HTTP/HTTPS 網頁協定與受害主機進行遠端心跳通信，以偽裝成合法網路流量規避周界防火牆攔截。',
        descEn: 'Adversaries communicate with compromised endpoints over standard HTTP/HTTPS web protocols to evade perimeter firewall inspection.',
        logSourcesZh: '周界防火牆連線日誌、代理伺服器 (Proxy) 日誌、Suricata 告警流',
        logSourcesEn: 'Perimeter Firewall Connection Logs, Proxy Traffic Logs, Suricata Alert Stream',
        mitigationZh: '於次世代防火牆 (NGFW) 啟用 TLS 流量解密與應用程式特徵深度檢測。',
        mitigationEn: 'Deploy TLS Decryption and Inspection at Next-Gen Firewall (NGFW).',
        detectionRule: 'Suricata: alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"C2 Beaconing";)'
      },
      {
        id: 'T1021.001',
        nameZh: '遠端桌面協定 (RDP Protocol)',
        nameEn: 'Remote Desktop Protocol',
        tacticZh: '橫向移動 / C2',
        tacticEn: 'Command & Control / Lateral Movement',
        ports: [3389],
        descZh: '使用 RDP 協定登入內部主機桌面並進行企業內網網段之橫向移動。',
        descEn: 'Adversaries use RDP protocol to interactively log into internal host desktops and navigate laterally across enterprise network segments.',
        logSourcesZh: 'Windows 安全事件 ID 4624 (Type 10 遠端互動式登入)',
        logSourcesEn: 'Windows Security Event ID 4624 (Type 10 Remote Interactive Logon)',
        mitigationZh: '強制要求網路層級驗證 (NLA)，將 RDP 置於企業專用 VPN 與跳板機之後。',
        mitigationEn: 'Require Network Level Authentication (NLA), place RDP behind enterprise VPN.',
        detectionRule: 'Sigma: EventID: 4624 and LogonType: 10'
      }
    ]
  }
];

export default function MitreMatrixView({ nmapScan }) {
  const { t, language } = useLanguage();
  const [selectedTech, setSelectedTech] = useState(TACTICS_DATA[0].techniques[0]);

  // Determine open ports from real nmapScan
  const openPortsList = (nmapScan && Array.isArray(nmapScan.openPorts))
    ? nmapScan.openPorts.map(p => p.port)
    : [];

  const getPortMatch = (tech) => {
    if (openPortsList.length === 0 || !tech.ports) return null;
    const match = tech.ports.find(p => openPortsList.includes(p));
    return match || null;
  };

  const isZh = language === 'zh-TW';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Grid className="w-6 h-6 text-cyan-400" />
            {t('mitre.title', 'MITRE ATT&CK Enterprise Matrix Navigator')}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {t('mitre.subtitle', 'Interactive enterprise threat framework. Click any technique below to inspect technical details, detection rules, and real scanner correlations.')}
          </p>
        </div>
      </div>

      {/* Real Scan Status Banner */}
      {nmapScan ? (
        <div className="glass-panel p-4 rounded-2xl border-l-4 border-l-emerald-500 flex items-center justify-between font-mono text-xs">
          <div className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="text-emerald-300 font-bold">
              {isZh ? '真實網路掃描器數據連動中：' : 'Live Network Telemetry Active:'}
            </span>
            <span className="text-slate-300">
              {isZh 
                ? `目標主機 ${nmapScan.host} 共檢測到 ${nmapScan.openPorts.length} 個開放 Port，匹配之 MITRE 技術已高亮標註。`
                : `Target host ${nmapScan.host} has ${nmapScan.openPorts.length} open ports. Correlated MITRE techniques are highlighted.`}
            </span>
          </div>
        </div>
      ) : (
        <div className="glass-panel p-4 rounded-2xl border-l-4 border-l-cyan-500 flex items-center justify-between font-mono text-xs text-slate-300">
          <div>
            <span className="text-cyan-300 font-bold">
              {isZh ? '標準 MITRE ATT&CK 框架視圖：' : 'Standard MITRE ATT&CK Framework View:'}
            </span>
            <span>
              {isZh 
                ? ' 系統處於基線狀態。至「Network Scanner」進行真實 Port 掃描，矩陣將自動關聯高亮；AI 劇情攻擊映射請至【攻擊模擬】。'
                : ' System in baseline state. Run a port scan in Network Scanner to highlight real-time mappings, or launch Attack Simulation for story scenarios.'}
            </span>
          </div>
        </div>
      )}

      {/* Interactive Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 overflow-x-auto">
        {TACTICS_DATA.map((tactic, idx) => (
          <div key={idx} className="space-y-2">
            <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-center font-mono text-[11px] font-bold text-slate-300">
              {isZh ? tactic.nameZh : tactic.nameEn}
            </div>
            <div className="space-y-2">
              {tactic.techniques.map((tech) => {
                const matchedPort = getPortMatch(tech);
                const isSelected = selectedTech?.id === tech.id;
                const techName = isZh ? tech.nameZh : tech.nameEn;
                return (
                  <button
                    key={tech.id}
                    onClick={() => setSelectedTech(tech)}
                    className={`w-full p-2.5 rounded-xl text-left font-mono text-xs transition-all border relative ${
                      isSelected
                        ? 'border-cyan-400 bg-cyan-500/20 text-cyan-200 shadow-md shadow-cyan-500/10'
                        : matchedPort
                        ? 'bg-amber-500/20 text-amber-300 border-amber-500/50 shadow-sm shadow-amber-500/20 font-bold animate-pulse'
                        : 'bg-slate-950/60 text-slate-400 border-slate-900 hover:bg-slate-900'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-[10px] text-cyan-400">{tech.id}</span>
                      {matchedPort && (
                        <span className="text-[9px] font-bold px-1 rounded bg-amber-500/30 text-amber-300 border border-amber-500/40">
                          Port {matchedPort}
                        </span>
                      )}
                    </div>
                    <div className="truncate text-slate-200 mt-1">{techName}</div>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Selected Technique Details Panel */}
      {selectedTech && (
        <div className="glass-panel p-5 rounded-2xl border border-cyan-500/30 space-y-4 font-mono">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-900 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 text-xs font-bold border border-cyan-500/30">
                  {isZh ? selectedTech.tacticZh : selectedTech.tacticEn}
                </span>
                <span className="text-xs text-slate-400 font-bold">TECHNIQUE ID: {selectedTech.id}</span>
              </div>
              <h3 className="text-base font-bold text-white mt-1">
                {selectedTech.id} - {isZh ? selectedTech.nameZh : selectedTech.nameEn}
              </h3>
            </div>

            {/* Scanned Match Notification */}
            {getPortMatch(selectedTech) ? (
              <div className="px-3.5 py-1.5 rounded-xl bg-amber-500/20 text-amber-300 border border-amber-500/40 text-xs font-bold flex items-center gap-2 shrink-0">
                <Zap className="w-4 h-4 text-amber-400 animate-bounce" />
                {isZh ? `實時掃描匹配：目標 ${nmapScan?.host} 之 Port ${getPortMatch(selectedTech)} 開啟` : `REAL SCAN MATCH: Target ${nmapScan?.host} Port ${getPortMatch(selectedTech)} Open`}
              </div>
            ) : (
              <span className="text-xs text-slate-400 bg-slate-900 px-3 py-1 rounded-lg border border-slate-800 shrink-0">
                {isZh ? '基準技術剖析器' : 'Baseline Technique Inspector'}
              </span>
            )}
          </div>

          {/* Technique Description */}
          <div className="space-y-1">
            <div className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-cyan-400" /> {isZh ? '技術手法行為描述：' : 'Technical Vector Description:'}
            </div>
            <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/60 p-3.5 rounded-xl border border-slate-900">
              {isZh ? selectedTech.descZh : selectedTech.descEn}
            </p>
          </div>

          {/* Details Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-900 space-y-1">
              <span className="font-bold text-cyan-300 flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-cyan-400" /> {isZh ? '關鍵日誌來源與遙測端點：' : 'Key Log Sources & Telemetry:'}
              </span>
              <p className="text-slate-400">{isZh ? selectedTech.logSourcesZh : selectedTech.logSourcesEn}</p>
            </div>

            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-900 space-y-1">
              <span className="font-bold text-emerald-400 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-emerald-400" /> {isZh ? '建議 SOC 防護與緩解措施：' : 'Recommended SOC Mitigation:'}
              </span>
              <p className="text-slate-400">{isZh ? selectedTech.mitigationZh : selectedTech.mitigationEn}</p>
            </div>
          </div>

          {/* Sample Detection Rule */}
          <div className="bg-slate-950 p-4 rounded-xl border border-cyan-500/20 space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-bold text-cyan-300 flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-cyan-400" /> {isZh ? '偵測規則與 SIEM 特徵簽章：' : 'Detection Rule & SIEM Signature:'}
              </span>
              <span className="text-[10px] text-slate-500">{isZh ? '自動關聯規則' : 'Auto-Correlated Rule'}</span>
            </div>
            <pre className="text-xs text-slate-300 font-mono bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              {selectedTech.detectionRule}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
