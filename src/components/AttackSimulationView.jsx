import React, { useState } from 'react';
import { Zap, Play, Terminal, ShieldAlert, CheckCircle, RefreshCw, AlertTriangle, ShieldCheck, BookOpen, Bug, Activity, Grid, FileCode, Copy, Check } from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts';
import { useLanguage } from '../contexts/LanguageContext';

export function getAttackScenarios(language) {
  const isZh = language === 'zh-TW';

  return [
    {
      id: 'brute',
      title: isZh ? 'RDP / SSH 密碼暴力破解演練' : 'RDP / SSH Password Brute-Force',
      description: isZh ? '模擬 500+ 次針對 DC-SRV-01 Administrator 帳號的高速密碼嘗試。' : 'Simulates 500+ rapid password attempts targeting DC-SRV-01 Administrator account.',
      eventLogs: [
        '[14:22:01] WIN-EVENT 4625: Logon Failure for Administrator from 185.220.101.5:54221 (Attempt 1)',
        '[14:22:02] WIN-EVENT 4625: Logon Failure for Administrator from 185.220.101.5:54222 (Attempt 2)',
        '[14:22:03] WIN-EVENT 4625: Logon Failure for Administrator from 185.220.101.5:54223 (Attempt 3)',
        '[14:22:05] ALERT TRIGGERED: Brute Force Pattern Threshold Exceeded (>100 fails/min)'
      ],
      detection: isZh ? 'T1110.001 暴力破解：密碼猜測' : 'T1110.001 Brute Force: Password Guessing',
      aiAction: isZh ? '下發防火牆阻擋規則隔離 185.220.101.5 並強制鎖定目標帳號' : 'Trigger Firewall IP Block rule on 185.220.101.5 & Enforce Account Lockout',
      storyline: isZh 
        ? '外部攻擊者針對主機 DC-SRV-01 之 3389 (RDP) 通訊埠使用 Administrator 帳號發動自動化字典檔猜測攻擊。60 秒內累計超過 500 次登入失敗紀錄。觸發防禦閾值後，自動化防火牆即時阻斷來源 IP 並鎖定帳號。'
        : 'An external adversary initiated an automated password guessing campaign against port 3389 (RDP) on host DC-SRV-01 using account "Administrator". Over 500 failed logon attempts were registered within 60 seconds from source IP 185.220.101.5. Upon threshold breach, automated firewall filtering engaged to block origin traffic and lock target account.',
      timelineData: [
        { time: '00:00', BruteForce: 5, Scans: 10, C2Traffic: 0 },
        { time: '04:00', BruteForce: 3, Scans: 8, C2Traffic: 0 },
        { time: '08:00', BruteForce: 180, Scans: 40, C2Traffic: 0 },
        { time: '12:00', BruteForce: 520, Scans: 85, C2Traffic: 0 },
        { time: '16:00', BruteForce: 210, Scans: 30, C2Traffic: 0 },
        { time: '20:00', BruteForce: 15, Scans: 5, C2Traffic: 0 },
      ],
      severityData: [
        { name: isZh ? '極高 (Critical)' : 'Critical', value: 1, color: '#ef4444' },
        { name: isZh ? '高 (High)' : 'High', value: 15, color: '#f59e0b' },
        { name: isZh ? '中 (Medium)' : 'Medium', value: 32, color: '#06b6d4' },
        { name: isZh ? '低 (Low)' : 'Low', value: 10, color: '#10b981' },
      ],
      criticalCount: 1,
      highCount: 15,
      vulnerabilities: [
        {
          id: "NV-3389",
          cve: "CVE-2019-0708",
          name: isZh ? "遠端桌面服務 RCE 弱點 (BlueKeep)" : "Remote Desktop Services RCE Vulnerability (BlueKeep)",
          severity: "Critical",
          cvss: 9.8,
          host: "192.168.1.10",
          port: 3389,
          exploitAvailable: true,
          patchPriority: isZh ? "立即修補 (P0)" : "Immediate (P0)",
          description: isZh ? "Remote Desktop Services (RDP) 存在未經身份驗證之遠端程式碼執行重大漏洞。" : "An unauthenticated remote code execution vulnerability exists in Remote Desktop Services (RDP)."
        },
        {
          id: "NV-2201",
          cve: "CVE-2020-1472",
          name: isZh ? "Netlogon 特權提升弱點 (Zerologon)" : "Netlogon Privilege Escalation (Zerologon)",
          severity: "Critical",
          cvss: 10.0,
          host: "DC-SRV-01",
          port: 445,
          exploitAvailable: true,
          patchPriority: isZh ? "立即修補 (P0)" : "Immediate (P0)",
          description: isZh ? "當攻擊者建立未驗證之 Netlogon 連線時可直接獲取網域管理員特權。" : "An elevation of privilege vulnerability exists when an attacker establishes an unauthenticated Netlogon connection."
        },
        {
          id: "NV-4625",
          cve: "CWE-307",
          name: isZh ? "未落實帳號鎖定閾值安全策略" : "Unenforced Account Lockout Threshold Policy",
          severity: "High",
          cvss: 7.5,
          host: "DC-SRV-01",
          port: 0,
          exploitAvailable: true,
          patchPriority: isZh ? "高優先級 (P1)" : "High (P1)",
          description: isZh ? "缺乏自動化暴力密碼猜測防禦鎖定機制，導致攻擊者得以進行持續字典檔猜測。" : "Absence of automated brute-force lockout allows rapid automated password dictionary guessing."
        }
      ],
      mitreTactics: [
        { name: isZh ? '偵察階段' : 'Reconnaissance', tech: 'T1595 Active Scanning', active: true },
        { name: isZh ? '初始存取' : 'Initial Access', tech: 'T1078 Valid Accounts', active: true },
        { name: isZh ? '執行階段' : 'Execution', tech: 'T1059.003 Windows Cmd', active: false },
        { name: isZh ? '持久化' : 'Persistence', tech: 'T1136.001 Local Account', active: false },
        { name: isZh ? '特權提升' : 'Privilege Escalation', tech: 'T1548.003 Sudo Abuse', active: false },
        { name: isZh ? '防禦逃避' : 'Defense Evasion', tech: 'T1070.001 Clear Event Logs', active: false },
        { name: isZh ? '憑證存取' : 'Credential Access', tech: 'T1110.001 Brute Force Password Guessing', active: true },
        { name: isZh ? '命令與控制' : 'Command & Control', tech: 'T1021.001 RDP Protocol', active: true },
      ],
      anomalies: [
        {
          id: "ANOM-SIM-1",
          title: isZh ? "暴力密碼猜測攻擊 (Brute Force)" : "Brute Force Password Guessing Attack",
          severity: "High",
          mitreId: "T1110.001",
          target: "DC-SRV-01 (Administrator)",
          attackerIp: "185.220.101.5",
          description: isZh ? "60 秒內針對 Administrator RDP 連線檢測到超過 500 次登入失敗。" : "Over 500 failed login attempts detected in 60 seconds targeting Administrator RDP session.",
          remediation: isZh ? "於周界防火牆阻擋 185.220.101.5，強制施行 5 次失敗帳號鎖定策略。" : "Block source IP 185.220.101.5 on perimeter firewall, enforce 5-attempt Account Lockout Policy."
        },
        {
          id: "ANOM-SIM-2",
          title: isZh ? "未啟用 NLA 之 RDP 3389 連線埠暴露" : "Exposed RDP Port 3389 without NLA",
          severity: "High",
          mitreId: "T1021.001",
          target: "DC-SRV-01:3389",
          attackerIp: "185.220.101.5",
          description: isZh ? "遠端桌面服務直接暴露於外網 WAN 且未強制啟用網路層驗證 (NLA)。" : "Remote Desktop Protocol service accessible directly from public internet WAN without Network Level Authentication.",
          remediation: isZh ? "將 RDP 服務置於企業專屬 VPN 與 MFA 之後。" : "Place RDP service behind enterprise VPN with MFA requirement."
        }
      ],
      scripts: {
        powershell: `# CyberMind AI Generated PowerShell Containment Script for Brute Force
New-NetFirewallRule -DisplayName "CyberMind-Block-185.220.101.5" -Direction Inbound -Action Block -RemoteAddress "185.220.101.5"
Set-LocalUser -Name "Administrator" -AccountNeverExpires $false`,
        bash: `#!/bin/bash
iptables -A INPUT -s 185.220.101.5 -j DROP
echo "[+] Blocked Brute-Force Origin IP 185.220.101.5"`,
        sigma: `title: RDP Brute Force Password Guessing
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection | count() > 100`,
        yara: `rule Sim_Brute_Force_Audit {
    strings:
        $event = "WIN-EVENT 4625"
    condition:
        $event
}`,
        snort: `alert tcp 185.220.101.5 any -> $HOME_NET 3389 (msg:"Simulated RDP Brute-Force Detection"; sid:1000101;)`,
        suricata: `alert tcp 185.220.101.5 any -> $HOME_NET 3389 (msg:"Simulated RDP Brute Force Threshold Exceeded"; sid:2000101;)`
      }
    },
    {
      id: 'powershell',
      title: isZh ? '混淆 Base64 PowerShell C2 載荷下載' : 'Obfuscated PowerShell C2 Beacon Download',
      description: isZh ? '模擬 cmd.exe 啟動 powershell.exe -enc 執行 Base64 編碼 shell.ps1。' : 'Simulates cmd.exe launching powershell.exe -enc with Base64 payload shell.ps1.',
      eventLogs: [
        '[14:25:30] WIN-EVENT 4688: New Process Created: powershell.exe by cmd.exe',
        '[14:25:31] COMMAND: powershell.exe -ExecutionPolicy Bypass -enc SQBFAAGAKABOAGV3LU9i...',
        '[14:25:32] NETWORK: Outbound connection attempt to 183.220.101.5:4444 (TCP)',
        '[14:25:33] ALERT TRIGGERED: Known Cobalt Strike Stager Signature Matched'
      ],
      detection: isZh ? 'T1059.001 PowerShell 指令直譯器 / C2 心跳通信' : 'T1059.001 PowerShell Command Interpreter / C2 Beaconing',
      aiAction: isZh ? '終止 PID 4812，隔離 shell.ps1，封鎖遠端 C2 IP 183.220.101.5' : 'Terminate PID 4812, Quarantine shell.ps1, Block Remote IP 183.220.101.5',
      storyline: isZh
        ? '攻擊者於主機 DC-SRV-01 透過 cmd.exe 執行 Base64 編碼之混淆 PowerShell 指令，企圖對遠端 C2 伺服器 183.220.101.5:4444 發起 HTTP GET 請求下載二階段惡意載荷 shell.ps1。端點偵測防禦系統已即時識別混淆字串並強制終止父處理程序樹。'
        : 'An adversary executed an encoded Base64 PowerShell command via cmd.exe on host DC-SRV-01. The stager attempted outbound HTTP GET request to download secondary payload shell.ps1 from remote C2 server 183.220.101.5:4444. Endpoint protection flagged the obfuscated execution string and killed the parent process tree.',
      timelineData: [
        { time: '00:00', BruteForce: 2, Scans: 10, C2Traffic: 0 },
        { time: '04:00', BruteForce: 0, Scans: 5, C2Traffic: 0 },
        { time: '08:00', BruteForce: 10, Scans: 25, C2Traffic: 45 },
        { time: '12:00', BruteForce: 5, Scans: 30, C2Traffic: 240 },
        { time: '16:00', BruteForce: 2, Scans: 15, C2Traffic: 110 },
        { time: '20:00', BruteForce: 0, Scans: 5, C2Traffic: 8 },
      ],
      severityData: [
        { name: isZh ? '極高 (Critical)' : 'Critical', value: 8, color: '#ef4444' },
        { name: isZh ? '高 (High)' : 'High', value: 18, color: '#f59e0b' },
        { name: isZh ? '中 (Medium)' : 'Medium', value: 14, color: '#06b6d4' },
        { name: isZh ? '低 (Low)' : 'Low', value: 5, color: '#10b981' },
      ],
      criticalCount: 8,
      highCount: 18,
      vulnerabilities: [
        {
          id: "NV-1059",
          cve: "CWE-94",
          name: isZh ? "未受限之 PowerShell 執行原則繞過 (Bypass)" : "Unrestricted PowerShell Execution Policy Bypass",
          severity: "Critical",
          cvss: 9.3,
          host: "DC-SRV-01",
          port: 0,
          exploitAvailable: true,
          patchPriority: isZh ? "立即修補 (P0)" : "Immediate (P0)",
          description: isZh ? "PowerShell 執行原則允許非特權使用者透過 -ExecutionPolicy Bypass 參數直接執行未簽章之惡意腳本。" : "PowerShell script execution policy allows non-administrative bypass via -ExecutionPolicy Bypass parameter."
        },
        {
          id: "NV-1832",
          cve: "CWE-284",
          name: isZh ? "未過濾之出站 C2 心跳連線 (Port 4444)" : "Unfiltered Outbound C2 Beacon Connection (Port 4444)",
          severity: "Critical",
          cvss: 9.1,
          host: "183.220.101.5",
          port: 4444,
          exploitAvailable: true,
          patchPriority: isZh ? "立即修補 (P0)" : "Immediate (P0)",
          description: isZh ? "主機出站防火牆允許內部主機向外部未驗證之非標準 Port 發起 TCP 連線。" : "Host firewall rules permit outbound TCP traffic to unverified external IP on non-standard C2 port."
        }
      ],
      mitreTactics: [
        { name: isZh ? '偵察階段' : 'Reconnaissance', tech: 'T1595 Active Scanning', active: false },
        { name: isZh ? '初始存取' : 'Initial Access', tech: 'T1190 Exploit Public App', active: false },
        { name: isZh ? '執行階段' : 'Execution', tech: 'T1059.001 PowerShell Stager', active: true },
        { name: isZh ? '持久化' : 'Persistence', tech: 'T1136.001 Local Account', active: true },
        { name: isZh ? '特權提升' : 'Privilege Escalation', tech: 'T1548.003 Sudo Abuse', active: false },
        { name: isZh ? '防禦逃避' : 'Defense Evasion', tech: 'T1027 Obfuscated Files', active: true },
        { name: isZh ? '憑證存取' : 'Credential Access', tech: 'T1003 OS Credential Dump', active: false },
        { name: isZh ? '命令與控制' : 'Command & Control', tech: 'T1071.001 C2 Web Protocol', active: true },
      ],
      anomalies: [
        {
          id: "ANOM-SIM-1",
          title: isZh ? "混淆 PowerShell 執行 (C2 下載載荷)" : "Obfuscated PowerShell Execution (C2 Stager)",
          severity: "Critical",
          mitreId: "T1059.001",
          target: "DC-SRV-01 (powershell.exe)",
          attackerIp: "183.220.101.5",
          description: isZh ? "可疑 Base64 編碼 PowerShell 腳本企圖下載外部載荷 shell.ps1。" : "Suspicious Base64 encoded PowerShell script initiated web download of external payload shell.ps1.",
          remediation: isZh ? "立即終止 PID 4812，阻擋遠端 C2 IP 183.220.101.5，執行 EDR 記憶體掃描。" : "Immediately kill PID 4812, block remote C2 IP 183.220.101.5, run EDR memory scan."
        }
      ],
      scripts: {
        powershell: `# CyberMind AI Generated PowerShell Containment Script for C2 Stager
Get-Process powershell | Where-Object { $_.CommandLine -like "*-enc*" } | Stop-Process -Force
New-NetFirewallRule -DisplayName "CyberMind-Block-C2-183.220.101.5" -Direction Outbound -Action Block -RemoteAddress "183.220.101.5"`,
        bash: `#!/bin/bash
pkill -f "shell.ps1"
iptables -A OUTPUT -d 183.220.101.5 -j DROP`,
        sigma: `title: Obfuscated PowerShell Execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        NewProcessName|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - 'DownloadString'
    condition: selection`,
        yara: `rule Sim_PowerShell_C2_Stager {
    strings:
        $ps = "powershell.exe"
        $bypass = "-ExecutionPolicy Bypass"
    condition:
        $ps and $bypass
}`,
        snort: `alert tcp any any -> 183.220.101.5 4444 (msg:"Simulated Cobalt Strike C2 Traffic"; sid:1000102;)`,
        suricata: `alert tcp $HOME_NET any -> 183.220.101.5 4444 (msg:"Simulated C2 Beacon Traffic Blocked"; sid:2000102;)`
      }
    },
    {
      id: 'ransomware',
      title: isZh ? 'LockBit 勒索軟體破壞磁碟陰影複本' : 'LockBit Ransomware Shadow Copy Destruction',
      description: isZh ? '模擬執行 vssadmin.exe delete shadows /all /quiet 銷毀備份並加密檔案。' : 'Simulates vssadmin.exe delete shadows /all /quiet command followed by bulk file encryption.',
      eventLogs: [
        '[14:28:10] WIN-EVENT 4688: Process: vssadmin.exe delete shadows /all /quiet',
        '[14:28:11] FILE-MOD: 1,420 files renamed to *.lockbit in C:\\Users\\Administrator\\Documents',
        '[14:28:12] ALERT TRIGGERED: High Velocity Mass File Rename & Shadow Copy Purge'
      ],
      detection: isZh ? 'T1486 資料加密勒索 / T1490 阻斷系統復原' : 'T1486 Data Encrypted for Impact / T1490 Inhibit System Recovery',
      aiAction: isZh ? '中斷磁碟 I/O，隔離 DC-SRV-01 網卡，啟動快照回滾劇本' : 'Emergency Halt Disk I/O, Disable Network Adapter, Deploy Immutable Rollback',
      storyline: isZh
        ? '勒索軟體載荷於 DC-SRV-01 啟動，率先調用 vssadmin.exe delete shadows 銷毀所有系統還原點以阻斷災難復原路徑，隨後在 Documents 目錄下進行檔案批次加密與副檔名變更 (.lockbit)。系統已即時封鎖磁碟寫入並斷開網絡連線。'
        : 'Ransomware stager initiated on DC-SRV-01, invoking vssadmin.exe delete shadows to eliminate volume restore points before initiating high-velocity document encryption under user profile paths. Defensive agent severed network adapter and froze disk write queues.',
      timelineData: [
        { time: '00:00', BruteForce: 0, Scans: 5, C2Traffic: 0 },
        { time: '04:00', BruteForce: 0, Scans: 2, C2Traffic: 0 },
        { time: '08:00', BruteForce: 10, Scans: 15, C2Traffic: 5 },
        { time: '12:00', BruteForce: 20, Scans: 40, C2Traffic: 310 },
        { time: '16:00', BruteForce: 8, Scans: 10, C2Traffic: 80 },
        { time: '20:00', BruteForce: 0, Scans: 2, C2Traffic: 0 },
      ],
      severityData: [
        { name: isZh ? '極高 (Critical)' : 'Critical', value: 12, color: '#ef4444' },
        { name: isZh ? '高 (High)' : 'High', value: 24, color: '#f59e0b' },
        { name: isZh ? '中 (Medium)' : 'Medium', value: 8, color: '#06b6d4' },
        { name: isZh ? '低 (Low)' : 'Low', value: 2, color: '#10b981' },
      ],
      criticalCount: 12,
      highCount: 24,
      vulnerabilities: [
        {
          id: "NV-1490",
          cve: "CWE-284",
          name: isZh ? "未限制之 Volume Shadow Copy 刪除權限" : "Unrestricted Volume Shadow Copy Deletion Access",
          severity: "Critical",
          cvss: 9.6,
          host: "DC-SRV-01",
          port: 0,
          exploitAvailable: true,
          patchPriority: isZh ? "立即修補 (P0)" : "Immediate (P0)",
          description: isZh ? "一般管理員權限允許透過 vssadmin 無阻礙刪除磁碟陰影複本。" : "Unprotected vssadmin.exe binary allows non-elevated destruction of backup shadow copies."
        }
      ],
      mitreTactics: [
        { name: isZh ? '偵察階段' : 'Reconnaissance', tech: 'T1595 Active Scanning', active: false },
        { name: isZh ? '初始存取' : 'Initial Access', tech: 'T1566 Phishing', active: true },
        { name: isZh ? '執行階段' : 'Execution', tech: 'T1059.003 Windows Cmd', active: true },
        { name: isZh ? '持久化' : 'Persistence', tech: 'T1053 Scheduled Task', active: false },
        { name: isZh ? '特權提升' : 'Privilege Escalation', tech: 'T1068 Exploit Vulnerability', active: true },
        { name: isZh ? '防禦逃避' : 'Defense Evasion', tech: 'T1070.001 Clear Event Logs', active: true },
        { name: isZh ? '衝擊影響' : 'Impact', tech: 'T1486 Data Encrypted for Impact', active: true },
        { name: isZh ? '衝擊影響' : 'Impact', tech: 'T1490 Inhibit System Recovery', active: true },
      ],
      anomalies: [
        {
          id: "ANOM-SIM-1",
          title: isZh ? "大量檔案修改與 .lockbit 副檔名附加" : "Bulk File Modification & .lockbit Extension Append",
          severity: "Critical",
          mitreId: "T1486",
          target: "C:\\Users\\Administrator\\Documents",
          attackerIp: "Local Executable Payload",
          description: isZh ? "Documents 資料夾下偵測到高通量檔案批次更名與加密。" : "Bulk file rename and encryption detected under document folders.",
          remediation: isZh ? "暫停磁碟 I/O，隔離主機，部署不可竄改之備份回滾劇本。" : "Halt disk I/O, isolate host, deploy immutable backup rollback playbook."
        }
      ],
      scripts: {
        powershell: `# CyberMind AI Generated Ransomware Emergency Containment Script
Stop-Process -Name "vssadmin" -Force
Disable-NetAdapter -Name "Ethernet" -Confirm:$false
Write-Host "[!] Ransomware Process Terminated & Host Network Isolated." -ForegroundColor Red`,
        bash: `#!/bin/bash
pkill -f "vssadmin"
pkill -f ".lockbit"
echo "[+] Isolated Host Network Interfaces"`,
        sigma: `title: Volume Shadow Copy Deletion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        NewProcessName|endswith: '\\vssadmin.exe'
        CommandLine|contains: 'delete shadows'
    condition: selection`,
        yara: `rule Sim_LockBit_Ransomware_Payload {
    strings:
        $vss = "vssadmin.exe delete shadows"
        $ext = ".lockbit"
    condition:
        any of them
}`,
        snort: `alert tcp any any -> any 445 (msg:"Simulated Ransomware SMB Lateral Movement"; sid:1000103;)`,
        suricata: `alert smb any any -> any 445 (msg:"Simulated LockBit Ransomware Activity"; sid:2000103;)`
      }
    },
    {
      id: 'sqli',
      title: isZh ? 'Web 應用程式 SQL 注入式攻擊 (SQLi)' : 'Web Application SQL Injection (SQLi)',
      description: isZh ? '模擬帶有 UNION SELECT 特徵之惡意 HTTP 請求企圖傾印使用者密碼資料表。' : 'Simulates GET /products.php?id=1%27%20UNION%20SELECT%201,username,password%20FROM%20users--',
      eventLogs: [
        '[14:30:10] NGINX-LOG: 192.168.1.155 - - "GET /products.php?id=1%27%20UNION%20SELECT%201,username,password%20FROM%20users-- HTTP/1.1" 200 4512',
        '[14:30:11] WAF ALERT: SQL Injection Signature ID 942100 Matched in URI parameter id'
      ],
      detection: isZh ? 'OWASP A03:2021 注入式攻擊 / T1190 利用公開 Web 漏洞' : 'OWASP A03:2021 Injection / T1190 Exploit Public-Facing Application',
      aiAction: isZh ? '於 Nginx WAF 阻擋來源 IP 192.168.1.155 並啟用輸入參數白名單' : 'Block Source IP 192.168.1.155 at Nginx WAF Layer, Sanitize Input Parameters',
      storyline: isZh
        ? '攻擊者針對對外公開之 /products.php 端點發送帶有 SQL UNION 注入語法之惡意請求，企圖自後端資料庫傾印使用者憑證資料表。網站應用程式防火牆 (WAF) 規則 942100 命中異常請求並立即阻斷用戶端 IP 192.168.1.155。'
        : 'An attacker probed public endpoint /products.php using SQL UNION injection syntax to extract credential tables from back-end database. Web Application Firewall (WAF) rule 942100 matched the malformed request and blocked client IP address 192.168.1.155.',
      timelineData: [
        { time: '00:00', BruteForce: 0, Scans: 30, C2Traffic: 0 },
        { time: '04:00', BruteForce: 0, Scans: 15, C2Traffic: 0 },
        { time: '08:00', BruteForce: 0, Scans: 280, C2Traffic: 0 },
        { time: '12:00', BruteForce: 0, Scans: 450, C2Traffic: 0 },
        { time: '16:00', BruteForce: 0, Scans: 190, C2Traffic: 0 },
        { time: '20:00', BruteForce: 0, Scans: 40, C2Traffic: 0 },
      ],
      severityData: [
        { name: isZh ? '極高 (Critical)' : 'Critical', value: 3, color: '#ef4444' },
        { name: isZh ? '高 (High)' : 'High', value: 19, color: '#f59e0b' },
        { name: isZh ? '中 (Medium)' : 'Medium', value: 22, color: '#06b6d4' },
        { name: isZh ? '低 (Low)' : 'Low', value: 12, color: '#10b981' },
      ],
      criticalCount: 3,
      highCount: 19,
      vulnerabilities: [
        {
          id: "NV-9421",
          cve: "CVE-2023-SQLI",
          name: isZh ? "OWASP A03:2021 /products.php SQL 注入弱點" : "OWASP A03:2021 SQL Injection in /products.php",
          severity: "Critical",
          cvss: 9.8,
          host: "web-prod-01",
          port: 80,
          exploitAvailable: true,
          patchPriority: isZh ? "立即修補 (P0)" : "Immediate (P0)",
          description: isZh ? "查詢參數 id 未對使用者輸入進行過濾，允許未經身份驗證之資料庫資料外洩。" : "Unsanitized user input in query parameter id permits unauthenticated SQL database exfiltration."
        },
        {
          id: "NV-10492",
          cve: "CVE-2021-44228",
          name: isZh ? "Apache Log4j 遠端程式碼執行弱點 (Log4Shell)" : "Apache Log4j Remote Code Execution (Log4Shell)",
          severity: "Critical",
          cvss: 10.0,
          host: "192.168.1.50",
          port: 8080,
          exploitAvailable: true,
          patchPriority: isZh ? "立即修補 (P0)" : "Immediate (P0)",
          description: isZh ? "Log4j 2.0 至 2.15.0 中之 JNDI 查閱功能允許攻擊者透過請求標頭觸發 RCE。" : "JNDI lookup feature in Apache Log4j 2.0-beta9 through 2.15.0 allows unauthenticated RCE via payload string."
        }
      ],
      mitreTactics: [
        { name: isZh ? '偵察階段' : 'Reconnaissance', tech: 'T1595 Active Web Scan', active: true },
        { name: isZh ? '初始存取' : 'Initial Access', tech: 'T1190 Exploit Public App (SQLi)', active: true },
        { name: isZh ? '執行階段' : 'Execution', tech: 'T1059 Command Interpreter', active: false },
        { name: isZh ? '持久化' : 'Persistence', tech: 'T1053 Scheduled Task', active: false },
        { name: isZh ? '特權提升' : 'Privilege Escalation', tech: 'T1068 Exploit Vulnerability', active: false },
        { name: isZh ? '防禦逃避' : 'Defense Evasion', tech: 'T1562 Impair WAF Defenses', active: true },
        { name: isZh ? '憑證存取' : 'Credential Access', tech: 'T1552 Credentials in DB', active: true },
        { name: isZh ? '命令與控制' : 'Command & Control', tech: 'T1071.001 Web Protocols', active: false },
      ],
      anomalies: [
        {
          id: "ANOM-SIM-1",
          title: isZh ? "Web 應用程式 SQL 注入攻擊 (UNION SELECT)" : "Web Application SQL Injection (UNION SELECT)",
          severity: "Critical",
          mitreId: "T1190",
          target: "web-prod-01 (/products.php)",
          attackerIp: "192.168.1.155",
          description: isZh ? "攻擊者發送帶有 SQL UNION SELECT 語法之 HTTP GET 請求。" : "Attacker sent HTTP GET request containing SQL UNION SELECT syntax in parameter id.",
          remediation: isZh ? "於 Nginx WAF 阻擋 192.168.1.155，將原始 SQL 查詢改為 PDO 參數化查詢 (Prepared Statements)。" : "Block IP 192.168.1.155 on Nginx WAF layer, replace raw SQL queries with PDO parameterized queries."
        }
      ],
      scripts: {
        powershell: `# CyberMind AI Generated PowerShell WAF Rule Deployment
# Block Attacker IP in Windows IIS / Advanced Firewall
New-NetFirewallRule -DisplayName "CyberMind-Block-SQLi-192.168.1.155" -Direction Inbound -Action Block -RemoteAddress "192.168.1.155"`,
        bash: `#!/bin/bash
# Nginx WAF IP Drop
iptables -A INPUT -s 192.168.1.155 -j DROP
echo "[+] Blocked SQLi Attacker IP 192.168.1.155"`,
        sigma: `title: Web SQL Injection Attempt in URI
logsource:
    category: webserver
detection:
    selection:
        cs-method: 'GET'
        cs-uri-query|contains:
            - 'UNION'
            - 'SELECT'
    condition: selection`,
        yara: `rule Sim_SQL_Injection_Payload {
    strings:
        $sqli = "UNION SELECT" nocase
    condition:
        $sqli
}`,
        snort: `alert tcp 192.168.1.155 any -> $HTTP_SERVERS 80 (msg:"Simulated SQL Injection UNION Attempt"; sid:1000104;)`,
        suricata: `alert http 192.168.1.155 any -> $HTTP_SERVERS 80 (msg:"Simulated OWASP SQL Injection Blocked"; sid:2000104;)`
      }
    }
  ];
}

export default function AttackSimulationView({ onLaunchScenario }) {
  const { t, language } = useLanguage();
  const scenarios = getAttackScenarios(language);
  const [selectedScenarioId, setSelectedScenarioId] = useState(scenarios[0].id);
  const [isSimulating, setIsSimulating] = useState(false);
  const [logs, setLogs] = useState([]);
  const [activeTab, setActiveTab] = useState('overview');
  const [activeScriptTab, setActiveScriptTab] = useState('powershell');
  const [copied, setCopied] = useState(false);

  const activeScenario = scenarios.find(s => s.id === selectedScenarioId) || scenarios[0];
  const isZh = language === 'zh-TW';

  const handleStartSimulation = () => {
    setIsSimulating(true);
    setLogs([]);

    activeScenario.eventLogs.forEach((log, index) => {
      setTimeout(() => {
        setLogs(prev => [...prev, log]);
        if (index === activeScenario.eventLogs.length - 1) {
          setIsSimulating(false);
          if (onLaunchScenario) {
            onLaunchScenario(activeScenario);
          }
        }
      }, (index + 1) * 600);
    });
  };

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Zap className="w-6 h-6 text-amber-400" />
            {t('simulation.title', 'AI Red/Blue Team Attack Simulation Sandbox')}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {t('simulation.subtitle', 'Safely simulate complex multi-stage cyber attacks. All simulated threat data will be contained here and dynamically reflected across the dashboard during execution.')}
          </p>
        </div>
      </div>

      {/* Scenario Selection Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {scenarios.map((sc) => (
          <div
            key={sc.id}
            onClick={() => { setSelectedScenarioId(sc.id); setLogs([]); }}
            className={`glass-panel p-5 rounded-2xl cursor-pointer border transition-all flex flex-col justify-between space-y-3 ${
              selectedScenarioId === sc.id
                ? 'border-amber-500/60 bg-amber-500/10 shadow-lg shadow-amber-500/10'
                : 'border-slate-800 hover:border-slate-700'
            }`}
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-bold border border-amber-500/30 uppercase">
                  {sc.id}
                </span>
                <Activity className="w-4 h-4 text-amber-400" />
              </div>
              <h3 className="text-sm font-bold text-white font-mono">{sc.title}</h3>
              <p className="text-xs text-slate-400 mt-1 line-clamp-2">{sc.description}</p>
            </div>

            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
              <span className="text-slate-500">{isZh ? '模擬事件日誌:' : 'Event Logs:'}</span>
              <span className="text-amber-300 font-bold">{sc.eventLogs.length} {isZh ? '條' : 'Events'}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Main Execution Console */}
      <div className="glass-panel p-6 rounded-2xl border border-amber-500/30 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                {isZh ? '已就緒之演練劇本' : 'ACTIVE SCENARIO READY'}
              </span>
              <h3 className="text-base font-bold text-white font-mono">{activeScenario.title}</h3>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-1">{activeScenario.description}</p>
          </div>

          <button
            onClick={handleStartSimulation}
            disabled={isSimulating}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-amber-500 to-red-600 hover:from-amber-400 hover:to-red-500 text-slate-950 font-mono text-xs font-bold shadow-lg shadow-amber-500/20 transition-all disabled:opacity-50 shrink-0"
          >
            {isSimulating ? <RefreshCw className="w-4 h-4 animate-spin text-slate-950" /> : <Play className="w-4 h-4 fill-slate-950" />}
            {isSimulating ? (isZh ? '正在串流注入演練日誌...' : 'Injecting Attack Telemetry...') : (isZh ? '啟動 AI 威脅演練 (Run Simulation)' : 'Run Simulation')}
          </button>
        </div>

        {/* Live Attack Terminal / Log Stream */}
        <div className="bg-slate-950 rounded-xl p-4 font-mono text-xs border border-slate-900 space-y-2">
          <div className="flex items-center justify-between text-slate-500 border-b border-slate-900 pb-2">
            <span className="flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-amber-400" />
              {isZh ? '虛擬攻擊者注入日誌串流 (Simulated Log Ingestion Engine)' : 'Simulated Real-Time Log Telemetry Stream'}
            </span>
            <span className="text-[10px] text-amber-400 font-semibold animate-pulse">
              {isSimulating ? (isZh ? '● 正在注入中' : '● INJECTING') : (isZh ? '● 待命' : '● IDLE')}
            </span>
          </div>

          <div className="max-h-48 overflow-y-auto space-y-1.5 pt-1">
            {logs.length === 0 ? (
              <div className="text-slate-600 italic py-4 text-center">
                {isZh ? '點擊上方「啟動 AI 威脅演練」以在安全的沙箱環境中重現該攻擊事件...' : 'Click "Run Simulation" above to execute this incident in the isolated sandbox...'}
              </div>
            ) : (
              logs.map((l, idx) => (
                <div key={idx} className="text-amber-300/90 leading-relaxed font-mono flex items-start gap-2">
                  <span className="text-slate-600 select-none">[{idx + 1}]</span>
                  <span>{l}</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Scenario Storyline & AI Counter-Measures */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
            <h4 className="text-xs font-bold text-amber-400 font-mono flex items-center gap-1.5">
              <BookOpen className="w-4 h-4" /> {isZh ? 'AI 攻擊情節敘事 (Attack Storyline):' : 'AI Attack Storyline Narrative:'}
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed font-mono">
              {activeScenario.storyline}
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
            <h4 className="text-xs font-bold text-emerald-400 font-mono flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4" /> {isZh ? 'AI 自動化處置與反制手段 (Counter-Measures):' : 'AI Automated Defensive Counter-Measures:'}
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed font-mono">
              {activeScenario.aiAction}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
