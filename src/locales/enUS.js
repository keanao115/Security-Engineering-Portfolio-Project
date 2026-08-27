// English (en-US) Localization Dictionary for CyberMind AI

export const enUS = {
  common: {
    status: "Status",
    online: "Online",
    offline: "Offline",
    search: "Search",
    cancel: "Cancel",
    save: "Save",
    copy: "Copy",
    copied: "Copied!",
    loading: "Loading...",
    error: "Error",
    success: "Success",
    refresh: "Refresh",
    export: "Export",
    import: "Import",
    filter: "Filter",
    all: "All",
    actions: "Actions",
    close: "Close",
    viewDetails: "View Details",
    optimal: "Optimal",
    critical: "Critical Risk",
    high: "High Risk",
    medium: "Medium Risk",
    low: "Low Risk",
    target: "Target",
    protocol: "Protocol",
    port: "Port",
    service: "Service",
    evidence: "Evidence",
    confidence: "Confidence",
    enabled: "Enabled",
    disabled: "Disabled",
    featureBadge: "FEATURE",
    prodBadge: "PROD",
    metricsBadge: "METRICS",
    aiBadge: "AI"
  },

  header: {
    title: "CyberMind AI",
    portfolioTitle: "Security Engineering Portfolio Platform",
    version: "ENTERPRISE v3.0",
    subtitle: "Autonomous AI Threat Detection & Real-Time SOC Monitoring",
    engineOnline: "AI Engine: Online (Rule + LLM)",
    configureKey: "Configure AI Key",
    keySet: "API Key Set",
    adminRole: "Security Admin",
    analystRole: "SOC Tier-3 Analyst",
    selectLanguage: "Switch Language"
  },

  sidebar: {
    socNavigation: "SOC NAVIGATION",
    liveMonitoring: "LIVE MONITORING & TELEMETRY",
    aiSimulation: "AI & SIMULATION",
    dashboard: "Dashboard",
    threat: "Threat Analysis",
    log: "Log Analyzer",
    network: "Network Scanner",
    vuln: "Vulnerability Scanner",
    reports: "Incident Reports",
    mitre: "MITRE ATT&CK",
    ioc: "IOC Database",
    collectors: "Collector Management",
    packetCapture: "Live Packet Capture",
    zeekSuricata: "Zeek & Suricata IDS",
    pipelinePerformance: "Pipeline Performance",
    investigationTimeline: "Evidence Timeline",
    liveNetwork: "Live Network Monitor",
    packetInspector: "Packet Inspector",
    assetDiscovery: "Asset Discovery",
    siemConsole: "SIEM Event Console",
    simulation: "Attack Simulation",
    copilot: "SOC Copilot (Playbooks)",
    rag: "RAG Knowledge Base",
    chat: "AI Chat Assistant",
    settings: "Settings & Profile",
    securityScore: "Security Score"
  },

  dashboard: {
    criticalIncidentTitle: "CRITICAL INCIDENT DETECTED:",
    criticalIncidentDesc: "Host DC-SRV-01 initiated C2 web download string to external IP 183.220.101.5. Automated mitigation rules ready.",
    investigateNow: "Investigate Now",
    overallScore: "Overall Security Score",
    networkProt: "Network Protection",
    endpointSec: "Endpoint Security",
    identityAccess: "Identity & Access",
    cloudPosture: "Cloud Posture",
    emailSec: "Email Security",
    liveAttackTimeline: "Live Cyber Attack Timeline (24 Hours)",
    realTimeVectors: "Real-time threat vectors detected across network perimeter",
    liveFeed: "Live Feed",
    threatSeverity: "Threat Severity Breakdown",
    severityDistDesc: "Distribution of active alerts",
    telemetryHealth: "SOC Infrastructure & Telemetry Health",
    siemCpu: "SIEM Engine CPU",
    ramUsage: "RAM Usage",
    diskUsage: "Log Buffer Disk",
    paloAltoFw: "PaloAlto Firewall",
    avStatus: "Antivirus Status",
    activeBlocking: "Active / Blocking",
    updated: "Updated (v4.18)",
    normal: "Normal",
    bruteForceSeries: "RDP/SSH Brute Force",
    scansSeries: "Port Scans",
    c2Series: "C2 Beacon Attempts"
  },

  threat: {
    title: "AI Automated Threat Analysis & Mitigation",
    subtitle: "Automated correlation, CVE lookup, MITRE ATT&CK mapping, and remediation script synthesis.",
    storylineTitle: "AI Attack Storyline Narrative",
    storylineContent: "An adversary gained initial access via remote password brute-forcing (Event 4625) against user account Administrator from IP 185.220.101.5. After successful credential guessing, the adversary launched an obfuscated Base64 PowerShell stager (Event 4688) downloading stage2 payload shell.ps1. High administrative local account shadow_admin (Event 4720) was subsequently added for persistence, followed by clearing event logs (Event 1102) to attempt forensic evasion.",
    targetSystem: "Target System:",
    attackerOrigin: "Attacker Origin:",
    mitreTechnique: "MITRE Technique:",
    aiFix: "AI Recommended Fix:",
    scriptGeneratorTitle: "Automated Incident Containment Script Generator",
    scriptGeneratorDesc: "One-click copyable mitigation scripts tailor-made for this incident",
    copyCode: "Copy Code",
    copied: "Copied!",
    tabs: {
      powershell: "PowerShell (Windows)",
      bash: "Bash (Linux)",
      sigma: "Sigma Rule",
      yara: "YARA Rule",
      snort: "Snort IDS Rule",
      suricata: "Suricata IDS Rule"
    }
  },

  logAnalysis: {
    title: "Enterprise Multi-Source Log Analyzer",
    subtitle: "Drag & drop raw log files or select preset attack scenarios to trigger AI anomaly parsing.",
    samplePresets: "Sample Attack Scenarios:",
    windowsBtn: "Windows Event Log (4625/4688)",
    linuxBtn: "Linux Syslog / Auth",
    firewallBtn: "Palo Alto Firewall Logs",
    uploadBtn: "Upload Log File",
    runBtn: "Run AI Threat Analysis",
    analyzingBtn: "Analyzing Log Signals...",
    filterLabel: "Filter Logs:",
    searchPlaceholder: "Search IP, Event ID, Keyword...",
    showingEntries: "Showing raw log entries:"
  },

  networkScanner: {
    title: "Real Network Security Scanner & Node.js Telemetry Engine",
    subtitle: "Uses Node.js native net.Socket to perform actual TCP connect scans against your laptop or local network IP.",
    targetLabel: "Target Laptop / IP Address:",
    importNmap: "Import Real Nmap (.xml / .txt)",
    launchProbe: "Execute Real TCP Socket Probe",
    probing: "Probing Target Ports...",
    authVerification: "Authorization Verification:",
    authText: "I confirm that I own or have explicit written authorization to scan this target.",
    showAllPorts: "Show All Scanned Ports",
    showOpenOnly: "Show Open Ports Only",
    targetHost: "Target Host",
    scannerEngine: "Scanner Engine",
    openPortsFound: "Open Ports Found",
    listenersUnit: "Active Listeners",
    verifiedTelemetry: "Verified Port Socket Telemetry",
    displayingCount: "Displaying ports count:",
    noOpenPortsTitle: "No open TCP ports detected!",
    noOpenPortsDesc: "Target host is hardened or protected by a local firewall. Click 'Show All Scanned Ports' above to inspect closed/filtered port responses.",
    readyTitle: "Real TCP Socket Scanner Ready",
    readyDesc: "Enter your laptop's IP address (e.g. 127.0.0.1 or 192.168.x.x), check the Authorization Verification checkbox, and click 'Execute Real TCP Socket Probe' to run a native Node.js TCP handshake port audit on your laptop."
  },

  vulnScanner: {
    title: "Nessus / Qualys / OpenVAS Vulnerability Scanner Engine",
    subtitle: "Automated CVSS rating, exploit probability calculation, patch priority, and business impact analysis.",
    filterSeverity: "Filter Severity:",
    showingFindings: "vulnerability findings:",
    exploitAvailable: "Exploit Available: YES",
    patchPriority: "Priority:",
    businessImpact: "Business Impact: High Risk of Remote Data Exfiltration & Systems Ransom",
    nvdLink: "NVD Link"
  },

  reports: {
    title: "Automated AI Incident Response Report Exporter",
    subtitle: "Auto-generate CISO-ready incident reports with executive summary, timeline, IOCs, and remediation.",
    exportPdf: "Export PDF Report",
    exportMarkdown: "Export Markdown",
    confidentialTag: "CONFIDENTIAL / CISO ONLY",
    reportTitle: "CYBERMIND AI - INCIDENT RESPONSE REPORT",
    executiveSummary: "1. EXECUTIVE SUMMARY",
    mitreMapped: "2. MITRE ATT&CK TACTICS MAPPED",
    iocSection: "3. INDICATORS OF COMPROMISE (IOC)",
    maliciousIp: "Malicious Remote IP:",
    observedPort: "Observed C2 Port:",
    rogueAccount: "Rogue User Account:"
  },

  mitre: {
    title: "MITRE ATT&CK Enterprise Matrix Navigator",
    subtitle: "Interactive tactical coverage board showing active detected threat vectors highlighted in red.",
    flaggedTag: "FLAGGED IN CURRENT INCIDENT",
    techDetails: "Technique Details:"
  },

  ioc: {
    title: "IOC Threat Intelligence Database & Feeds",
    subtitle: "Search malicious IPs, file hashes, C2 domain names, and external threat intel feeds (AbuseIPDB, VirusTotal, Shodan).",
    searchPlaceholder: "Search IP, MD5/SHA256 Hash, Domain, Malware Name...",
    activeFeed: "Active Feed:",
    sourcesConnected: "4 Intelligence Sources Connected",
    indicator: "INDICATOR",
    threatType: "TYPE",
    classification: "THREAT CLASSIFICATION",
    confidence: "CONFIDENCE",
    originCountry: "ORIGIN / COUNTRY",
    intelSource: "INTELLIGENCE SOURCE"
  },

  simulation: {
    title: "Live Cyber Attack Simulation & SOC Response Lab",
    subtitle: "Simulate real-world attack vectors (Brute Force, Ransomware, PowerShell C2, SQLi) to test AI detection triggers.",
    simulationTag: "SIMULATION",
    launchBtn: "Launch Simulation",
    simulatingBtn: "Simulating Attack...",
    consoleTitle: "SOC Real-Time Event Stream Console",
    executingStatus: "EXECUTING PAYLOAD",
    idleStatus: "IDLE / READY",
    idlePrompt: "Click 'Launch Simulation' on any attack scenario above to stream live telemetry...",
    counterMeasureTitle: "CyberMind AI Automated Counter-Measure Triggered",
    mitigatedStatus: "MITIGATED"
  },

  copilot: {
    title: "SOC Analyst Copilot & Incident Investigation Playbooks",
    subtitle: "Guided incident triage playbooks with automated investigation checklists and host isolation triggers.",
    availablePlaybooks: "Available Playbooks:",
    stepsCount: "Step Guided Investigation",
    activeResponse: "Active Incident Response",
    emergencyTrigger: "Emergency Action Trigger:",
    isolateHostBtn: "Isolate Target Host DC-SRV-01"
  },

  rag: {
    title: "RAG Security Knowledge Base (NIST / OWASP / MITRE)",
    subtitle: "Search embedded cyber security knowledge base prioritized by AI analysis.",
    searchPlaceholder: "Search NIST 800-61, OWASP Top 10, Windows Event ID (e.g. 4625), MITRE T1059..."
  },

  chat: {
    title: "CyberMind AI Chat Assistant (Security Copilot)",
    subtitle: "Ask questions, query incident logs, request custom YARA/Sigma/PowerShell rules.",
    initialGreeting: "Greetings, Commander. I am CyberMind AI Security Copilot. Ask me any question regarding Windows Event logs, Linux Auth logs, Firewall rules, or request auto-generated mitigation scripts.",
    inputPlaceholder: "Ask: 'Why is this Windows Event suspicious?', 'Generate PowerShell block script'...",
    sendBtn: "Send",
    reasoningStatus: "CyberMind AI is reasoning..."
  },

  settings: {
    title: "System Settings & User Profile Configuration",
    subtitle: "Configure AI Engine Model, API key credentials, language preferences, and Role-Based Access Controls (RBAC).",
    languageSection: "Language & Regional Settings",
    languageDesc: "Choose the primary display language for the security operations console.",
    aiModelSection: "AI Engine Model Selection",
    deepReasoning: "Deep contextual reasoning (Recommended)",
    ultraFast: "Ultra fast log parsing & high throughput",
    offlineMode: "100% Offline local rule engine execution",
    apiKeySection: "API Keys & Secret Tokens",
    keyLabel: "Gemini / OpenAI API Key:",
    rbacSection: "Role-Based Access Control (RBAC)",
    adminRole: "Admin (Full Access)",
    analystRole: "SOC Analyst",
    engineerRole: "Security Engineer",
    readOnlyRole: "Read Only"
  },

  apiKeyModal: {
    title: "Configure AI API Key",
    description: "Enter your Google Gemini or OpenAI API Key to enable online contextual threat intelligence reasoning. If omitted, CyberMind AI operates using its built-in offline security rules engine.",
    placeholder: "AIzaSy... / sk-...",
    saveAndClose: "Save & Close"
  }
};
