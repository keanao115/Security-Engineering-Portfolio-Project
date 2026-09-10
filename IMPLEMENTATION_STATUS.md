# CyberMind AI — Implementation Truthfulness Matrix & Provenance Register

> **Portfolio Engineering Standard**: In alignment with zero-trust engineering ethics and enterprise portfolio transparency, every telemetry collector, parser, security engine, and AI capability in CyberMind AI is strictly categorized by operational truthfulness. No simulated metrics or synthetic mocks are presented as genuine live production data.

---

## 1. Provenance Classification Taxonomy

| Taxonomy Tier | Definition & Security Engineering Boundary |
|---|---|
| **`REAL`** | End-to-end execution against genuine system sockets, network interfaces, real file binary formats, remote cryptographic APIs, or deterministic rule engines. |
| **`PARTIAL`** | True network/OS interaction with environmental dependencies or fallback logic when external kernel drivers / elevated privileges are absent. |
| **`REPLAY`** | Ingestion of genuine captured industry artifacts (e.g., real PCAP binaries, real Suricata EVE JSON, real Zeek logs) parsed by production decoding logic. |
| **`SEEDED`** | Pre-populated realistic baseline entities in memory for development, testing, and isolated evaluation without internet connectivity. |
| **`SIMULATED`** | Explicitly flagged synthetic attack scenarios and telemetry generators utilized strictly for controlled testing, SOC drills, and non-production demonstration. |
| **`LEGACY`** | Deprecated historical code paths retained for backward-compatibility or migration reference, isolated from primary execution paths. |

---

## 2. Master Feature Status Matrix

| Feature | Classification | Source Code Location | Operational Mechanics & Truthfulness Guarantees |
|---|---|---|---|
| **Local Host Discovery** | `REAL` | `server/src/services/osNetworkDiscovery.ts` | Queries OS kernel via `os.networkInterfaces()`, retrieves real local IP/subnet, identifies loopback, and computes CIDR boundaries. |
| **TCP Connect Port Scanner** | `REAL` | `server/src/routes/threatRoutes.ts` | Initiates genuine TCP three-way handshake (`net.Socket.connect`), enforces explicit timeout controls, validates target hosts against SSRF boundaries. |
| **ARP Discovery** | `REAL / OS Dependent` | `server/src/services/osNetworkDiscovery.ts` | Parses OS ARP table via native `arp -a` CLI execution; explicitly flags OS platform limitations and returns genuine MAC-to-IP pairings. |
| **Netstat / Active Sockets** | `REAL / OS Dependent` | `server/src/services/osNetworkDiscovery.ts` | Executes OS native socket inspection (`netstat -ano` / `ss -tn`) and parses active TCP/UDP listening states without fabrication. |
| **PCAP Binary Parser** | `REAL` | `server/src/capture/packetDecoder.ts`<br>`server/src/routes/packetRoutes.ts` | Decodes Ethernet frame headers (EtherType 0x0800 IPv4, 0x86DD IPv6), IPv4/IPv6 packet headers, and TCP/UDP transport layers directly from raw binary buffers. |
| **PCAP Upload & Inspection** | `REAL` | `server/src/routes/packetRoutes.ts` | Uploads raw PCAP file buffers via multer, parses global headers (magic `0xa1b2c3d4` / `0xd4c3b2a1`), validates snaplen, and iterates packet records. |
| **Interface Enumeration** | `REAL` | `server/src/capture/interfaceManager.ts` | Queries OS network interfaces; dynamically detects loopback; removed all hardcoded Hyper-V fake MACs and reports genuine hardware state or 'Unavailable'. |
| **Live Packet Capture** | `PARTIAL` | `server/src/capture/captureManager.ts` | Stateful capture session manager with BPF filter validation and buffer flow queuing; supports native Npcap binding when elevated driver is present. |
| **Nmap Telemetry Parser** | `REAL` | `server/src/adapters/nmapParser.ts` | Ingests genuine Nmap XML / text reports, extracting open ports, service banners, and protocol states. |
| **Zeek Telemetry Collector** | `REAL / REPLAY` | `server/src/collectors/zeek/zeekCollector.ts` | Parses Zeek TSV / JSON streaming log files (`conn.log`, `dns.log`, `ssl.log`, `http.log`), standardizes fields into enterprise telemetry events. |
| **Suricata EVE IDS Ingest** | `REAL / REPLAY` | `server/src/collectors/suricata/suricataCollector.ts` | Consumes real Suricata `eve.json` streaming events, mapping alerts, signatures, categories, severity levels, and protocol metadata. |
| **Syslog Collector (RFC 5424/3164)** | `REAL` | `server/src/collectors/syslog/syslogCollector.ts`<br>`server/src/collectors/syslogCollectorService.ts` | Binds real UDP/TCP sockets (default port 5140/514), parses RFC 5424 PRI/Facility/Severity headers and ISO timestamps. |
| **WEF / Windows Event Collector** | `PARTIAL` | `server/src/collectors/wefCollectorService.ts` | Ingests Windows Event XML / JSON payloads, standardizing EventID 4624 (Logon), 4625 (Failed Logon), 4688 (Process Creation) into unified schema. |
| **NetFlow v5/v9 Decoder** | `REAL` | `server/src/collectors/netflowCollectorService.ts` | Decodes binary NetFlow datagrams, unpacking 5-tuple metrics, packet counts, byte counts, and autonomous system numbers. |
| **NVD CVE Lookup & Synchronization** | `REAL` | `server/src/services/nvdCveService.ts` | Connects directly to NIST NVD REST API v2.0 with API key authentication, in-memory caching, CVSS v3.1 vector calculation, and rate-limiting. |
| **Exploit Availability Correlation** | `REAL (EVIDENCE-BACKED)` | `server/src/services/nvdCveService.ts` | Verifies exploitability strictly against CISA KEV (`cve.cisaExploitAdd`) and certified exploit reference sources; eliminates incorrect configuration counting bugs. |
| **Threat Intel Feeds & CISA KEV** | `REAL` | `server/src/services/threatIntelService.ts` | Synchronizes with CISA Known Exploited Vulnerabilities catalog, AlienVault OTX, and Tor exit node lists with provenance headers. |
| **Sigma Detection Rule Engine** | `REAL` | `server/src/services/sigmaRuleEngine.ts` | Evaluates detection rules against unified telemetry event streams using pattern matching, condition trees, and severity classification. |
| **Explainable Risk Scoring** | `REAL` | `server/src/services/riskScoringService.ts` | Pure deterministic CVSS v3.1 + open ports penalty formula (`100 - (Critical*18 + High*9 + Medium*3 + OpenPorts*2)`); no hidden score mocks. |
| **AI Security Copilot** | `REAL` | `server/src/services/geminiAiService.ts` | Multi-provider architecture (Gemini / OpenAI / Claude / Local Ollama) using evidence-grounded prompt engineering with SSRF destination validation. |
| **RAG Knowledge Base** | `STATIC REFERENCE` | `src/utils/ragDatabase.js` | Local threat intelligence corpus embedding and semantic retrieval grounded in vetted MITRE ATT&CK techniques and incident playbooks. |
| **Attack Simulation Suite** | `SIMULATED` | `server/src/demo/syntheticFlowGenerator.ts`<br>`src/components/AttackSimulationView.jsx` | Explicitly marked as synthetic attack scenarios (Port Scan, Brute Force, Data Exfiltration) for red/blue SOC training and verification. |
| **Role-Based Access Control (RBAC)** | `REAL` | `server/src/services/userService.ts`<br>`server/src/routes/authRoutes.ts` | Scrypt password hashing with cryptographic salt, server-authoritative role store; client role spoofing strictly rejected; mode switch enforced. |

---

## 3. Platform Operating Modes & Guardrails

```
┌─────────────────────────────────────────────────────────────┐
│                     PLATFORM_MODE                           │
├──────────────────────────────┬──────────────────────────────┤
│          LIVE MODE           │          DEMO MODE           │
├──────────────────────────────┼──────────────────────────────┤
│ • Synthetic generation OFF   │ • Synthetic generation OK    │
│ • Client role-switch BLOCKED │ • Role switching permitted   │
│ • Real network scans ONLY    │ • Offline seed assets loaded │
│ • Strict CSP & Origin checks │ • Training scenarios active  │
└──────────────────────────────┴──────────────────────────────┘
```

### Security Guardrails Enforced in `LIVE` Mode:
1. **Zero Fake Metrics**: Fallback numbers or mock generators are barred from execution paths.
2. **SSRF Boundary Control**: Outbound AI and API requests block link-local (`169.254.169.254`) and unauthorized internal RFC 1918 subnets.
3. **Role Elevation Lockout**: `POST /api/auth/switch-role` returns `403 Forbidden`; role changes require re-authentication with valid cryptographic credentials.
4. **Input Sanitization**: Client-side Markdown rendering is wrapped with DOMPurify XSS defenses.
