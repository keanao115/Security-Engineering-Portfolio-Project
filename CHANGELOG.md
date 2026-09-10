# Changelog

All notable changes to the **CyberMind AI — Security Engineering Portfolio Project** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.0.0] - 2026-09-10

### Added
- **Enterprise Maturity Audit Remediation**: Comprehensive defense-in-depth hardening across 13 engineering dimensions.
- **End-to-End HTTP API Integration Test Suite**: Added `api_integration.test.ts` covering health probes, authentication flow, RBAC enforcement, SIEM event pagination, and network scanning boundaries.
- **WebSocket Security Handshake**: Added strict JWT verification (`verifyWebSocketHandshake`) supporting both query parameter (`?token=`) and Authorization Bearer headers.
- **SSRF & Network Boundary Protection**: Enforced RFC-1918 and whitelist validation (`isIpInAuthorizedScope`) on active port scanner `/api/threats/scan` to block external probe attacks.
- **Fail-Safe Boot Environment Validation**: Added `enforceEnvironmentConfig()` validating required secrets (`JWT_SECRET`, ports, operating mode) at boot time with immediate process exit on failure.
- **Granular Rate Limiting**: Added `aiRateLimiter` (20 req/min) to defend against LLM quota abuse and `scanRateLimiter` (30 req/min) to prevent port scan denial-of-service.
- **LLM Timeout & Local Fallback Engine**: Wrapped Gemini AI requests with 30-second `Promise.race` timeout protection and automatic degradation to deterministic local rule inference.
- **Structured JSON Logger**: Implemented enterprise logger (`logger.ts`) with ISO 8601 timestamps, module tags, severity levels, and automated credential desensitization.
- **SIEM Event Stream Pagination**: Implemented dual-layer pagination in `/api/siem/events` and frontend `SiemEventConsole.jsx` with customizable page sizes.
- **Repository Governance & Compliance**: Added `LICENSE` (MIT), `.github/dependabot.yml`, `.prettierrc`, `.editorconfig`, `CONTRIBUTING.md`, and `docs/API_SPECIFICATION.md`.

### Security & Hardening
- **Container Least Privilege**: Updated `deploy/Dockerfile.server` to execute under unprivileged `node` user with explicit file ownership (`--chown=node:node`).
- **Dependency Vulnerability Remediation**: Upgraded `multer` to 2.3.0+ and `nanoid` to 3.3.18 to eliminate critical and high-severity CVE advisories.
- **Git Index Hygiene**: Purged 6,930 inadvertently committed dependency files from the Git tracking index.
- **Collector Port Synchronization**: Aligned UDP/TCP ports for Syslog, WEF, and NetFlow between `server/src/index.ts` and `deploy/docker-compose.yml`.

### Changed
- Expanded automated test coverage from 40 unit tests to **112+ automated tests** across 49 test suites with 100% passing status.

---

## [2.0.0] - 2026-08-15

### Added
- Enterprise Telemetry Collectors: RFC 3164/5424 Syslog, Windows Event Forwarding (WEF XML), and NetFlow v5/v9/IPFIX collectors.
- Deep Packet Inspection: Binary PCAP decoder with JA3 and JA4 TLS fingerprint generation.
- IDS & Protocol Ingestion: Zeek connection log and Suricata EVE IDS alert parsers.
- Unified Evidence Timeline Engine: Multi-source event correlation by target IP and MITRE ATT&CK tactics.

---

## [1.0.0] - 2026-07-01

### Added
- Initial release of CyberMind SOC Platform with React Vite frontend and Express backend.
- Role-Based Access Control (RBAC) with Admin, Analyst, and Viewer tiers.
- NIST NVD CVE API v2.0 integration with in-memory caching.
- Incident case management and investigation lifecycle.
