# CyberMind AI — REST & WebSocket API Specification

This document provides the definitive specification for all API endpoints exposed by the **CyberMind AI Security Operations Center (SOC) Engine** (v3.0.0).

---

## 🔒 Authentication & Authorization Model

All protected endpoints require an RFC 6750 Bearer Token in the HTTP `Authorization` header:

```http
Authorization: Bearer <JWT_TOKEN>
```

### Role-Based Access Control (RBAC) Matrix

| Role | Permissions | Typical Operations |
|---|---|---|
| **Admin** | Full System Access | Platform mode switching, collector management, incident creation, port scanning, AI inference |
| **Analyst** | Read & Write SOC Operations | Event ingestion, incident triage, log ingestion, vulnerability management, report generation |
| **Viewer** | Read-Only Access | Query dashboards, view telemetry streams, inspect health metrics |

---

## 1. Health & Kubernetes Probes

### `GET /health/live`
- **Auth**: None (Public)
- **Description**: Kubernetes liveness probe checking if the Node.js process is responsive.
- **Response (200 OK)**:
```json
{
  "status": "UP",
  "timestamp": "2026-09-10T10:00:00.000Z",
  "uptimeSeconds": 1240
}
```

### `GET /health/ready`
- **Auth**: None (Public)
- **Description**: Kubernetes readiness probe verifying that telemetry collectors and database connections are ready.
- **Response (200 OK or 503 Service Unavailable)**:
```json
{
  "status": "READY",
  "timestamp": "2026-09-10T10:00:00.000Z",
  "uptimeSeconds": 1240,
  "collectors": [
    { "name": "Syslog-Server", "state": "RUNNING", "ready": true }
  ]
}
```

### `GET /metrics`
- **Auth**: None (Public / Scraped by Prometheus)
- **Description**: Exposes OpenMetrics / Prometheus formatted telemetry counters.
- **Content-Type**: `text/plain; version=0.0.4`

---

## 2. Authentication Routes (`/api/auth`)

### `POST /api/auth/login`
- **Auth**: None
- **Body**:
```json
{
  "username": "admin",
  "password": "Admin@CyberMind2026!"
}
```
- **Response (200 OK)**:
```json
{
  "message": "Authentication successful",
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "Admin",
    "displayName": "CyberMind Security Administrator"
  }
}
```

---

## 3. Platform Mode & Configuration (`/api/platform`)

### `GET /api/platform/status`
- **Auth**: None (Public operational flags for client bootstrap)
- **Response (200 OK)**:
```json
{
  "platformMode": "DEMO",
  "syntheticDataEnabled": true,
  "seedDataEnabled": true,
  "attackSimulationEnabled": true,
  "uptimeSeconds": 1240
}
```

### `POST /api/platform/mode`
- **Auth**: `Admin` only
- **Body**: `{ "targetMode": "LIVE" | "DEMO" }`
- **Response (200 OK)**: Updated platform configuration.

---

## 4. SIEM & Log Telemetry (`/api/siem`)

### `GET /api/siem/events`
- **Auth**: `Admin`, `Analyst`, `Viewer`
- **Query Parameters**:
  - `page` (optional, integer >= 1)
  - `limit` (optional, integer 1–200)
  - `category` (optional, string: `Windows_WEF`, `Sysmon`, `Linux_Auditd`, `Zeek`, `Suricata`)
  - `severity` (optional, string: `Critical`, `High`, `Medium`, `Low`, `Info`)
- **Response (200 OK)**:
```json
{
  "total": 142,
  "page": 1,
  "limit": 10,
  "totalPages": 15,
  "events": [
    {
      "id": "SIEM-001",
      "timestamp": "2026-09-10T09:45:00.000Z",
      "sourceCategory": "Windows_WEF",
      "hostName": "DC-SRV-01.corp.internal",
      "severity": "High",
      "eventId": "4625",
      "mitreTechnique": "T1110.001",
      "summary": "Multiple failed logon attempts for Administrator."
    }
  ]
}
```

---

## 5. Threat Detection & Network Scanner (`/api/threats`)

### `GET /api/threats/risk-score`
- **Auth**: `Admin`, `Analyst`, `Viewer`
- **Response (200 OK)**: Centralized explainable CVSS v3.1 posture assessment.

### `GET /api/threats/scan`
- **Auth**: `Admin`, `Analyst` (Rate limited to 30 req/min)
- **Query Parameters**: `target` (e.g. `127.0.0.1`, `192.168.1.1`)
- **Security Boundary**: Public IP ranges or octal/hex SSRF notations are rejected with `403 Forbidden` or `400 Bad Request`.
- **Response (200 OK)**:
```json
{
  "host": "127.0.0.1",
  "scanTime": "2026-09-10T10:00:00.000Z",
  "scannedPortsCount": 21,
  "openPorts": [
    { "port": 5000, "service": "SOC-Backend", "state": "open" }
  ]
}
```

---

## 6. AI SOC Copilot (`/api/ai`)

### `POST /api/ai/chat`
- **Auth**: `Admin`, `Analyst` (Rate limited to 20 req/min)
- **Timeout**: 30 seconds with automatic fallback to deterministic local rules engine.
- **Body**:
```json
{
  "message": "Explain MITRE ATT&CK technique T1110.001 and recommended mitigation.",
  "history": []
}
```
- **Response (200 OK)**:
```json
{
  "reply": "MITRE ATT&CK T1110.001 refers to Password Guessing...",
  "source": "GEMINI_1.5_FLASH" | "LOCAL_INFERENCE_FALLBACK"
}
```

---

## 7. Live Telemetry WebSocket

### `ws://localhost:5000/ws/telemetry?token=<JWT>`
- **Protocol**: WebSocket (RFC 6455)
- **Handshake Verification**: Requires valid JWT token in query parameter `?token=` or HTTP `Authorization` header.
- **Event Types Broadcasted**:
  - `SIEM_EVENT`: New normalized security event.
  - `NETWORK_FLOW`: Network conversation flow update.
  - `METRIC_UPDATE`: System posture or collector watermark metrics.
