import { getStoredToken } from '../contexts/AuthContext';

export const API_BASE = '/api';

let bootstrapPromise = null;

export async function ensureToken() {
  let token = getStoredToken();
  if (token) return token;

  // If user explicitly chose Guest, do not auto-authenticate
  try {
    const raw = localStorage.getItem('cybermind_auth_session');
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed.user?.role === 'Guest') return '';
    }
  } catch {}

  // In DEMO mode, bootstrap an initial evaluation session using the server's demo role switch.
  // In LIVE mode, /api/auth/switch-role returns 403 Forbidden; unauthenticated requests receive 401
  // and dispatch auth:expired to prompt standard credential login. No passwords are hardcoded in client bundle.
  if (!bootstrapPromise) {
    bootstrapPromise = fetch('/api/auth/switch-role', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'Admin' })
    })
      .then(r => (r.ok ? r.json() : null))
      .then(d => {
        if (d?.token) {
          localStorage.setItem('cybermind_auth_session', JSON.stringify({
            token: d.token,
            user: d.user
          }));
          return d.token;
        }
        return '';
      })
      .catch(() => '')
      .finally(() => {
        bootstrapPromise = null;
      });
  }
  return bootstrapPromise;
}

export async function authFetch(url, options = {}) {
  let token = getStoredToken();
  if (!token) {
    token = await ensureToken();
  }
  const headers = new Headers(options.headers || {});
  
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  
  const response = await fetch(url, {
    ...options,
    headers
  });

  if (response.status === 401 && !url.includes('/api/auth/login')) {
    console.warn('[API Client] 401 Unauthorized received from server. Session expired or invalid.');
    window.dispatchEvent(new CustomEvent('auth:expired', { detail: { url } }));
  }

  return response;
}

// ─── Collector Management APIs ─────────────────────────────────────────────

export async function fetchCollectorStatus() {
  try {
    const res = await authFetch(`${API_BASE}/collectors/status`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchCollectorStatus fallback:', err.message);
    return null;
  }
}

export async function fetchCollectorMetrics() {
  try {
    const res = await authFetch(`${API_BASE}/collectors/metrics`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchCollectorMetrics fallback:', err.message);
    return null;
  }
}

export async function fetchCollectorEvents(params = {}) {
  try {
    const query = new URLSearchParams(params).toString();
    const res = await authFetch(`${API_BASE}/collectors/events?${query}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchCollectorEvents fallback:', err.message);
    return null;
  }
}

export async function controlCollectorState(collectorName, action) {
  try {
    const res = await authFetch(`${API_BASE}/collectors/${collectorName}/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn(`[API Client] controlCollectorState ${action} failed:`, err.message);
    return null;
  }
}

// ─── Core SOC APIs ───────────────────────────────────────────────────────────

export async function ingestLogs(logText, logType = 'windows') {
  try {
    const res = await authFetch(`${API_BASE}/ingest/logs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ logText, logType })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] ingestLogs fallback:', err.message);
    return null;
  }
}

export async function fetchVulnerabilities() {
  try {
    const res = await authFetch(`${API_BASE}/vulnerabilities`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchVulnerabilities fallback:', err.message);
    return null;
  }
}

export async function fetchAssetInventory() {
  try {
    const res = await authFetch(`${API_BASE}/assets`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchAssetInventory fallback:', err.message);
    return null;
  }
}

export async function generatePdfReport(reportParams) {
  try {
    const res = await authFetch(`${API_BASE}/reports/pdf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reportParams)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.blob();
  } catch (err) {
    console.warn('[API Client] generatePdfReport fallback:', err.message);
    return null;
  }
}

// ─── Network Flow / SPAN APIs ────────────────────────────────────────────────

export async function fetchLiveNetworkFlows() {
  try {
    const res = await authFetch(`${API_BASE}/network-flows`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchLiveNetworkFlows fallback:', err.message);
    return null;
  }
}

// ─── Packet Analysis APIs ─────────────────────────────────────────────────────

export async function fetchPcapSample() {
  try {
    const res = await authFetch(`${API_BASE}/packets/sample`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchPcapSample fallback:', err.message);
    return null;
  }
}

// ─── Asset Discovery APIs ─────────────────────────────────────────────────────

export async function fetchDiscoveryScope() {
  try {
    const res = await authFetch(`${API_BASE}/discovery/scope`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchDiscoveryScope fallback:', err.message);
    return null;
  }
}

export async function runAssetDiscoverySweep(targetCidr) {
  try {
    const res = await authFetch(`${API_BASE}/discovery/sweep`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetCidr })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] runAssetDiscoverySweep fallback:', err.message);
    return null;
  }
}

// ─── SIEM Collector APIs ──────────────────────────────────────────────────────

export async function fetchSiemEvents(category = 'ALL', severity = 'ALL') {
  try {
    const params = new URLSearchParams();
    if (category && category !== 'ALL') params.append('category', category);
    if (severity && severity !== 'ALL') params.append('severity', severity);
    const res = await authFetch(`${API_BASE}/siem/events?${params.toString()}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchSiemEvents fallback:', err.message);
    return null;
  }
}

export async function fetchMultiVectorCorrelation() {
  try {
    const res = await authFetch(`${API_BASE}/siem/correlate`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchMultiVectorCorrelation fallback:', err.message);
    return null;
  }
}

// ─── Phase 4: Real AI APIs ────────────────────────────────────────────────────

export async function getAiStatus() {
  try {
    const res = await authFetch(`${API_BASE}/ai/status`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] getAiStatus fallback:', err.message);
    return { geminiConfigured: false, mode: 'OFFLINE' };
  }
}

export async function sendAiChatMessage(history, message, includeContext = true, aiConfig = null) {
  const payload = {
    history,
    message,
    includeContext,
  };
  if (aiConfig) {
    if (typeof aiConfig === 'string') {
      payload.apiKey = aiConfig;
    } else {
      payload.aiConfig = aiConfig;
      if (aiConfig.apiKey) payload.apiKey = aiConfig.apiKey;
    }
  }
  const res = await authFetch(`${API_BASE}/ai/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.error || `HTTP ${res.status}`);
  }
  return await res.json();
}

export async function testAiConnection(aiConfig) {
  try {
    const res = await authFetch(`${API_BASE}/ai/test-connection`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ aiConfig }),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      return { success: false, message: errData.error || `HTTP ${res.status}` };
    }
    return await res.json();
  } catch (err) {
    return { success: false, message: err.message };
  }
}

// ─── Phase 4: Real OS Network Discovery ──────────────────────────────────────

export async function fetchLocalNetworkDiscovery() {
  try {
    const res = await authFetch(`${API_BASE}/discovery/localhost`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchLocalNetworkDiscovery fallback:', err.message);
    return null;
  }
}

export async function fetchArpTable() {
  try {
    const res = await authFetch(`${API_BASE}/discovery/arp`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchArpTable fallback:', err.message);
    return null;
  }
}

export async function fetchNetstatConnections() {
  try {
    const res = await authFetch(`${API_BASE}/discovery/netstat`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchNetstatConnections fallback:', err.message);
    return null;
  }
}

// ─── Phase 4: Real PCAP Upload ────────────────────────────────────────────────

export async function uploadPcapFile(file) {
  try {
    const formData = new FormData();
    formData.append('pcapFile', file);
    const res = await authFetch(`${API_BASE}/packets/upload`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return await res.json();
  } catch (err) {
    console.warn('[API Client] uploadPcapFile error:', err.message);
    throw err;
  }
}

// ─── Phase 4: Real Threat Intel ───────────────────────────────────────────────

export async function fetchThreatIntelIocs(type) {
  try {
    const url = type ? `${API_BASE}/threat-intel/iocs?type=${type}` : `${API_BASE}/threat-intel/iocs`;
    const res = await authFetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchThreatIntelIocs fallback:', err.message);
    return null;
  }
}

// ─── Phase 4: Sigma Rules (Detection-as-Code) ─────────────────────────────────

export async function fetchSigmaRules() {
  try {
    let res = await authFetch(`${API_BASE}/sigma/rules`);
    if (!res.ok) {
      res = await authFetch(`${API_BASE}/ingest/sigma/rules`);
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchSigmaRules fallback:', err.message);
    return { total: 0, rules: [] };
  }
}

export async function runSigmaScan(events) {
  try {
    const res = await authFetch(`${API_BASE}/ingest/sigma/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] runSigmaScan fallback:', err.message);
    return null;
  }
}

// ─── Phase 4: Real NVD CVE Lookup ────────────────────────────────────────────

export async function lookupCveByProduct(software) {
  try {
    const list = Array.isArray(software) ? software : [software];
    const res = await authFetch(`${API_BASE}/vulnerabilities/lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ software: list }),
    });
    if (res.ok) {
      return await res.json();
    }
    // Fallback to GET /api/vulnerabilities/search
    if (list.length > 0 && list[0]?.name) {
      const q = encodeURIComponent(`${list[0].name} ${list[0].version || ''}`.trim());
      const searchRes = await authFetch(`${API_BASE}/vulnerabilities/search?query=${q}`);
      if (searchRes.ok) return await searchRes.json();
    }
    return { vulnerabilities: [] };
  } catch (err) {
    console.warn('[API Client] lookupCveByProduct fallback:', err.message);
    return { vulnerabilities: [] };
  }
}

// ─── Phase 5: Incident Management & Escalation APIs ──────────────────────────

export async function fetchIncidentCases() {
  try {
    const res = await authFetch(`${API_BASE}/investigation/incidents`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchIncidentCases fallback:', err.message);
    return { incidents: [] };
  }
}

export async function createIncidentCase(incidentData) {
  try {
    const res = await authFetch(`${API_BASE}/investigation/incidents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(incidentData),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return await res.json();
  } catch (err) {
    console.error('[API Client] createIncidentCase failed:', err.message);
    throw err;
  }
}

export async function updateIncidentCase(id, patchData) {
  try {
    const res = await authFetch(`${API_BASE}/investigation/incidents/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patchData),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.error('[API Client] updateIncidentCase failed:', err.message);
    throw err;
  }
}

export async function escalateEventToIncident(event) {
  const payload = {
    title: `[SIEM Escalate] ${event.summary?.slice(0, 80) || 'Correlated Security Alert'}`,
    severity: event.severity || 'Medium',
    sourceIp: event.rawDetails?.IpAddress || event.rawDetails?.src_ip || event.rawDetails?.srcip || 'Unknown',
    targetIp: event.hostName || event.rawDetails?.dest_ip || 'Internal Asset',
    mitreTechnique: event.mitreTechnique || 'T1071',
    summary: event.summary || 'Escalated from SIEM Event Console',
    notes: [`Escalated from EventID ${event.eventId || 'GENERIC'} at ${new Date().toLocaleString()}`],
  };
  return await createIncidentCase(payload);
}

// ─── Centralized Risk Score & GeoIP APIs ─────────────────────────────────────

export async function fetchRiskScore() {
  try {
    const res = await authFetch(`${API_BASE}/threats/risk-score`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchRiskScore fallback:', err.message);
    return null;
  }
}

export async function fetchIpGeo(ip) {
  try {
    const res = await authFetch(`${API_BASE}/threats/geoip/${encodeURIComponent(ip)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchIpGeo fallback:', err.message);
    return null;
  }
}

// ─── Singleton WebSocket Connection Manager ──────────────────────────────────

let globalWs = null;
let reconnectTimer = null;
let isConnecting = false;
const telemetryListeners = new Set();

async function initGlobalWebSocket() {
  if (globalWs && (globalWs.readyState === WebSocket.OPEN || globalWs.readyState === WebSocket.CONNECTING)) {
    return;
  }
  if (isConnecting) return;
  isConnecting = true;

  try {
    let token = getStoredToken();
    if (!token) {
      token = await ensureToken();
    }

    if (!token) {
      isConnecting = false;
      return;
    }

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsHost = window.location.hostname;
    const wsPort = '5000';
    const wsUrl = `${wsProtocol}//${wsHost}:${wsPort}/ws/telemetry?token=${encodeURIComponent(token)}`;

    globalWs = new WebSocket(wsUrl);

    globalWs.onopen = () => {
      isConnecting = false;
      console.log('[WebSocket] Singleton Live Telemetry Stream connected.');
      telemetryListeners.forEach(l => l.onOpen && l.onOpen());
    };

    globalWs.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        telemetryListeners.forEach(l => l.onMessage && l.onMessage(data));
      } catch (e) {
        console.warn('[WebSocket] Message parse error:', e);
      }
    };

    globalWs.onclose = () => {
      isConnecting = false;
      globalWs = null;
      console.log('[WebSocket] Connection closed. Auto-reconnect in 5s...');
      telemetryListeners.forEach(l => l.onClose && l.onClose());

      if (!reconnectTimer) {
        reconnectTimer = setTimeout(() => {
          reconnectTimer = null;
          if (telemetryListeners.size > 0) initGlobalWebSocket();
        }, 5000);
      }
    };

    globalWs.onerror = (err) => {
      isConnecting = false;
      console.warn('[WebSocket] Connection error (backend may be offline)', err);
    };
  } catch (err) {
    isConnecting = false;
    console.warn('[WebSocket] Connection setup failed:', err);
  }
}

export function connectLiveTelemetryStream(onMessage, onOpen, onClose) {
  const listenerObj = { onMessage, onOpen, onClose };
  telemetryListeners.add(listenerObj);

  initGlobalWebSocket();

  if (globalWs && globalWs.readyState === WebSocket.OPEN && onOpen) {
    onOpen();
  }

  return {
    close: () => {
      telemetryListeners.delete(listenerObj);
      if (telemetryListeners.size === 0 && globalWs) {
        // Linger for 10 seconds before physically closing in case another component mounts
        setTimeout(() => {
          if (telemetryListeners.size === 0 && globalWs) {
            globalWs.close();
            globalWs = null;
          }
        }, 10000);
      }
    }
  };
}

async function parseResponseJson(res) {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    return { error: text?.slice(0, 300) || `HTTP ${res.status} ${res.statusText}` };
  }
}

// ─── Detection-as-Code: Sigma YAML Rules API ─────────────────────────────────

export async function testSigmaRule(yamlContent, events = []) {
  const res = await authFetch(`${API_BASE}/sigma/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ yaml: yamlContent, events }),
  });
  const data = await parseResponseJson(res);
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

export async function createSigmaRule(yamlContent, persist = false) {
  const res = await authFetch(`${API_BASE}/sigma/rules`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ yaml: yamlContent, persist }),
  });
  const data = await parseResponseJson(res);
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

export async function reloadSigmaRules() {
  const res = await authFetch(`${API_BASE}/sigma/reload`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  const data = await parseResponseJson(res);
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ─── SOAR Automated Actions & Webhook Dispatcher API ──────────────────────────

export async function executeSoarBlockIp({ ip, reason, severity, incidentId, ruleId, force }) {
  const res = await authFetch(`${API_BASE}/soar/playbooks/block-ip`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, reason, severity, incidentId, ruleId, force }),
  });
  const data = await parseResponseJson(res);
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

export async function executeSoarUnblockIp(ip) {
  const res = await authFetch(`${API_BASE}/soar/playbooks/unblock-ip`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  });
  const data = await parseResponseJson(res);
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

export async function fetchBlockedIps() {
  try {
    const res = await authFetch(`${API_BASE}/soar/blocked-ips`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchBlockedIps fallback:', err.message);
    return { total: 0, blockedIps: [] };
  }
}

export async function dispatchSoarWebhook(payload) {
  const res = await authFetch(`${API_BASE}/soar/playbooks/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await parseResponseJson(res);
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

export async function generateSoarFirewallRules(ip, reason) {
  const res = await authFetch(`${API_BASE}/soar/playbooks/generate-rules`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, reason }),
  });
  const data = await parseResponseJson(res);
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

export async function generateHostIsolationScript(hostOrIp, os = 'windows') {
  const res = await authFetch(`${API_BASE}/soar/playbooks/isolate-host`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hostOrIp, os }),
  });
  const data = await parseResponseJson(res);
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

export async function fetchSoarHistory(limit = 50) {
  try {
    const res = await authFetch(`${API_BASE}/soar/history?limit=${limit}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchSoarHistory fallback:', err.message);
    return { total: 0, history: [] };
  }
}


