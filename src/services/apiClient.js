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

  // Otherwise, bootstrap initial Admin session
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
  
  return fetch(url, {
    ...options,
    headers
  });
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

export async function analyzeThreatsWithAi(telemetryData) {
  try {
    const res = await authFetch(`${API_BASE}/threats/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(telemetryData)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] analyzeThreatsWithAi fallback:', err.message);
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

export async function analyzePcapContent(fileName, rawBufferText) {
  try {
    const res = await authFetch(`${API_BASE}/packets/analyze-pcap`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fileName, rawBufferText })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] analyzePcapContent fallback:', err.message);
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

export async function analyzeWithGeminiAi(telemetryData, aiConfig = null) {
  try {
    const payload = { ...telemetryData };
    if (aiConfig) {
      if (typeof aiConfig === 'string') {
        payload.apiKey = aiConfig;
      } else {
        payload.aiConfig = aiConfig;
        if (aiConfig.apiKey) payload.apiKey = aiConfig.apiKey;
      }
    }
    const res = await authFetch(`${API_BASE}/ai/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] analyzeWithGeminiAi fallback:', err.message);
    return null;
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

// ─── Phase 4: Sigma Rules ─────────────────────────────────────────────────────

export async function fetchSigmaRules() {
  try {
    const res = await authFetch(`${API_BASE}/ingest/sigma/rules`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] fetchSigmaRules fallback:', err.message);
    return null;
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
    const res = await authFetch(`${API_BASE}/vulnerabilities/lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ software }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] lookupCveByProduct fallback:', err.message);
    return null;
  }
}

// ─── Singleton WebSocket Connection Manager ──────────────────────────────────

let globalWs = null;
let reconnectTimer = null;
let isConnecting = false;
const telemetryListeners = new Set();

function initGlobalWebSocket() {
  if (globalWs && (globalWs.readyState === WebSocket.OPEN || globalWs.readyState === WebSocket.CONNECTING)) {
    return;
  }
  if (isConnecting) return;
  isConnecting = true;

  try {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsHost = window.location.hostname;
    const wsPort = '5000';
    const wsUrl = `${wsProtocol}//${wsHost}:${wsPort}/ws/telemetry`;

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
      console.warn('[WebSocket] Connection error (backend may be offline)');
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
