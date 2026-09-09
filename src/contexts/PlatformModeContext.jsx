import React, { createContext, useContext, useState, useEffect } from 'react';
import { authFetch } from '../services/apiClient';

const PlatformModeContext = createContext({
  platformMode: 'LIVE',
  syntheticDataEnabled: false,
  seedDataEnabled: false,
  attackSimulationEnabled: false,
  runtimeModeSwitchAllowed: false,
  dataPolicy: {
    allowSyntheticInCurrentMode: false,
    defaultIncludeSynthetic: false,
    allowSeedInCurrentMode: false,
  },
  loading: true,
  refreshStatus: async () => {},
  switchMode: async () => {},
});

export function PlatformModeProvider({ children }) {
  const [platformStatus, setPlatformStatus] = useState({
    platformMode: 'LIVE',
    syntheticDataEnabled: false,
    seedDataEnabled: false,
    attackSimulationEnabled: false,
    runtimeModeSwitchAllowed: false,
    dataPolicy: {
      allowSyntheticInCurrentMode: false,
      defaultIncludeSynthetic: false,
      allowSeedInCurrentMode: false,
    },
  });
  const [loading, setLoading] = useState(true);

  const refreshStatus = async () => {
    try {
      const res = await authFetch('/api/platform/status');
      if (res.ok) {
        const data = await res.json();
        setPlatformStatus(data);
      }
    } catch (err) {
      console.warn('[PlatformModeContext] Fetch failed:', err);
    } finally {
      setLoading(false);
    }
  };

  const switchMode = async (targetMode, enableSynthetic = true, enableSeed = true) => {
    try {
      const res = await authFetch('/api/platform/mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetMode, enableSynthetic, enableSeed }),
      });
      if (res.ok) {
        await refreshStatus();
        return { success: true };
      } else {
        const errJson = await res.json().catch(() => ({}));
        return { success: false, error: errJson.error || `HTTP ${res.status}` };
      }
    } catch (err) {
      console.error('[PlatformModeContext] Mode switch failed:', err);
      return { success: false, error: err.message };
    }
  };

  useEffect(() => {
    refreshStatus();
  }, []);

  return (
    <PlatformModeContext.Provider
      value={{
        ...platformStatus,
        loading,
        refreshStatus,
        switchMode,
      }}
    >
      {children}
    </PlatformModeContext.Provider>
  );
}

export function usePlatformMode() {
  return useContext(PlatformModeContext);
}
