import React, { createContext, useContext, useState, useEffect } from 'react';
import { getAiStatus, testAiConnection } from '../services/apiClient';

const STORAGE_KEY = 'cybermind_ai_config';

const DEFAULT_CONFIG = {
  provider: 'local', // 'gemini' | 'openai' | 'custom' | 'local'
  apiKey: '',
  model: 'gemini-1.5-flash',
  baseUrl: 'http://localhost:11434/v1',
};

const AiConfigContext = createContext({
  aiConfig: DEFAULT_CONFIG,
  updateAiConfig: () => {},
  showApiModal: false,
  setShowApiModal: () => {},
  aiStatus: null,
  refreshAiStatus: async () => {},
  testCurrentConnection: async () => {},
  isOnlineApiConfigured: false,
});

export function AiConfigProvider({ children }) {
  const [aiConfig, setAiConfigState] = useState(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        return { ...DEFAULT_CONFIG, ...parsed };
      }
    } catch (e) {
      console.warn('[AiConfig] Failed to parse stored config:', e);
    }
    return DEFAULT_CONFIG;
  });

  const [showApiModal, setShowApiModal] = useState(false);
  const [aiStatus, setAiStatus] = useState(null);

  const updateAiConfig = (partialOrFn) => {
    setAiConfigState(prev => {
      const next = typeof partialOrFn === 'function' ? partialOrFn(prev) : { ...prev, ...partialOrFn };
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      } catch (e) {
        console.warn('[AiConfig] Failed to persist config:', e);
      }
      return next;
    });
  };

  const refreshAiStatus = async () => {
    try {
      const data = await getAiStatus();
      if (data) setAiStatus(data);
    } catch (err) {
      console.warn('[AiConfig] refresh status error:', err);
    }
  };

  const testCurrentConnection = async (overrideConfig) => {
    return await testAiConnection(overrideConfig || aiConfig);
  };

  useEffect(() => {
    refreshAiStatus();
    const interval = setInterval(refreshAiStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  const isOnlineApiConfigured = Boolean(
    (aiConfig.provider === 'gemini' || aiConfig.provider === 'openai' || aiConfig.provider === 'custom') &&
    aiConfig.apiKey &&
    aiConfig.apiKey.trim().length > 0
  );

  return (
    <AiConfigContext.Provider
      value={{
        aiConfig,
        updateAiConfig,
        showApiModal,
        setShowApiModal,
        aiStatus,
        refreshAiStatus,
        testCurrentConnection,
        isOnlineApiConfigured,
      }}
    >
      {children}
    </AiConfigContext.Provider>
  );
}

export function useAiConfig() {
  return useContext(AiConfigContext);
}
