import React, { useState } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import DashboardView from './components/DashboardView';
import VulnerabilityScannerView from './components/VulnerabilityScannerView';
import IncidentReportsView from './components/IncidentReportsView';
import AttackSimulationView from './components/AttackSimulationView';
import SettingsView from './components/SettingsView';
import ApiKeyModal from './components/ApiKeyModal';
import AssetDiscoveryView from './components/AssetDiscoveryView';
import SiemEventConsole from './components/SiemEventConsole';
import NetworkTelemetryHub from './components/NetworkTelemetryHub';
import ThreatInvestigationHub from './components/ThreatInvestigationHub';
import AiCopilotHub from './components/AiCopilotHub';
import ThreatIntelHub from './components/ThreatIntelHub';

import { PlatformModeProvider } from './contexts/PlatformModeContext';
import { LanguageProvider } from './contexts/LanguageContext';
import { AuthProvider } from './contexts/AuthContext';
import { AiConfigProvider, useAiConfig } from './contexts/AiConfigContext';
import DemoWarningBanner from './components/DemoWarningBanner';

function MainLayout() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [activeScan, setActiveScan] = useState(null);
  const { aiConfig, updateAiConfig, showApiModal, setShowApiModal } = useAiConfig();

  const apiKey = aiConfig?.apiKey || '';
  const setApiKey = (key) => updateAiConfig({ apiKey: key });
  const aiModel = aiConfig?.model || 'gemini-1.5-flash';
  const setAiModel = (model) => updateAiConfig({ model });

  return (
    <div className="min-h-screen bg-[#070a12] text-slate-100 font-sans flex flex-col selection:bg-cyan-500 selection:text-white">
      {/* Header */}
      <Header apiKey={apiKey} setApiKey={setApiKey} setShowApiModal={() => setShowApiModal(true)} />
      <DemoWarningBanner />

      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar */}
        <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

        {/* Main Content Area */}
        <main className="flex-1 overflow-y-auto p-6 md:p-8 space-y-6">
          {activeTab === 'dashboard' && (
            <DashboardView onNavigate={setActiveTab} nmapScan={activeScan} anomalies={[]} />
          )}
          {activeTab === 'siem-console' && <SiemEventConsole />}
          {activeTab === 'asset-discovery' && <AssetDiscoveryView />}
          {activeTab === 'vuln' && (
            <VulnerabilityScannerView nmapScan={activeScan} onNavigate={setActiveTab} />
          )}
          {activeTab === 'network-telemetry' && <NetworkTelemetryHub />}
          {activeTab === 'threat-investigation' && <ThreatInvestigationHub />}
          {activeTab === 'ai-copilot' && <AiCopilotHub apiKey={apiKey} />}
          {activeTab === 'reports' && (
            <IncidentReportsView anomalies={[]} nmapScan={activeScan} />
          )}
          {activeTab === 'threat-intel' && <ThreatIntelHub nmapScan={activeScan} />}
          {activeTab === 'simulation' && <AttackSimulationView />}
          {activeTab === 'settings' && (
            <SettingsView
              apiKey={apiKey}
              setApiKey={setApiKey}
              aiModel={aiModel}
              setAiModel={setAiModel}
            />
          )}
        </main>
      </div>

      {/* Modal */}
      {showApiModal && (
        <ApiKeyModal apiKey={apiKey} setApiKey={setApiKey} onClose={() => setShowApiModal(false)} />
      )}
    </div>
  );
}

export default function App() {
  return (
    <LanguageProvider>
      <AuthProvider>
        <PlatformModeProvider>
          <AiConfigProvider>
            <MainLayout />
          </AiConfigProvider>
        </PlatformModeProvider>
      </AuthProvider>
    </LanguageProvider>
  );
}
