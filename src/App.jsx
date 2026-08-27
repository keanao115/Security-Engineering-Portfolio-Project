import React, { useState } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import DashboardView from './components/DashboardView';
import ThreatAnalysisView from './components/ThreatAnalysisView';
import LogAnalysisView from './components/LogAnalysisView';
import NetworkScannerView from './components/NetworkScannerView';
import VulnerabilityScannerView from './components/VulnerabilityScannerView';
import IncidentReportsView from './components/IncidentReportsView';
import MitreMatrixView from './components/MitreMatrixView';
import IocDatabaseView from './components/IocDatabaseView';
import AttackSimulationView from './components/AttackSimulationView';
import SocCopilotView from './components/SocCopilotView';
import RagKnowledgeView from './components/RagKnowledgeView';
import AiChatView from './components/AiChatView';
import SettingsView from './components/SettingsView';
import ApiKeyModal from './components/ApiKeyModal';
import LiveNetworkDashboard from './components/LiveNetworkDashboard';
import PacketInspectorView from './components/PacketInspectorView';
import AssetDiscoveryView from './components/AssetDiscoveryView';
import SiemEventConsole from './components/SiemEventConsole';
import CollectorManagementView from './components/CollectorManagementView';
import LivePacketCaptureView from './components/LivePacketCaptureView';
import ZeekSuricataView from './components/ZeekSuricataView';
import PipelinePerformanceView from './components/PipelinePerformanceView';
import InvestigationTimelineView from './components/InvestigationTimelineView';
import { PlatformModeProvider } from './contexts/PlatformModeContext';
import { LanguageProvider } from './contexts/LanguageContext';
import DemoWarningBanner from './components/DemoWarningBanner';

import { SAMPLE_WINDOWS_LOGS, SAMPLE_LINUX_LOGS, SAMPLE_FIREWALL_LOGS, SAMPLE_NMAP_XML } from './data/sampleData';
import { parseWindowsEventLog, parseLinuxLog, parseFirewallLog, parseNmapScan } from './utils/logParsers';
import { analyzeLogThreats } from './utils/threatEngine';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [apiKey, setApiKey] = useState('');
  const [aiModel, setAiModel] = useState('Google Gemini 1.5 Pro');
  const [showApiModal, setShowApiModal] = useState(false);

  // Initial clean dataset (Real Telemetry baseline)
  const [parsedData, setParsedData] = useState({
    windowsLogs: [],
    linuxLogs: [],
    firewallLogs: [],
    nmapScan: null
  });

  const threatResult = analyzeLogThreats(parsedData);

  const handleLogAnalyzed = (newData) => {
    setParsedData(prev => ({ ...prev, ...newData }));
    setActiveTab('threat');
  };

  const handleScanCompleted = (scanResult) => {
    setParsedData(prev => ({ ...prev, nmapScan: scanResult }));
  };

  return (
    <LanguageProvider>
      <PlatformModeProvider>
      <div className="min-h-screen bg-[#070a12] text-slate-100 font-sans flex flex-col selection:bg-cyan-500 selection:text-white">
        {/* Header */}
        <Header apiKey={apiKey} setApiKey={setApiKey} setShowApiModal={() => setShowApiModal(true)} />
        <DemoWarningBanner />

        <div className="flex-1 flex overflow-hidden">
          {/* Sidebar */}
        <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

        {/* Main Content Area */}
        <main className="flex-1 overflow-y-auto p-6 md:p-8 space-y-6">
          {activeTab === 'dashboard' && <DashboardView onNavigate={setActiveTab} nmapScan={parsedData.nmapScan} anomalies={threatResult.anomalies} />}
          {activeTab === 'threat' && <ThreatAnalysisView anomalies={threatResult.anomalies} nmapScan={parsedData.nmapScan} />}
          {activeTab === 'log' && <LogAnalysisView onLogAnalyzed={handleLogAnalyzed} />}
          {activeTab === 'network' && <NetworkScannerView onScanCompleted={handleScanCompleted} />}
          {activeTab === 'vuln' && <VulnerabilityScannerView nmapScan={parsedData.nmapScan} onNavigate={setActiveTab} />}
          {activeTab === 'reports' && <IncidentReportsView anomalies={threatResult.anomalies} nmapScan={parsedData.nmapScan} />}
          {activeTab === 'mitre' && <MitreMatrixView nmapScan={parsedData.nmapScan} />}
          {activeTab === 'ioc' && <IocDatabaseView />}
          {activeTab === 'simulation' && <AttackSimulationView />}
          {activeTab === 'copilot' && <SocCopilotView />}
          {activeTab === 'rag' && <RagKnowledgeView />}
          {activeTab === 'chat' && <AiChatView apiKey={apiKey} />}
          {activeTab === 'settings' && (
            <SettingsView apiKey={apiKey} setApiKey={setApiKey} aiModel={aiModel} setAiModel={setAiModel} />
          )}
          {/* SOC Platform Expansion — Phase 2 & 3 */}
          {activeTab === 'collectors' && <CollectorManagementView />}
          {activeTab === 'packet-capture' && <LivePacketCaptureView />}
          {activeTab === 'zeek-suricata' && <ZeekSuricataView />}
          {activeTab === 'pipeline-performance' && <PipelinePerformanceView />}
          {activeTab === 'investigation-timeline' && <InvestigationTimelineView />}
          {activeTab === 'live-network' && <LiveNetworkDashboard />}
          {activeTab === 'packet-inspector' && <PacketInspectorView />}
          {activeTab === 'asset-discovery' && <AssetDiscoveryView />}
          {activeTab === 'siem-console' && <SiemEventConsole />}
        </main>
      </div>

      {/* Modal */}
      {showApiModal && (
        <ApiKeyModal apiKey={apiKey} setApiKey={setApiKey} onClose={() => setShowApiModal(false)} />
      )}
    </div>
    </PlatformModeProvider>
    </LanguageProvider>
  );
}
