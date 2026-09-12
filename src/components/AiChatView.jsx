import React, { useState, useRef, useEffect } from 'react';
import { MessageSquare, Send, Bot, User, Sparkles, Shield, Copy, Check, Zap, AlertCircle, Settings2, RefreshCw, Cpu, Activity } from 'lucide-react';
import DOMPurify from 'dompurify';
import { useLanguage } from '../contexts/LanguageContext';
import { sendAiChatMessage } from '../services/apiClient';
import { useAiConfig } from '../contexts/AiConfigContext';

function sanitizeHtml(rawHtml) {
  return DOMPurify.sanitize(rawHtml, {
    ALLOWED_TAGS: ['strong', 'code', 'span', 'b', 'i', 'em', 'p', 'br'],
    ALLOWED_ATTR: ['class']
  });
}

// Simple markdown renderer for AI responses with strict XSS sanitization
function MarkdownText({ text }) {
  const lines = text.split('\n');
  return (
    <div className="space-y-1">
      {lines.map((line, i) => {
        if (line.startsWith('### ')) return <h3 key={i} className="text-cyan-300 font-bold text-sm mt-2">{line.slice(4)}</h3>;
        if (line.startsWith('## ')) return <h2 key={i} className="text-cyan-200 font-bold mt-2">{line.slice(3)}</h2>;
        if (line.startsWith('**') && line.endsWith('**')) return <p key={i} className="font-bold text-white">{line.slice(2, -2)}</p>;
        if (line.startsWith('- ') || line.startsWith('* ')) {
          const rawItem = line.slice(2)
            .replace(/\*\*([^*]+)\*\*/g, '<strong class="text-white">$1</strong>')
            .replace(/`([^`]+)`/g, '<code class="bg-slate-800 px-1 rounded text-cyan-300 text-xs">$1</code>');
          return (
            <div key={i} className="flex gap-2 items-start">
              <span className="text-cyan-400 mt-0.5">•</span>
              <span dangerouslySetInnerHTML={{ __html: sanitizeHtml(rawItem) }} />
            </div>
          );
        }
        if (line.startsWith('```')) return null;
        if (line.trim() === '') return <div key={i} className="h-1" />;
        const rawLine = line
          .replace(/\*\*([^*]+)\*\*/g, '<strong class="text-white">$1</strong>')
          .replace(/`([^`]+)`/g, '<code class="bg-slate-800 px-1 rounded text-cyan-300 text-xs">$1</code>')
          .replace(/\*(T\d{4}[\.\d]*)\*/g, '<span class="text-yellow-400 font-mono text-xs">$1</span>');
        return (
          <p key={i} dangerouslySetInnerHTML={{ __html: sanitizeHtml(rawLine) }} />
        );
      })}
    </div>
  );
}

export default function AiChatView({ apiKey: propApiKey }) {
  const { t, language } = useLanguage();
  const isZh = language === 'zh-TW';
  const { aiConfig, setShowApiModal, aiStatus, refreshAiStatus, isOnlineApiConfigured } = useAiConfig();

  const effectiveKey = aiConfig?.apiKey || propApiKey || '';
  const isOnlineActive = isOnlineApiConfigured || (effectiveKey && aiConfig?.provider !== 'local');

  const siemCount = aiStatus?.telemetry?.siemEventsCount ?? 0;
  const portCount = aiStatus?.telemetry?.openPortsCount ?? 0;
  const cveCount = aiStatus?.telemetry?.nvdFindingsCount ?? 0;

  const quickPromptsZh = [
    { label: '⚡ 全系統真實數據研判', prompt: '請對當前系統所有已掛載之實時 SIEM 事件、開放連接埠與 NVD CVE 弱點進行全方位真實數據研判與風險評估。', icon: '⚡' },
    { label: 'Windows 事件 4625', prompt: '當大量出現 Windows Event ID 4625 代表什麼安全意涵？應如何進行鑑識與防禦排查？', icon: '🪟' },
    { label: 'PowerShell -enc 分析', prompt: '行程建立日誌顯示 powershell.exe 帶有 -EncodedCommand 參數，請問此攻擊手法為何？如何應變？', icon: '💻' },
    { label: '開放端口威脅關聯', prompt: '請依據系統當前掃描到的開放連接埠（如 Port 445 SMB、Port 3389 RDP、Port 80/443 等）分析潛在攻擊面與弱點。', icon: '🌐' },
    { label: '生成 Sigma 偵測規則', prompt: '請幫我編寫一條偵測混淆 PowerShell (Event 4688 含 -enc) 的 Sigma 規則。', icon: '📋' },
    { label: '勒索軟體 SOP 處置', prompt: '請提供一份針對 Windows 網域控制器疑似遭受勒索軟體感染之標準緊急應變處置作業程序 (IR Procedure / SOP)。', icon: '🛡️' },
  ];

  const quickPromptsEn = [
    { label: '⚡ Full Telemetry Assessment', prompt: 'Please conduct a full-spectrum real telemetry assessment across all live SIEM events, open ports, and NVD CVE vulnerabilities.', icon: '⚡' },
    { label: 'Windows Event 4625', prompt: 'What does a high volume of Windows Event ID 4625 indicate and how should I respond?', icon: '🪟' },
    { label: 'PowerShell -enc Anomaly', prompt: 'A process created event shows powershell.exe with -EncodedCommand parameter. What is the threat and remediation?', icon: '💻' },
    { label: 'Open Ports Correlation', prompt: 'Correlate potential threat attack surfaces based on the currently discovered open ports (e.g. SMB 445, RDP 3389, Web 80/443).', icon: '🌐' },
    { label: 'Sigma Rule Generation', prompt: 'Write a Sigma rule to detect encoded PowerShell execution (Event ID 4688 with -enc or -EncodedCommand).', icon: '📋' },
    { label: 'Ransomware IR SOP', prompt: 'Give me an incident response standard operating procedure for a suspected ransomware infection on a Windows domain controller.', icon: '🛡️' },
  ];

  const quickPrompts = isZh ? quickPromptsZh : quickPromptsEn;

  const [messages, setMessages] = useState([
    {
      sender: 'ai',
      text: isZh
        ? `您好！我是 **CyberMind AI 資安運維助手 (SecOps Copilot)**。\n\n• **分析引擎機制**：當您在設定中心提供 API 金鑰時，我將由您指定的雲端 API 模型（${isOnlineActive ? `☁️ ${aiConfig.provider?.toUpperCase()}: ${aiConfig.model}` : 'Google Gemini / OpenAI'}）進行全系統真實數據分析；**若未提供任何 API，我將自動使用本地模型（🖥️ CyberMind 實時遙測推論引擎 / Ollama）直接對真實數據進行深度分析**。\n• **當前數據掛載**：已即時連接 SIEM 實時日誌、網路連接埠掃描與 NIST NVD 弱點資料庫。\n\n您可以點擊下方快捷按鈕，或直接提問！`
        : `Greetings! I am **CyberMind AI Security Operations Copilot**.\n\n• **Inference Mechanism**: When you configure an API key, I utilize your specified cloud AI model (${isOnlineActive ? `☁️ ${aiConfig.provider?.toUpperCase()}: ${aiConfig.model}` : 'Google Gemini / OpenAI'}) for authentic telemetry analysis; **if no API key is provided, I automatically run on the Local Model (🖥️ Deterministic SOC Telemetry Engine / Ollama) to analyze your real system data**.\n• **Mounted Telemetry**: Live SIEM logs, open ports, and NIST NVD CVE catalog are active.\n\nClick any quick prompt below or type your inquiry to begin!`,
      timestamp: new Date().toISOString(),
    }
  ]);

  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [copied, setCopied] = useState(null);
  const [includeContext, setIncludeContext] = useState(true);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    refreshAiStatus();
  }, [refreshAiStatus]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  const handleSend = async (text) => {
    const userText = (text || input).trim();
    if (!userText) return;

    const userMsg = { sender: 'user', text: userText, timestamp: new Date().toISOString() };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsTyping(true);

    try {
      const history = messages.filter(m => m.sender !== 'system').map(m => ({
        role: m.sender === 'ai' ? 'model' : 'user',
        parts: m.text
      }));

      const replyData = await sendAiChatMessage(history, userText, includeContext, aiConfig);
      const reply = replyData?.reply || (typeof replyData === 'string' ? replyData : 'No response');
      
      setMessages(prev => [...prev, { sender: 'ai', text: reply, timestamp: new Date().toISOString() }]);
    } catch (err) {
      const errMsg = err?.message || String(err);
      const isAuthErr = errMsg.includes('401') || errMsg.includes('403') || errMsg.toLowerCase().includes('unauthorized') || errMsg.toLowerCase().includes('bearer');
      
      setMessages(prev => [...prev, {
        sender: 'ai',
        text: isAuthErr
          ? (isZh
            ? `⚠️ **身份驗證失敗 (${errMsg})**\n\n未獲合法授權存取 SOC 智能助手。請於右上角切換至 **Admin** 或 **Analyst** 角色重新取得有效憑證。`
            : `⚠️ **Authorization Failed (${errMsg})**\n\nUnauthorized to access SOC Copilot. Please switch your role to **Admin** or **Analyst** via the top-right menu to acquire a valid token.`)
          : (isZh
            ? `⚠️ **API 呼叫異常**\n\n無法完成模型推理: ${errMsg}\n\n💡 **提示**：若您提供的 API 金鑰失效或額度不足，可點擊上方「⚙️ 配置模型與 API」清除金鑰，系統將自動無縫切換為**本地模型**進行真實數據分析！`
            : `⚠️ **Inference Error**\n\nFailed to complete analysis: ${errMsg}\n\n💡 **Tip**: If your API key expired or quota was exceeded, click "⚙️ AI Config" to clear the key and automatically switch to the **Local Model** for authentic telemetry analysis!`),
        timestamp: new Date().toISOString(),
      }]);
    } finally {
      setIsTyping(false);
    }
  };

  const copyMessage = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopied(idx);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="flex flex-col h-[calc(100vh-140px)] space-y-3 font-mono">

      {/* Top Model Status & Control Bar */}
      <div className="glass-panel p-3 rounded-2xl border border-slate-800 flex flex-wrap items-center justify-between gap-3 shrink-0">
        
        {/* Active Engine Badge */}
        <div className="flex items-center gap-3">
          {isOnlineActive ? (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-cyan-500/15 border border-cyan-500/40 text-cyan-300 text-xs">
              <Zap className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
              <span className="font-bold">
                {isZh ? '雲端 API 模型分析' : 'API Model Active'}:
              </span>
              <span className="text-white font-semibold">
                {aiConfig.provider?.toUpperCase()} ({aiConfig.model || 'gemini-1.5-flash'})
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-xs">
              <Shield className="w-3.5 h-3.5 text-emerald-400" />
              <span className="font-bold">
                {isZh ? '本地模型真實數據分析' : 'Local Model Active'}:
              </span>
              <span className="text-white font-semibold">
                {isZh ? '實時遙測推論引擎 (Zero Egress)' : 'Deterministic SOC Telemetry Engine'}
              </span>
            </div>
          )}

          {/* Telemetry Grounding Status */}
          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-[11px] text-slate-300">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>{isZh ? '已掛載真實數據' : 'Mounted Telemetry'}:</span>
            <span className="text-cyan-400 font-bold">{siemCount} {isZh ? '日誌' : 'Logs'}</span>
            <span>•</span>
            <span className="text-cyan-400 font-bold">{portCount} {isZh ? '連接埠' : 'Ports'}</span>
            <span>•</span>
            <span className="text-cyan-400 font-bold">{cveCount} CVE</span>
          </div>
        </div>

        {/* Right Action Controls */}
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1.5 text-xs text-slate-400 cursor-pointer select-none mr-1">
            <input
              type="checkbox"
              checked={includeContext}
              onChange={e => setIncludeContext(e.target.checked)}
              className="accent-cyan-500 rounded"
            />
            <span>{isZh ? '包含實時 SOC 脈絡' : 'Live Context'}</span>
          </label>

          <button
            onClick={() => setShowApiModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-cyan-500/40 text-xs text-slate-300 hover:text-cyan-300 transition-all shadow-sm"
          >
            <Settings2 className="w-3.5 h-3.5 text-cyan-400" />
            <span>{isZh ? '配置模型與 API' : 'AI Config'}</span>
          </button>
        </div>
      </div>

      {/* Quick Prompts */}
      <div className="flex flex-wrap gap-2 shrink-0">
        {quickPrompts.map((p, i) => (
          <button
            key={i}
            onClick={() => handleSend(p.prompt)}
            disabled={isTyping}
            className="text-xs bg-slate-900/80 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 px-3 py-1.5 rounded-xl transition-all disabled:opacity-50 flex items-center gap-1.5 shadow-sm"
          >
            <span>{p.icon}</span>
            <span>{p.label}</span>
          </button>
        ))}
      </div>

      {/* Messages Stream */}
      <div className="flex-1 overflow-y-auto space-y-4 pr-1">
        {messages.map((m, idx) => (
          <div key={idx} className={`flex gap-3 ${m.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
            {m.sender === 'ai' && (
              <div className="w-8 h-8 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center shrink-0 text-cyan-300 shadow-md">
                <Bot className="w-4 h-4" />
              </div>
            )}
            <div className={`max-w-3xl rounded-2xl p-4 text-xs space-y-2 relative group ${
              m.sender === 'user'
                ? 'bg-cyan-600 text-white rounded-tr-none shadow-lg'
                : 'glass-panel text-slate-200 border border-slate-800 rounded-tl-none shadow-md'
            }`}>
              {m.sender === 'ai' ? <MarkdownText text={m.text} /> : <p className="leading-relaxed whitespace-pre-wrap">{m.text}</p>}
              
              <div className="flex items-center justify-between pt-1 text-[10px] text-slate-500 border-t border-slate-800/40">
                <span>{new Date(m.timestamp).toLocaleTimeString()}</span>
                {m.sender === 'ai' && (
                  <button
                    onClick={() => copyMessage(m.text, idx)}
                    className="text-slate-500 hover:text-cyan-300 flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity"
                  >
                    {copied === idx ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copied === idx ? (isZh ? '已複製' : 'Copied') : (isZh ? '複製內容' : 'Copy')}
                  </button>
                )}
              </div>
            </div>
            {m.sender === 'user' && (
              <div className="w-8 h-8 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0 text-slate-300 shadow-md">
                <User className="w-4 h-4" />
              </div>
            )}
          </div>
        ))}

        {isTyping && (
          <div className="flex gap-3 items-center text-xs text-cyan-400 bg-slate-900/60 p-3 rounded-2xl max-w-sm border border-cyan-500/30">
            <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
            <span>
              {isOnlineActive
                ? (isZh ? `正在透過 ${aiConfig.model || 'API 模型'} 進行真實數據研判...` : `Analyzing real data with ${aiConfig.model || 'API model'}...`)
                : (isZh ? '正在透過本地模型進行實時數據推論研判...' : 'Performing local model inference on real telemetry...')}
            </span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input box */}
      <div className="shrink-0">
        <form
          onSubmit={(e) => { e.preventDefault(); handleSend(); }}
          className="flex items-center gap-2 glass-panel p-2.5 rounded-2xl border border-slate-800 focus-within:border-cyan-500 transition-colors shadow-lg"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={
              isZh
                ? '向 CyberMind 提問：「全系統真實數據研判」、「分析 Event 4625」、「生成阻擋攻擊 IP 的 PowerShell」...'
                : 'Ask CyberMind: "Assess real telemetry", "Why is Event 4625 suspicious?", "Generate PowerShell block script"...'
            }
            disabled={isTyping}
            className="flex-1 bg-transparent border-none text-slate-100 text-xs px-3 py-2 focus:outline-none placeholder:text-slate-500"
          />
          <button
            type="submit"
            disabled={isTyping || !input.trim()}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs transition-all disabled:opacity-40 flex items-center gap-1.5 shadow-md"
          >
            <Send className="w-3.5 h-3.5" />
            <span>{t('chat.sendBtn', '發送')}</span>
          </button>
        </form>
      </div>
    </div>
  );
}
