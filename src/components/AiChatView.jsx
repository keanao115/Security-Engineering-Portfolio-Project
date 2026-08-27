import React, { useState, useRef, useEffect } from 'react';
import { MessageSquare, Send, Bot, User, Sparkles, Shield, Copy, Check, Zap, AlertCircle } from 'lucide-react';
import { useLanguage } from '../contexts/LanguageContext';

const API_BASE = '/api';

async function sendChatMessage(history, message, includeContext = true) {
  const res = await fetch(`${API_BASE}/ai/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      history: history.map(m => ({ role: m.sender === 'ai' ? 'model' : 'user', parts: m.text })),
      message,
      includeContext,
    }),
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  const data = await res.json();
  return data.reply;
}

async function checkAiStatus() {
  try {
    const res = await fetch(`${API_BASE}/ai/status`);
    return await res.json();
  } catch {
    return { geminiConfigured: false, mode: 'OFFLINE' };
  }
}

// Simple markdown renderer for AI responses
function MarkdownText({ text }) {
  const lines = text.split('\n');
  return (
    <div className="space-y-1">
      {lines.map((line, i) => {
        if (line.startsWith('### ')) return <h3 key={i} className="text-cyan-300 font-bold text-sm mt-2">{line.slice(4)}</h3>;
        if (line.startsWith('## ')) return <h2 key={i} className="text-cyan-200 font-bold mt-2">{line.slice(3)}</h2>;
        if (line.startsWith('**') && line.endsWith('**')) return <p key={i} className="font-bold text-white">{line.slice(2, -2)}</p>;
        if (line.startsWith('- ') || line.startsWith('* ')) {
          return (
            <div key={i} className="flex gap-2 items-start">
              <span className="text-cyan-400 mt-0.5">•</span>
              <span dangerouslySetInnerHTML={{ __html: line.slice(2).replace(/\*\*([^*]+)\*\*/g, '<strong class="text-white">$1</strong>').replace(/`([^`]+)`/g, '<code class="bg-slate-800 px-1 rounded text-cyan-300 text-xs">$1</code>') }} />
            </div>
          );
        }
        if (line.startsWith('```')) return null;
        if (line.trim() === '') return <div key={i} className="h-1" />;
        return (
          <p key={i} dangerouslySetInnerHTML={{
            __html: line
              .replace(/\*\*([^*]+)\*\*/g, '<strong class="text-white">$1</strong>')
              .replace(/`([^`]+)`/g, '<code class="bg-slate-800 px-1 rounded text-cyan-300 text-xs">$1</code>')
              .replace(/\*(T\d{4}[\.\d]*)\*/g, '<span class="text-yellow-400 font-mono text-xs">$1</span>')
          }} />
        );
      })}
    </div>
  );
}

export default function AiChatView() {
  const { t, language } = useLanguage();
  const isZh = language === 'zh-TW';

  const quickPromptsZh = [
    { label: '分析實時 SIEM', prompt: '請分析當前實時 SIEM 事件日誌並找出最關鍵之資安威脅，並附上 MITRE ATT&CK 對齊與處置建議。', icon: '🔍' },
    { label: 'Windows 事件 4625', prompt: '當大量出現 Windows Event ID 4625 代表什麼安全意涵？應如何進行鑑識與防禦排查？', icon: '🪟' },
    { label: 'PowerShell -enc', prompt: '行程建立日誌顯示 powershell.exe 帶有 -EncodedCommand 參數，請問此攻擊手法為何？如何應變？', icon: '⚡' },
    { label: '網路橫向移動', prompt: '若發現主機之間在 SMB Port 445 發生異常連線，適用哪些 MITRE ATT&CK 戰術？應如何遏阻？', icon: '🌐' },
    { label: '生成 Sigma 規則', prompt: '請幫我編寫一條偵測混淆 PowerShell (Event 4688 含 -enc) 的 Sigma 規則。', icon: '📋' },
    { label: '勒索軟體 SOP', prompt: '請提供一份針對 Windows 網域控制器疑似遭受勒索軟體感染之標準緊急應變處置劇本 (IR Playbook)。', icon: '🛡️' },
  ];

  const quickPromptsEn = [
    { label: 'Analyze Live SIEM', prompt: 'Analyze the current live SIEM events and identify the top threats. Include MITRE ATT&CK mapping.', icon: '🔍' },
    { label: 'Windows Event 4625', prompt: 'What does a high volume of Windows Event ID 4625 indicate and how should I respond?', icon: '🪟' },
    { label: 'PowerShell -enc', prompt: 'A process created event shows powershell.exe with -EncodedCommand parameter. What is the threat and remediation?', icon: '⚡' },
    { label: 'Network Anomaly', prompt: 'I see lateral movement on SMB port 445 between internal hosts. What MITRE techniques apply and what should I do?', icon: '🌐' },
    { label: 'Sigma Rule', prompt: 'Write a Sigma rule to detect encoded PowerShell execution (Event ID 4688 with -enc or -EncodedCommand).', icon: '📋' },
    { label: 'IR Playbook', prompt: 'Give me an incident response playbook for a suspected ransomware infection on a Windows domain controller.', icon: '🛡️' },
  ];

  const quickPrompts = isZh ? quickPromptsZh : quickPromptsEn;

  const [messages, setMessages] = useState([
    {
      sender: 'ai',
      text: isZh
        ? '指揮官您好。我是 **CyberMind 企業智慧資安維運助手 (SOC Copilot)** — 由 Google Gemini 1.5 Flash 核心驅動。\n\n我已連接全系統之實時遙測數據：包含 SIEM 事件串流、連接埠掃描結果與漏洞報告。您可以隨時向我諮詢各項資安態勢、索取 YARA/Sigma 偵測規則或要求生成緊急事件處置劇本。'
        : 'Greetings, Commander. I am the **Intelligent Enterprise Security Operations Copilot** — powered by Google Gemini 1.5 Flash.\n\nI have access to your live SOC telemetry: SIEM events, scan results, and vulnerability findings. Ask me anything about your security posture, request YARA/Sigma rules, or get incident response guidance.',
      timestamp: new Date().toISOString(),
    }
  ]);

  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [aiStatus, setAiStatus] = useState(null);
  const [copied, setCopied] = useState(null);
  const [includeContext, setIncludeContext] = useState(true);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    checkAiStatus().then(setAiStatus);
  }, []);

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
      const history = messages.filter(m => m.sender !== 'system');
      const reply = await sendChatMessage(history, userText, includeContext);
      setMessages(prev => [...prev, { sender: 'ai', text: reply, timestamp: new Date().toISOString() }]);
    } catch (err) {
      setMessages(prev => [...prev, {
        sender: 'ai',
        text: isZh
          ? `⚠️ **API 連線錯誤**\n\n無法連接 Gemini API: ${err.message}\n\n請確認後端伺服器正常運作並已於 \`server/.env\` 中配置 GEMINI_API_KEY。`
          : `⚠️ **Connection Error**\n\nUnable to reach Gemini API: ${err.message}\n\nCheck that the backend server is running and GEMINI_API_KEY is configured in \`server/.env\`.`,
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
    <div className="flex flex-col h-[calc(100vh-140px)] space-y-4">

      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4 shrink-0">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <MessageSquare className="w-6 h-6 text-cyan-400" />
            {t('chat.title', 'AI SOC Copilot & Threat Consultation')}
            {aiStatus?.geminiConfigured && (
              <span className="text-xs font-mono bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 px-2 py-0.5 rounded-full flex items-center gap-1">
                <Zap className="w-3 h-3" /> Gemini 1.5 Flash
              </span>
            )}
            {aiStatus && !aiStatus.geminiConfigured && (
              <span className="text-xs font-mono bg-amber-500/20 border border-amber-500/40 text-amber-400 px-2 py-0.5 rounded-full flex items-center gap-1">
                <AlertCircle className="w-3 h-3" /> {isZh ? '本地規則引擎' : 'Rule-based Fallback'}
              </span>
            )}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {t('chat.subtitle', 'Natural language cybersecurity reasoning: parse suspicious logs, map CVEs, generate mitigation scripts.')}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={includeContext}
              onChange={e => setIncludeContext(e.target.checked)}
              className="accent-cyan-500"
            />
            {isZh ? '包含實時 SOC 脈絡數據' : 'Include live SOC context'}
          </label>
        </div>
      </div>

      {/* Quick Prompts */}
      <div className="flex flex-wrap gap-2 shrink-0">
        {quickPrompts.map((p, i) => (
          <button
            key={i}
            onClick={() => handleSend(p.prompt)}
            disabled={isTyping}
            className="text-xs font-mono bg-slate-900 border border-slate-700 hover:border-cyan-500/50 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 px-3 py-1.5 rounded-lg transition-all disabled:opacity-50"
          >
            {p.icon} {p.label}
          </button>
        ))}
      </div>

      {/* Messages Stream */}
      <div className="flex-1 overflow-y-auto space-y-4 pr-1">
        {messages.map((m, idx) => (
          <div key={idx} className={`flex gap-3 ${m.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
            {m.sender === 'ai' && (
              <div className="w-7 h-7 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center shrink-0 text-cyan-300">
                <Bot className="w-4 h-4" />
              </div>
            )}
            <div className={`max-w-2xl rounded-2xl p-4 text-xs font-mono space-y-2 relative group ${
              m.sender === 'user'
                ? 'bg-cyan-600 text-white rounded-tr-none'
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
              <div className="w-7 h-7 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0 text-slate-300">
                <User className="w-4 h-4" />
              </div>
            )}
          </div>
        ))}

        {isTyping && (
          <div className="flex gap-3 items-center text-xs font-mono text-cyan-400 bg-slate-900/40 p-3 rounded-xl max-w-xs border border-cyan-500/20">
            <Bot className="w-4 h-4 animate-spin" />
            <span>{isZh ? 'AI 正在分析日誌脈絡並生成回覆...' : 'AI is reasoning through security telemetry...'}</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input box */}
      <div className="shrink-0">
        <form
          onSubmit={(e) => { e.preventDefault(); handleSend(); }}
          className="flex items-center gap-2 glass-panel p-2 rounded-2xl border border-slate-800 focus-within:border-cyan-500 transition-colors"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={t('chat.inputPlaceholder', 'Ask anything: "Why is Event 4625 suspicious?", "Generate PowerShell script", "Analyze CVE"...')}
            disabled={isTyping}
            className="flex-1 bg-transparent border-none text-slate-100 text-xs px-3 py-2 focus:outline-none font-mono"
          />
          <button
            type="submit"
            disabled={isTyping || !input.trim()}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-mono text-xs font-bold transition-all disabled:opacity-40 flex items-center gap-1.5"
          >
            <Send className="w-3.5 h-3.5" />
            <span>{t('chat.sendBtn', 'Send')}</span>
          </button>
        </form>
      </div>
    </div>
  );
}
