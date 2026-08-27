import React, { useState } from 'react';
import { BookOpen, Search, Bookmark, ExternalLink } from 'lucide-react';
import { searchRagKnowledge } from '../utils/ragDatabase';
import { useLanguage } from '../contexts/LanguageContext';

export default function RagKnowledgeView() {
  const { t, language } = useLanguage();
  const [query, setQuery] = useState('');
  const results = searchRagKnowledge(query, language);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <BookOpen className="w-6 h-6 text-cyan-400" />
            {t('rag.title', 'RAG Security Knowledge Base (NIST / OWASP / MITRE)')}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {t('rag.subtitle', 'Search embedded cyber security knowledge base prioritized by AI analysis.')}
          </p>
        </div>
      </div>

      {/* Search Bar */}
      <div className="glass-panel p-4 rounded-2xl">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
          <input
            type="text"
            placeholder={t('rag.searchPlaceholder', 'Search NIST 800-61, OWASP Top 10, Windows Event ID (e.g. 4625), MITRE T1059...')}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-xl pl-9 pr-4 py-2.5 focus:outline-none focus:border-cyan-500 w-full font-mono"
          />
        </div>
      </div>

      {/* Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {results.map((item) => (
          <div key={item.id} className="glass-panel p-5 rounded-2xl space-y-3 border border-slate-800 hover:border-cyan-500/30 transition-all">
            <div className="flex items-center justify-between">
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                {item.category}
              </span>
              <span className="text-xs font-mono text-slate-500">{item.id}</span>
            </div>

            <h4 className="text-sm font-bold text-white font-mono">{item.title}</h4>
            <p className="text-xs text-slate-400 font-mono">{item.summary}</p>

            <div className="bg-slate-950 p-3 rounded-xl border border-slate-900 text-xs font-mono text-slate-300 leading-relaxed">
              {item.content}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
