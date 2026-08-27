import React, { useState } from 'react';
import { Database, Search, ExternalLink, ShieldAlert, Globe, Hash, Server } from 'lucide-react';
import { SAMPLE_IOC_LIST } from '../data/sampleData';
import { useLanguage } from '../contexts/LanguageContext';

export default function IocDatabaseView() {
  const { t, language } = useLanguage();
  const [query, setQuery] = useState('');
  const [iocs, setIocs] = useState(SAMPLE_IOC_LIST);

  const filtered = iocs.filter(i => 
    (i.ip && i.ip.includes(query)) ||
    (i.hash && i.hash.toLowerCase().includes(query.toLowerCase())) ||
    (i.domain && i.domain.toLowerCase().includes(query.toLowerCase())) ||
    (i.threat && i.threat.toLowerCase().includes(query.toLowerCase()))
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-extrabold text-white flex items-center gap-2">
            <Database className="w-6 h-6 text-cyan-400" />
            {t('ioc.title', 'IOC Threat Intelligence Database & Feeds')}
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-1">
            {t('ioc.subtitle', 'Search malicious IPs, file hashes, C2 domain names, and external threat intel feeds (AbuseIPDB, VirusTotal, Shodan).')}
          </p>
        </div>
      </div>

      {/* Search box */}
      <div className="glass-panel p-4 rounded-2xl flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
          <input
            type="text"
            placeholder={t('ioc.searchPlaceholder', 'Search IP, MD5/SHA256 Hash, Domain, Malware Name...')}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-xl pl-9 pr-4 py-2.5 focus:outline-none focus:border-cyan-500 w-full font-mono"
          />
        </div>

        <span className="text-xs font-mono text-slate-400 whitespace-nowrap">
          {language === 'zh-TW' ? '情報來源連線：' : 'Active Feed:'} <strong className="text-emerald-400">{language === 'zh-TW' ? '已連線 4 組即時情報源' : '4 Intelligence Sources Connected'}</strong>
        </span>
      </div>

      {/* IOC Table */}
      <div className="glass-panel p-5 rounded-2xl overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs font-mono">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400">
              <th className="py-2.5 px-3">{t('ioc.indicator', 'INDICATOR')}</th>
              <th className="py-2.5 px-3">{t('ioc.type', 'TYPE')}</th>
              <th className="py-2.5 px-3">{t('ioc.threatType', 'THREAT CLASSIFICATION')}</th>
              <th className="py-2.5 px-3">{t('ioc.confidence', 'CONFIDENCE')}</th>
              <th className="py-2.5 px-3">{language === 'zh-TW' ? '來源國家' : 'ORIGIN / COUNTRY'}</th>
              <th className="py-2.5 px-3">{language === 'zh-TW' ? '情報源檢驗' : 'INTELLIGENCE SOURCE'}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-900">
            {filtered.map((item, idx) => (
              <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                <td className="py-3 px-3 font-bold text-red-400 max-w-xs truncate">
                  {item.ip || item.domain || item.hash}
                </td>
                <td className="py-3 px-3 text-slate-400">{item.type}</td>
                <td className="py-3 px-3 font-bold text-slate-200">{item.threat}</td>
                <td className="py-3 px-3">
                  <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 font-bold text-[10px]">
                    {item.confidence}% {language === 'zh-TW' ? '信賴度' : 'Confidence'}
                  </span>
                </td>
                <td className="py-3 px-3 text-slate-300">{item.country}</td>
                <td className="py-3 px-3">
                  <a
                    href={`https://www.virustotal.com/gui/search/${encodeURIComponent(item.ip || item.domain || item.hash)}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-cyan-400 hover:underline flex items-center gap-1 text-[11px]"
                  >
                    {item.source} <ExternalLink className="w-3 h-3" />
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
