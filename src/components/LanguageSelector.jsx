import React, { useState, useRef, useEffect } from 'react';
import { Globe, Check, ChevronDown } from 'lucide-react';
import { useLanguage } from '../contexts/LanguageContext';

export default function LanguageSelector({ variant = 'header' }) {
  const { language, setLanguage, languages, currentLanguage, t } = useLanguage();
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  if (variant === 'settings') {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {languages.map((lang) => {
          const isSelected = language === lang.code;
          return (
            <button
              key={lang.code}
              onClick={() => setLanguage(lang.code)}
              className={`p-4 rounded-xl border text-left transition-all flex items-center justify-between font-mono text-xs ${
                isSelected
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 shadow-md shadow-cyan-500/10'
                  : 'bg-slate-950 text-slate-400 border-slate-900 hover:border-slate-800 hover:text-slate-200'
              }`}
            >
              <div className="flex items-center gap-3">
                <span className="text-xl select-none">{lang.flag}</span>
                <div>
                  <div className="font-bold text-white flex items-center gap-2">
                    {lang.label}
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 font-mono">
                      {lang.code}
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">{lang.region}</div>
                </div>
              </div>
              {isSelected && <Check className="w-4 h-4 text-cyan-400 shrink-0" />}
            </button>
          );
        })}
      </div>
    );
  }

  // Header Dropdown Variant
  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-cyan-500/30 hover:border-cyan-400 text-xs font-mono text-slate-200 transition-all shadow-sm"
        title={t('header.selectLanguage', '切換語言 / Switch Language')}
      >
        <span className="text-sm select-none">{currentLanguage.flag}</span>
        <span className="hidden sm:inline font-semibold">{currentLanguage.shortLabel}</span>
        <ChevronDown className={`w-3 h-3 text-cyan-400 transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-48 rounded-xl bg-slate-950/95 border border-cyan-500/30 backdrop-blur-xl shadow-2xl z-50 py-1.5 overflow-hidden animate-in fade-in zoom-in-95 duration-150">
          <div className="px-3 py-1.5 text-[10px] font-mono font-bold text-slate-500 uppercase tracking-wider border-b border-slate-900 flex items-center gap-1.5">
            <Globe className="w-3 h-3 text-cyan-400" />
            <span>{t('header.selectLanguage', '切換語言 / Select Language')}</span>
          </div>

          <div className="p-1 space-y-0.5">
            {languages.map((lang) => {
              const isActive = language === lang.code;
              return (
                <button
                  key={lang.code}
                  onClick={() => {
                    setLanguage(lang.code);
                    setIsOpen(false);
                  }}
                  className={`w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-xs font-mono transition-all ${
                    isActive
                      ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                      : 'text-slate-300 hover:bg-slate-900 hover:text-white'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <span className="text-base select-none">{lang.flag}</span>
                    <span>{lang.label}</span>
                  </div>
                  {isActive && <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0" />}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
