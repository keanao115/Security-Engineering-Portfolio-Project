import React, { createContext, useContext, useState, useEffect } from 'react';
import { locales, LANGUAGES, DEFAULT_LANGUAGE } from '../locales';

const LanguageContext = createContext();

export function LanguageProvider({ children }) {
  const [language, setLanguageState] = useState(() => {
    try {
      const saved = localStorage.getItem('cybermind_language');
      if (saved && locales[saved]) {
        return saved;
      }
    } catch (e) {
      console.warn('Unable to access localStorage for language preference:', e);
    }
    return DEFAULT_LANGUAGE;
  });

  const setLanguage = (newLang) => {
    if (locales[newLang]) {
      setLanguageState(newLang);
      try {
        localStorage.setItem('cybermind_language', newLang);
      } catch (e) {
        console.warn('Unable to save language preference:', e);
      }
    }
  };

  // Translation helper function supporting nested dot-notation paths e.g. t('header.title')
  const t = (path, fallback = '') => {
    if (!path) return fallback;
    const keys = path.split('.');
    let current = locales[language];

    for (const key of keys) {
      if (current && current[key] !== undefined) {
        current = current[key];
      } else {
        // Fallback to default language dictionary if missing in current locale
        let fallbackCurrent = locales[DEFAULT_LANGUAGE];
        for (const fbKey of keys) {
          if (fallbackCurrent && fallbackCurrent[fbKey] !== undefined) {
            fallbackCurrent = fallbackCurrent[fbKey];
          } else {
            return fallback || path;
          }
        }
        return fallbackCurrent;
      }
    }

    return current !== undefined ? current : (fallback || path);
  };

  const currentLanguageObj = LANGUAGES.find(l => l.code === language) || LANGUAGES[0];

  return (
    <LanguageContext.Provider value={{ language, setLanguage, t, languages: LANGUAGES, currentLanguage: currentLanguageObj }}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage() {
  const context = useContext(LanguageContext);
  if (!context) {
    throw new Error('useLanguage must be used within a LanguageProvider');
  }
  return context;
}
