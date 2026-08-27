import { zhTW } from './zhTW';
import { enUS } from './enUS';

export const locales = {
  'zh-TW': zhTW,
  'en-US': enUS,
};

export const LANGUAGES = [
  {
    code: 'zh-TW',
    label: '繁體中文',
    shortLabel: '繁中',
    flag: '🇹🇼',
    region: 'Taiwan / Traditional Chinese'
  },
  {
    code: 'en-US',
    label: 'English (US)',
    shortLabel: 'EN',
    flag: '🇺🇸',
    region: 'United States / English'
  }
];

export const DEFAULT_LANGUAGE = 'zh-TW';
