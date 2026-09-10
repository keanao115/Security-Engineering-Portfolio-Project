import js from '@eslint/js';

export default [
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'server/**',
      '*.config.js',
      'postcss.config.js',
      'tailwind.config.js',
      'vite.config.js',
    ],
  },
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      parserOptions: {
        ecmaFeatures: {
          jsx: true,
        },
      },
      globals: {
        window: 'readonly',
        document: 'readonly',
        localStorage: 'readonly',
        navigator: 'readonly',
        fetch: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        console: 'readonly',
        URL: 'readonly',
        Blob: 'readonly',
        FileReader: 'readonly',
        FormData: 'readonly',
        Headers: 'readonly',
        CustomEvent: 'readonly',
        alert: 'readonly',
        confirm: 'readonly',
        prompt: 'readonly',
        NodeJS: 'readonly',
        AbortSignal: 'readonly',
        URLSearchParams: 'readonly',
        WebSocket: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-console': 'off',
      'no-empty': ['error', { allowEmptyCatch: true }],
    },
  },
];
