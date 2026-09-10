// Environment Variable Validation & Fail-Safe Boot Guard

export interface EnvironmentValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export function validateEnvironmentConfig(): EnvironmentValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // 1. JWT_SECRET Validation
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    if (process.env.NODE_ENV === 'production') {
      errors.push('[CRITICAL] JWT_SECRET environment variable is missing in production environment. Server refused to start.');
    } else if (process.env.NODE_ENV !== 'test') {
      errors.push('[CRITICAL] JWT_SECRET environment variable is missing. Set JWT_SECRET in server/.env.');
    }
  } else if (jwtSecret.length < 16 && process.env.NODE_ENV === 'production') {
    errors.push('[SECURITY WARNING] JWT_SECRET is too short (less than 16 characters) for production use.');
  }

  // 2. PORT Validation
  if (process.env.PORT) {
    const portNum = parseInt(process.env.PORT, 10);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
      errors.push(`[CONFIG ERROR] Invalid PORT specified: "${process.env.PORT}". Must be an integer between 1 and 65535.`);
    }
  }

  // 3. PLATFORM_MODE Validation
  const mode = process.env.PLATFORM_MODE?.toUpperCase();
  if (mode && mode !== 'LIVE' && mode !== 'DEMO') {
    warnings.push(`[CONFIG WARNING] Unknown PLATFORM_MODE "${process.env.PLATFORM_MODE}". Defaulting safely to "LIVE".`);
  }

  // 4. Collector Port Validations
  const checkPort = (name: string, val?: string) => {
    if (val) {
      const p = parseInt(val, 10);
      if (isNaN(p) || p < 1 || p > 65535) {
        errors.push(`[CONFIG ERROR] Invalid ${name} specified: "${val}".`);
      }
    }
  };

  checkPort('SYSLOG_UDP_PORT', process.env.SYSLOG_UDP_PORT);
  checkPort('SYSLOG_TCP_PORT', process.env.SYSLOG_TCP_PORT);
  checkPort('WEF_HTTP_PORT', process.env.WEF_HTTP_PORT);
  checkPort('NETFLOW_UDP_PORT', process.env.NETFLOW_UDP_PORT);

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

export function enforceEnvironmentConfig(): void {
  const result = validateEnvironmentConfig();

  for (const warning of result.warnings) {
    console.warn(`\x1b[33m${warning}\x1b[0m`);
  }

  if (!result.valid) {
    console.error('\x1b[31m=======================================================');
    console.error('[FATAL CONFIGURATION ERROR] Environment Check Failed:');
    for (const error of result.errors) {
      console.error(` - ${error}`);
    }
    console.error('=======================================================\x1b[0m');
    
    if (process.env.NODE_ENV !== 'test') {
      process.exit(1);
    } else {
      throw new Error(`Environment validation failed: ${result.errors.join('; ')}`);
    }
  }
}
