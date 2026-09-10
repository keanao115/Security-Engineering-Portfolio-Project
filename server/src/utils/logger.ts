// Structured JSON Logger for Enterprise SOC Operations
// Standardizes log format with timestamps, levels, modules, context, and automatic credential/PII sanitization

import { maskSensitivePii, sanitizeRawLog } from '../security/sanitize.js';

export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'FATAL';

export interface StructuredLogEntry {
  timestamp: string;
  level: LogLevel;
  module: string;
  message: string;
  context?: Record<string, any>;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
}

class StructuredLogger {
  private moduleName: string;

  constructor(moduleName: string = 'SOC-Engine') {
    this.moduleName = moduleName;
  }

  public forModule(moduleName: string): StructuredLogger {
    return new StructuredLogger(moduleName);
  }

  private sanitizeContext(obj: any): any {
    if (!obj || typeof obj !== 'object') return obj;
    try {
      const copy = Array.isArray(obj) ? [...obj] : { ...obj };
      for (const [key, value] of Object.entries(copy)) {
        if (typeof value === 'string') {
          copy[key] = maskSensitivePii(sanitizeRawLog(value, 4096)).maskedText;
        } else if (typeof value === 'object') {
          copy[key] = this.sanitizeContext(value);
        }
      }
      return copy;
    } catch {
      return '[Unparseable Context]';
    }
  }

  private write(level: LogLevel, message: string, context?: Record<string, any>, err?: Error): void {
    const isProduction = process.env.NODE_ENV === 'production';
    const cleanMsg = maskSensitivePii(sanitizeRawLog(message, 8192)).maskedText;
    const sanitizedCtx = context ? this.sanitizeContext(context) : undefined;

    const entry: StructuredLogEntry = {
      timestamp: new Date().toISOString(),
      level,
      module: this.moduleName,
      message: cleanMsg,
      context: sanitizedCtx,
    };

    if (err) {
      entry.error = {
        name: err.name,
        message: err.message,
        stack: isProduction ? undefined : err.stack,
      };
    }

    const output = JSON.stringify(entry);

    if (level === 'ERROR' || level === 'FATAL') {
      console.error(output);
    } else if (level === 'WARN') {
      console.warn(output);
    } else {
      console.log(output);
    }
  }

  public debug(message: string, context?: Record<string, any>): void {
    if (process.env.NODE_ENV !== 'production') {
      this.write('DEBUG', message, context);
    }
  }

  public info(message: string, context?: Record<string, any>): void {
    this.write('INFO', message, context);
  }

  public warn(message: string, context?: Record<string, any>): void {
    this.write('WARN', message, context);
  }

  public error(message: string, err?: Error, context?: Record<string, any>): void {
    this.write('ERROR', message, context, err);
  }

  public fatal(message: string, err?: Error, context?: Record<string, any>): void {
    this.write('FATAL', message, context, err);
  }
}

export const logger = new StructuredLogger();
