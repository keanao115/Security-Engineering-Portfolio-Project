import rateLimit from 'express-rate-limit';

export const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300, // Limit each IP to 300 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests from this IP address to the SOC API. Please try again after 15 minutes.'
  }
});

export const ingestRateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 100, // Limit ingestion to 100 uploads per window
  standardHeaders: true,
  message: {
    error: 'Log ingestion rate limit exceeded. Please throttle log stream uploads.',
    code: 'RATE_LIMIT_INGEST_EXCEEDED'
  }
});

// Dedicated strict rate limiter for LLM calls (prevents quota exhaustion & financial abuse)
export const aiRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // 20 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many AI inference requests. Please throttle your requests to at most 20 per minute.',
    code: 'RATE_LIMIT_AI_EXCEEDED'
  }
});

// Dedicated rate limiter for network port scanning (prevents network flood / denial of service)
export const scanRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 probes per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Network port scan rate limit exceeded. Please throttle active scanning.',
    code: 'RATE_LIMIT_SCAN_EXCEEDED'
  }
});

// Dedicated rate limiter for authentication login attempts (prevents brute-force & credential stuffing)
export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'test' ? 100 : 15, // 15 attempts per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many authentication attempts from this IP. Please try again after 15 minutes.',
    code: 'RATE_LIMIT_AUTH_EXCEEDED'
  }
});

