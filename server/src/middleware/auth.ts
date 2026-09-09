import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export interface AuthenticatedRequest extends Request {
  user?: {
    id: number;
    username: string;
    role: 'Admin' | 'Analyst' | 'Viewer' | string;
  };
}

export function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    if (process.env.NODE_ENV === 'test') {
      return 'test_jwt_secret_cybermind_soc_testing_only';
    }
    throw new Error('[FATAL SECURITY CONFIG] JWT_SECRET environment variable is missing. Refusing to operate with insecure fallback.');
  }
  return secret;
}

export function generateToken(payload: { id: number; username: string; role: string }) {
  return jwt.sign(payload, getJwtSecret(), { expiresIn: '8h' });
}

export function authenticateJwt(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Unauthorized: Missing or malformed Bearer token. Valid authentication is required.',
      code: 'AUTH_TOKEN_MISSING'
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, getJwtSecret()) as any;
    req.user = decoded;
    next();
  } catch (err: any) {
    return res.status(401).json({
      error: 'Unauthorized: Invalid or expired JWT token',
      code: 'AUTH_TOKEN_INVALID'
    });
  }
}

export function requireRole(allowedRoles: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Forbidden: Role '${req.user?.role || 'Anonymous'}' is not authorized for this SOC operation. Allowed roles: [${allowedRoles.join(', ')}]`,
        code: 'AUTH_ROLE_FORBIDDEN'
      });
    }
    next();
  };
}

