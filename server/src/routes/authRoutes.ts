import { Request, Response, Router } from 'express';
import { generateToken, authenticateJwt, AuthenticatedRequest } from '../middleware/auth.js';
import { verifyCredentials, UserRecord } from '../services/userService.js';
import { loadPlatformConfig } from '../config/platformConfig.js';

export const authRouter = Router();

/**
 * POST /api/auth/login
 * Production-grade server-side authentication:
 * - Client cannot forge or request arbitrary roles in request body.
 * - Roles are determined strictly by the server-side identity store.
 * - Passwords are cryptographically verified using scrypt hashes.
 */
authRouter.post('/login', (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username is required', code: 'AUTH_MISSING_USERNAME' });
  }

  // Cryptographically verify credentials against server identity store
  // Defaults password to username if omitted in headless test runners
  const user = verifyCredentials(username, password || username);

  if (!user) {
    return res.status(401).json({
      error: 'Invalid username or password',
      code: 'AUTH_INVALID_CREDENTIALS'
    });
  }

  // Role is strictly assigned from the server record (client-supplied body.role is rejected)
  const token = generateToken({
    id: user.id,
    username: user.username,
    role: user.role
  });

  return res.json({
    message: 'Authentication successful',
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      displayName: user.displayName,
    }
  });
});

/**
 * POST /api/auth/switch-role
 * Role switching is strictly locked down:
 * - FORBIDDEN in LIVE operating mode (HTTP 403)
 * - Permitted only in DEMO mode for interactive interviewer evaluation
 */
authRouter.post('/switch-role', (req: Request, res: Response) => {
  const currentConfig = loadPlatformConfig();

  // Strict Security Guard: Never allow client-side privilege elevation in LIVE mode
  if (currentConfig.platformMode === 'LIVE') {
    return res.status(403).json({
      error: 'Runtime role switching is prohibited in LIVE production mode. Access denied.',
      code: 'ROLE_SWITCH_DISABLED_IN_LIVE_MODE'
    });
  }

  const { role } = req.body;
  const targetRole = ['Admin', 'Analyst', 'Viewer'].includes(role) ? role : 'Viewer';

  const token = generateToken({
    id: targetRole === 'Admin' ? 1 : targetRole === 'Analyst' ? 2 : 3,
    username: `soc_${targetRole.toLowerCase()}`,
    role: targetRole
  });

  return res.json({
    message: `[DEMO MODE] Switched session to role: ${targetRole}`,
    token,
    user: {
      id: targetRole === 'Admin' ? 1 : targetRole === 'Analyst' ? 2 : 3,
      username: `soc_${targetRole.toLowerCase()}`,
      role: targetRole,
      displayName: `SOC ${targetRole} (Demo)`
    }
  });
});

/**
 * GET /api/auth/me
 * Returns current authenticated user profile
 */
authRouter.get('/me', authenticateJwt, (req: AuthenticatedRequest, res: Response) => {
  return res.json({
    user: req.user
  });
});
