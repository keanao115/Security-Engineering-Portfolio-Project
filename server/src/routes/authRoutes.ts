import { Request, Response, Router } from 'express';
import { generateToken, authenticateJwt, AuthenticatedRequest } from '../middleware/auth.js';
import { memoryDb } from '../db/client.js';

export const authRouter = Router();

// Pre-defined demo credentials
const DEMO_ROLES: Record<string, string> = {
  admin: 'Admin',
  soc_admin: 'Admin',
  analyst: 'Analyst',
  soc_analyst: 'Analyst',
  viewer: 'Viewer',
  auditor: 'Viewer'
};

authRouter.post('/login', (req: Request, res: Response) => {
  const { username, password, role } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  // Determine role based on explicit request or demo username mapping
  let assignedRole = role || DEMO_ROLES[username.toLowerCase()] || 'Viewer';
  if (!['Admin', 'Analyst', 'Viewer'].includes(assignedRole)) {
    assignedRole = 'Viewer';
  }

  const user = {
    id: username === 'admin' ? 1 : username === 'analyst' ? 2 : 3,
    username: username,
    role: assignedRole
  };

  const token = generateToken({ id: user.id, username: user.username, role: user.role });

  return res.json({
    message: 'Authentication successful',
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role
    }
  });
});

// Demo switch role endpoint (generates a valid token with the requested role for testing RBAC)
authRouter.post('/switch-role', (req: Request, res: Response) => {
  const { role } = req.body;
  const targetRole = ['Admin', 'Analyst', 'Viewer'].includes(role) ? role : 'Viewer';
  
  const token = generateToken({
    id: targetRole === 'Admin' ? 1 : targetRole === 'Analyst' ? 2 : 3,
    username: `soc_${targetRole.toLowerCase()}`,
    role: targetRole
  });

  return res.json({
    message: `Switched session to role: ${targetRole}`,
    token,
    user: {
      id: targetRole === 'Admin' ? 1 : targetRole === 'Analyst' ? 2 : 3,
      username: `soc_${targetRole.toLowerCase()}`,
      role: targetRole
    }
  });
});

// Current user profile verification (Protected)
authRouter.get('/me', authenticateJwt, (req: AuthenticatedRequest, res: Response) => {
  return res.json({
    user: req.user
  });
});

