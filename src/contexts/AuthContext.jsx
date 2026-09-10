import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext(null);

const STORAGE_KEY = 'cybermind_auth_session';

export function AuthProvider({ children }) {
  const [session, setSession] = useState(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) return JSON.parse(saved);
    } catch (e) {
      console.warn('[AuthContext] Failed to parse saved auth session:', e);
    }
    return null;
  });

  const [loading, setLoading] = useState(!session);

  // Initialize session on startup if not present
  useEffect(() => {
    if (!session) {
      // Default initial session: Admin (can be switched anytime via UI)
      switchRole('Admin').finally(() => setLoading(false));
    }
  }, []);

  const switchRole = async (targetRole) => {
    if (targetRole === 'Guest') {
      // Guest mode simulates an unauthenticated user with no token
      const guestSession = {
        token: '',
        user: { id: 0, username: 'guest_visitor', role: 'Guest' }
      };
      setSession(guestSession);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(guestSession));
      return guestSession;
    }

    const defaultCredentials = {
      Admin: { username: 'admin', password: 'Admin@CyberMind2026!' },
      Analyst: { username: 'analyst', password: 'Analyst@CyberMind2026!' },
      Viewer: { username: 'viewer', password: 'Viewer@CyberMind2026!' }
    };
    const cred = defaultCredentials[targetRole] || defaultCredentials.Viewer;

    try {
      // Primary: authenticate against server identity store
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cred)
      });

      if (res.ok) {
        const data = await res.json();
        const newSession = {
          token: data.token,
          user: data.user
        };
        setSession(newSession);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(newSession));
        return newSession;
      }

      // Fallback: in DEMO mode, switch-role endpoint is permitted
      const demoRes = await fetch('/api/auth/switch-role', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: targetRole })
      });

      if (demoRes.ok) {
        const data = await demoRes.json();
        const newSession = {
          token: data.token,
          user: data.user
        };
        setSession(newSession);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(newSession));
        return newSession;
      }
    } catch (err) {
      console.error('[AuthContext] switchRole error:', err);
      return null;
    }
  };

  const login = async (username, password, role) => {
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, role })
      });

      if (!res.ok) throw new Error(`Login failed: HTTP ${res.status}`);
      const data = await res.json();
      const newSession = {
        token: data.token,
        user: data.user
      };
      setSession(newSession);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(newSession));
      return newSession;
    } catch (err) {
      console.error('[AuthContext] Login error:', err);
      throw err;
    }
  };

  const logout = () => {
    switchRole('Guest');
  };

  const getToken = () => {
    return session?.token || '';
  };

  const value = {
    user: session?.user || { id: 0, username: 'anonymous', role: 'Guest' },
    token: session?.token || '',
    role: session?.user?.role || 'Guest',
    isAuthenticated: !!session?.token,
    loading,
    switchRole,
    login,
    logout,
    getToken
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

// Global helper for non-React contexts (e.g. apiClient.js)
export function getStoredToken() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      const parsed = JSON.parse(saved);
      return parsed.token || '';
    }
  } catch (e) {
    // Ignore storage parse error
  }
  return '';
}
