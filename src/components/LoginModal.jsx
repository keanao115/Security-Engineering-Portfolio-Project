import React, { useState } from 'react';
import { Shield, Key, User, Lock, X, Check, AlertCircle, Sparkles, LogIn } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useLanguage } from '../contexts/LanguageContext';

export default function LoginModal({ isOpen, onClose }) {
  const { login, switchRole } = useAuth();
  const { t, language } = useLanguage();
  const isZh = language === 'zh-TW';

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  if (!isOpen) return null;

  const handleStandardLogin = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setError(isZh ? '請輸入使用者名稱與密碼' : 'Username and password are required');
      return;
    }

    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const res = await login(username.trim(), password);
      if (res && res.token) {
        setSuccess(isZh ? `登入成功！已驗證為 ${res.user.role} 權限` : `Logged in as ${res.user.role}`);
        setTimeout(() => {
          onClose();
        }, 800);
      }
    } catch (err) {
      setError(err.message || (isZh ? '登入失敗：帳號或密碼錯誤' : 'Authentication failed'));
    } finally {
      setLoading(false);
    }
  };

  const handleQuickRoleSwitch = async (roleName) => {
    setError('');
    setSuccess('');
    setLoading(true);
    try {
      const res = await switchRole(roleName);
      if (res && res.token) {
        setSuccess(isZh ? `已切換為 ${roleName} 身分` : `Switched to ${roleName}`);
        setTimeout(() => {
          onClose();
        }, 700);
      } else {
        setError(isZh ? '目前模式禁止直接提權，請使用標準帳密登入' : 'Role switching disabled in this mode. Please log in.');
      }
    } catch (err) {
      setError(err.message || (isZh ? '快速登入失敗' : 'Failed to switch role'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="relative w-full max-w-md rounded-2xl bg-slate-900 border border-slate-700 shadow-2xl p-6 text-slate-100">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="flex items-center gap-3 mb-5">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">
              {isZh ? 'CyberMind SOC 認證登入' : 'CyberMind SOC Authentication'}
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              {isZh ? '以 Scrypt 雜湊校驗與最小權限 RBAC 機制驗證身分' : 'Scrypt salted hash validation with least-privilege RBAC'}
            </p>
          </div>
        </div>

        {/* Quick Demo Role Selector */}
        <div className="mb-5 p-3 rounded-xl bg-slate-950/70 border border-slate-800">
          <div className="text-[11px] font-mono text-cyan-400 font-semibold mb-2 flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5" />
            {isZh ? '展示與面試快速體驗 (One-Click Role Switch)' : 'Demo & Interview Quick Access'}
          </div>
          <div className="grid grid-cols-3 gap-2">
            <button
              type="button"
              onClick={() => handleQuickRoleSwitch('Admin')}
              className="px-2.5 py-1.5 rounded-lg bg-red-500/15 border border-red-500/30 hover:bg-red-500/25 text-red-300 text-xs font-mono text-center transition-all"
            >
              Admin
              <span className="block text-[9px] text-slate-400">全系統權限</span>
            </button>
            <button
              type="button"
              onClick={() => handleQuickRoleSwitch('Analyst')}
              className="px-2.5 py-1.5 rounded-lg bg-cyan-500/15 border border-cyan-500/30 hover:bg-cyan-500/25 text-cyan-300 text-xs font-mono text-center transition-all"
            >
              Analyst
              <span className="block text-[9px] text-slate-400">事件與探測</span>
            </button>
            <button
              type="button"
              onClick={() => handleQuickRoleSwitch('Viewer')}
              className="px-2.5 py-1.5 rounded-lg bg-emerald-500/15 border border-emerald-500/30 hover:bg-emerald-500/25 text-emerald-300 text-xs font-mono text-center transition-all"
            >
              Viewer
              <span className="block text-[9px] text-slate-400">唯讀稽核員</span>
            </button>
          </div>
        </div>

        {/* Standard Form */}
        <form onSubmit={handleStandardLogin} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1.5 flex items-center gap-1.5">
              <User className="w-3.5 h-3.5 text-slate-400" />
              {isZh ? '帳號 (Username)' : 'Username'}
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. admin / analyst"
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-slate-300 mb-1.5 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-slate-400" />
              {isZh ? '密碼 (Password)' : 'Password'}
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>

          {error && (
            <div className="p-2.5 rounded-lg bg-red-500/15 border border-red-500/40 text-red-300 text-xs flex items-center gap-2 font-mono">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="p-2.5 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-xs flex items-center gap-2 font-mono">
              <Check className="w-4 h-4 shrink-0" />
              <span>{success}</span>
            </div>
          )}

          <div className="pt-2 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 text-xs font-mono transition-colors"
            >
              {isZh ? '取消' : 'Cancel'}
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-bold transition-all flex items-center gap-1.5 disabled:opacity-50"
            >
              <LogIn className="w-3.5 h-3.5" />
              {loading ? (isZh ? '驗證中…' : 'Authenticating...') : (isZh ? '安全登入' : 'Sign In')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
