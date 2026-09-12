import React, { useState, useEffect } from 'react';
import { AlertOctagon, ShieldAlert, CheckCircle, Clock, Filter, Plus, ArrowRight, UserCheck, MessageSquare, RefreshCw, X } from 'lucide-react';
import { fetchIncidentCases, createIncidentCase, updateIncidentCase } from '../services/apiClient';
import { useLanguage } from '../contexts/LanguageContext';
import { useAuth } from '../contexts/AuthContext';

export default function IncidentCasesView() {
  const { t, language } = useLanguage();
  const isZh = language === 'zh-TW';
  const { role, user } = useAuth();
  const canEdit = role === 'Admin' || role === 'Analyst';

  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [newNote, setNewNote] = useState('');
  const [updating, setUpdating] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createForm, setCreateForm] = useState({
    title: '',
    severity: 'High',
    sourceIp: '',
    targetIp: '',
    mitreTechnique: '',
    summary: ''
  });
  const [createError, setCreateError] = useState('');

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const data = await fetchIncidentCases();
      setIncidents(data.incidents || []);
      if (data.incidents?.length > 0 && !selectedIncident) {
        setSelectedIncident(data.incidents[0]);
      }
    } catch (err) {
      console.warn('Failed to load incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const handleUpdateStatus = async (incidentId, newStatus) => {
    if (!canEdit) return;
    setUpdating(true);
    try {
      const data = await updateIncidentCase(incidentId, { status: newStatus });
      if (data && data.incident) {
        setIncidents(prev => prev.map(inc => inc.id === incidentId ? data.incident : inc));
        setSelectedIncident(data.incident);
      }
    } catch (err) {
      console.error('Update status error:', err);
    } finally {
      setUpdating(false);
    }
  };

  const handleCreateIncident = async (e) => {
    e.preventDefault();
    if (!createForm.title.trim()) {
      setCreateError(isZh ? '請輸入事件標題' : 'Incident title is required');
      return;
    }
    setUpdating(true);
    setCreateError('');
    try {
      const res = await createIncidentCase({
        ...createForm,
        assignedTo: user?.username || (isZh ? '資安分析師' : 'SOC Analyst')
      });
      if (res && res.incident) {
        setIncidents(prev => [res.incident, ...prev]);
        setSelectedIncident(res.incident);
        setShowCreateModal(false);
        setCreateForm({
          title: '',
          severity: 'High',
          sourceIp: '',
          targetIp: '',
          mitreTechnique: '',
          summary: ''
        });
      }
    } catch (err) {
      setCreateError(err.message || 'Creation failed');
    } finally {
      setUpdating(false);
    }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNote.trim() || !selectedIncident || !canEdit) return;
    setUpdating(true);
    try {
      const res = await authFetch(`/api/investigation/incidents/${selectedIncident.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: newNote.trim() })
      });
      if (res.ok) {
        const data = await res.json();
        setIncidents(prev => prev.map(inc => inc.id === selectedIncident.id ? data.incident : inc));
        setSelectedIncident(data.incident);
        setNewNote('');
      }
    } catch (err) {
      console.error('Add note error:', err);
    } finally {
      setUpdating(false);
    }
  };

  const filtered = filterStatus === 'ALL'
    ? incidents
    : incidents.filter(i => i.status === filterStatus);

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'Critical': return 'bg-red-500/20 text-red-300 border-red-500/40';
      case 'High': return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'Medium': return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';
      default: return 'bg-slate-700 text-slate-300 border-slate-600';
    }
  };

  const getStatusBadge = (st) => {
    switch (st) {
      case 'New': return 'bg-purple-500/20 text-purple-300 border-purple-500/40';
      case 'Investigating': return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';
      case 'Contained': return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'Remediated': return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
      case 'Closed': return 'bg-slate-700 text-slate-300 border-slate-600';
      default: return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Action and Filter Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center gap-2">
          <AlertOctagon className="w-5 h-5 text-amber-400" />
          <span className="text-sm font-bold text-white font-mono">
            {isZh ? '資安事件工單與處置閉環 (Incident Cases)' : 'SOC Incident Cases & Remediation Lifecycle'}
          </span>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
            {incidents.length} {isZh ? '件事件' : 'Cases'}
          </span>
        </div>

        <div className="flex items-center gap-2">
          {canEdit && (
            <button
              onClick={() => setShowCreateModal(true)}
              className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-gradient-to-r from-amber-500 to-red-600 hover:from-amber-400 hover:to-red-500 text-white font-mono text-xs font-bold transition-all shadow-md"
            >
              <Plus className="w-3.5 h-3.5" />
              {isZh ? '手動立案' : 'New Incident'}
            </button>
          )}
          <span className="text-xs text-slate-400 font-mono flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" />
            {isZh ? '狀態過濾:' : 'Status:'}
          </span>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-cyan-300 text-xs rounded-lg px-2 py-1 font-mono focus:outline-none"
          >
            <option value="ALL">{isZh ? '全部狀態' : 'All Status'}</option>
            <option value="New">New</option>
            <option value="Investigating">Investigating</option>
            <option value="Contained">Contained</option>
            <option value="Remediated">Remediated</option>
            <option value="Closed">Closed</option>
          </select>
          <button
            onClick={fetchIncidents}
            className="p-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
            title={isZh ? '重新整理' : 'Refresh'}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Main Grid: List + Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Incident List */}
        <div className="lg:col-span-5 space-y-3">
          {filtered.length === 0 ? (
            <div className="p-8 rounded-xl border border-slate-800 bg-slate-900/40 text-center space-y-2">
              <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto opacity-80" />
              <p className="text-xs font-mono text-slate-300">
                {isZh ? '無符合條件之資安工單' : 'No incident cases match filter.'}
              </p>
              {canEdit && (
                <button
                  onClick={() => setShowCreateModal(true)}
                  className="mt-2 text-xs font-mono text-cyan-400 hover:underline inline-block"
                >
                  {isZh ? '+ 建立新資安事件工單' : '+ Create New Incident'}
                </button>
              )}
            </div>
          ) : (
            filtered.map(inc => {
              const isSelected = selectedIncident?.id === inc.id;
              return (
                <div
                  key={inc.id}
                  onClick={() => setSelectedIncident(inc)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-cyan-950/30 border-cyan-500/50 shadow-lg shadow-cyan-950/50'
                      : 'bg-slate-900/50 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-cyan-300">{inc.id}</span>
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border font-bold ${getSeverityBadge(inc.severity)}`}>
                        {inc.severity}
                      </span>
                    </div>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border font-semibold ${getStatusBadge(inc.status)}`}>
                      {inc.status}
                    </span>
                  </div>
                  <h4 className="text-sm font-semibold text-slate-100 line-clamp-1 mb-1">{inc.title}</h4>
                  <p className="text-xs text-slate-400 font-mono line-clamp-2">{inc.summary}</p>
                  <div className="flex items-center justify-between mt-3 pt-2 border-t border-slate-800/80 text-[10px] text-slate-500 font-mono">
                    <span>{isZh ? '負責人:' : 'Assignee:'} {inc.assignedTo}</span>
                    <span>{new Date(inc.updatedAt || inc.createdAt).toLocaleTimeString()}</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Incident Details & Actions */}
        <div className="lg:col-span-7">
          {selectedIncident ? (
            <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-5">
              <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="text-xs font-mono font-extrabold text-cyan-400">{selectedIncident.id}</span>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${getSeverityBadge(selectedIncident.severity)}`}>
                      {selectedIncident.severity}
                    </span>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border font-semibold ${getStatusBadge(selectedIncident.status)}`}>
                      {selectedIncident.status}
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-white">{selectedIncident.title}</h3>
                </div>

                {/* Status Changer */}
                {canEdit && (
                  <div className="flex items-center gap-1 shrink-0">
                    <span className="text-[10px] font-mono text-slate-400">{isZh ? '變更狀態:' : 'State:'}</span>
                    <select
                      value={selectedIncident.status}
                      disabled={updating}
                      onChange={(e) => handleUpdateStatus(selectedIncident.id, e.target.value)}
                      className="bg-slate-950 border border-slate-700 text-xs rounded px-2 py-1 font-mono text-cyan-300 focus:outline-none disabled:opacity-50"
                    >
                      <option value="New">New</option>
                      <option value="Investigating">Investigating</option>
                      <option value="Contained">Contained</option>
                      <option value="Remediated">Remediated</option>
                      <option value="Closed">Closed</option>
                    </select>
                  </div>
                )}
              </div>

              {/* Meta information */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80">
                  <span className="text-slate-500 block text-[10px]">{isZh ? '攻擊來源 IP' : 'Source IP'}</span>
                  <span className="text-slate-200 font-semibold">{selectedIncident.sourceIp}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80">
                  <span className="text-slate-500 block text-[10px]">{isZh ? '受害目標 IP' : 'Target IP'}</span>
                  <span className="text-slate-200 font-semibold">{selectedIncident.targetIp}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80">
                  <span className="text-slate-500 block text-[10px]">{isZh ? 'MITRE 戰術戰技' : 'MITRE Technique'}</span>
                  <span className="text-cyan-300 font-semibold">{selectedIncident.mitreTechnique}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80">
                  <span className="text-slate-500 block text-[10px]">{isZh ? '分析師' : 'Assignee'}</span>
                  <span className="text-emerald-400 font-semibold">{selectedIncident.assignedTo}</span>
                </div>
              </div>

              {/* Summary */}
              <div>
                <h5 className="text-xs font-mono font-bold text-slate-300 mb-1">{isZh ? '事件調查摘要' : 'Investigation Summary'}</h5>
                <p className="text-xs text-slate-400 leading-relaxed p-3 rounded-xl bg-slate-950/50 border border-slate-800 font-mono">
                  {selectedIncident.summary}
                </p>
              </div>

              {/* Investigation Notes Chain */}
              <div>
                <h5 className="text-xs font-mono font-bold text-slate-300 mb-2 flex items-center gap-1.5">
                  <MessageSquare className="w-3.5 h-3.5 text-cyan-400" />
                  {isZh ? '處置稽核日誌與調查備註' : 'Remediation Notes & Action Log'}
                </h5>
                <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                  {selectedIncident.notes?.map((n, idx) => (
                    <div key={idx} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 text-xs font-mono text-slate-300">
                      {n}
                    </div>
                  ))}
                  {(!selectedIncident.notes || selectedIncident.notes.length === 0) && (
                    <div className="text-xs font-mono text-slate-500 italic p-2">{isZh ? '暫無處置備註' : 'No notes recorded.'}</div>
                  )}
                </div>

                {canEdit && (
                  <form onSubmit={handleAddNote} className="flex gap-2 mt-3">
                    <input
                      type="text"
                      value={newNote}
                      onChange={(e) => setNewNote(e.target.value)}
                      placeholder={isZh ? '新增分析備註 (如：已阻斷來源 IP、完成主機隔離)' : 'Add investigation note...'}
                      className="flex-1 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                    />
                    <button
                      type="submit"
                      disabled={updating || !newNote.trim()}
                      className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-bold transition-all disabled:opacity-50"
                    >
                      {isZh ? '送出' : 'Add'}
                    </button>
                  </form>
                )}
              </div>
            </div>
          ) : (
            <div className="p-12 text-center text-slate-500 font-mono text-xs rounded-xl border border-slate-800">
              {isZh ? '請選擇左側事件以檢視處置細節' : 'Select an incident from the left to inspect'}
            </div>
          )}
        </div>
      </div>

      {/* Manual Incident Creation Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="glass-panel p-6 rounded-2xl max-w-xl w-full border border-cyan-500/30 space-y-4 shadow-2xl bg-slate-900">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2 font-mono">
                <AlertOctagon className="w-5 h-5 text-amber-400" />
                {isZh ? '手動建立資安事件工單' : 'Create New Incident Case'}
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {createError && (
              <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-xs font-mono text-red-400">
                {createError}
              </div>
            )}

            <form onSubmit={handleCreateIncident} className="space-y-3 font-mono text-xs">
              <div>
                <label className="text-slate-400 block mb-1">{isZh ? '事件名稱 / 標題 *' : 'Incident Title *'}</label>
                <input
                  type="text"
                  required
                  placeholder={isZh ? "例如: 外部 C2 通聯可疑端點主機" : "e.g., C2 Beaconing Detected on Workstation"}
                  value={createForm.title}
                  onChange={e => setCreateForm(f => ({ ...f, title: e.target.value }))}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">{isZh ? '嚴重度' : 'Severity'}</label>
                  <select
                    value={createForm.severity}
                    onChange={e => setCreateForm(f => ({ ...f, severity: e.target.value }))}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-cyan-300 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">{isZh ? 'MITRE 戰術手法' : 'MITRE Technique'}</label>
                  <input
                    type="text"
                    placeholder="T1071.001 (Web Protocols)"
                    value={createForm.mitreTechnique}
                    onChange={e => setCreateForm(f => ({ ...f, mitreTechnique: e.target.value }))}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">{isZh ? '來源 IP / 端點' : 'Source IP / Endpoint'}</label>
                  <input
                    type="text"
                    placeholder="185.220.101.5"
                    value={createForm.sourceIp}
                    onChange={e => setCreateForm(f => ({ ...f, sourceIp: e.target.value }))}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">{isZh ? '受害目標 IP' : 'Target IP'}</label>
                  <input
                    type="text"
                    placeholder="10.0.4.15"
                    value={createForm.targetIp}
                    onChange={e => setCreateForm(f => ({ ...f, targetIp: e.target.value }))}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">{isZh ? '事件調查摘要與應變處置程序 (SOP)' : 'Investigation Summary & Response Actions'}</label>
                <textarea
                  rows={3}
                  placeholder={isZh ? "描述異常特徵、初步證據與第一步隔離措施..." : "Describe anomaly signature, initial evidence, containment steps..."}
                  value={createForm.summary}
                  onChange={e => setCreateForm(f => ({ ...f, summary: e.target.value }))}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold"
                >
                  {isZh ? '取消' : 'Cancel'}
                </button>
                <button
                  type="submit"
                  disabled={updating}
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-amber-500 to-red-600 hover:from-amber-400 hover:to-red-500 text-white font-bold disabled:opacity-50"
                >
                  {updating ? (isZh ? '建立中…' : 'Creating…') : (isZh ? '建立工單' : 'Create Case')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

