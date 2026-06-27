import React, { useState, useEffect } from 'react';
import { Compass, AlertTriangle, User, FileText, CheckCircle2, RefreshCw } from 'lucide-react';

export default function IncidentManager({ incidents, onUpdateIncident, triggerRefresh }) {
  const [editingId, setEditingId] = useState(null);
  const [editStatus, setEditStatus] = useState('');
  const [editNotes, setEditNotes] = useState('');
  const [editAnalyst, setEditAnalyst] = useState('');

  const startEdit = (incident) => {
    setEditingId(incident.id);
    setEditStatus(incident.status);
    setEditNotes(incident.analyst_notes || '');
    setEditAnalyst(incident.assigned_analyst || '');
  };

  const handleSave = async (id) => {
    const success = await onUpdateIncident(id, {
      status: editStatus,
      analyst_notes: editNotes,
      assigned_analyst: editAnalyst
    });
    if (success) {
      setEditingId(null);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'Resolved':
        return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
      case 'In Progress':
        return 'bg-blue-500/10 text-blue-400 border border-blue-500/20';
      case 'Open':
      default:
        return 'bg-red-500/10 text-red-400 border border-red-500/20';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-lg font-semibold text-slate-100 flex items-center">
          <Compass className="w-5 h-5 mr-2 text-blue-500" />
          Active Incident Investigations
        </h2>
        <button 
          onClick={triggerRefresh}
          className="flex items-center space-x-1 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 rounded-lg transition-colors border border-slate-750"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh List</span>
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {incidents.length === 0 ? (
          <div className="h-64 flex flex-col justify-center items-center text-slate-500 border border-dashed border-slate-800 rounded-2xl">
            <CheckCircle2 className="w-8 h-8 text-emerald-500/60 mb-2" />
            <p className="text-sm">No incidents reported.</p>
            <p className="text-xs text-slate-600">Escalate alerts from Threat Hunting or Alerts feed.</p>
          </div>
        ) : (
          incidents.map((incident) => {
            const isEditing = editingId === incident.id;
            
            return (
              <div 
                key={incident.id}
                className="glass-panel p-5 rounded-2xl border border-slate-800/80 space-y-4 hover:border-slate-800 transition-all"
              >
                {/* Header info */}
                <div className="flex items-start justify-between">
                  <div className="space-y-1.5">
                    <div className="flex items-center space-x-3">
                      <span className="font-mono text-xs text-slate-500 font-bold">#INC-{incident.id}</span>
                      <span className={`px-2.5 py-0.5 rounded-full text-[10px] uppercase font-bold tracking-wider ${getStatusColor(incident.status)}`}>
                        {incident.status}
                      </span>
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${
                        incident.severity === 'Critical' ? 'border-red-500/30 text-red-400 bg-red-950/20' :
                        incident.severity === 'High' ? 'border-orange-500/30 text-orange-400 bg-orange-950/20' :
                        'border-amber-500/20 text-amber-300 bg-amber-950/10'
                      }`}>
                        {incident.severity} Severity
                      </span>
                    </div>
                    <h3 className="text-sm font-semibold text-slate-200">{incident.attack_type} Investigation</h3>
                    <p className="text-[10px] text-slate-500 font-mono">Created at: {incident.created_at.replace('T', ' ').slice(0,19)}</p>
                  </div>

                  {!isEditing && (
                    <button
                      onClick={() => startEdit(incident)}
                      className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 rounded-lg transition-colors border border-slate-750"
                    >
                      Update Incident
                    </button>
                  )}
                </div>

                {/* Associated Alerts count */}
                {incident.alerts && incident.alerts.length > 0 && (
                  <div className="bg-slate-950/30 p-3 rounded-lg border border-slate-900/60 text-xs space-y-2">
                    <span className="text-slate-500 font-semibold uppercase tracking-wider block text-[10px]">Associated Detections ({incident.alerts.length})</span>
                    <div className="flex flex-wrap gap-2">
                      {incident.alerts.map(a => (
                        <span key={a.id} className="bg-slate-900 px-2 py-1 rounded border border-slate-850 font-mono text-[10px] text-slate-300">
                          IP: {a.source_ip} | Threat Score: {a.threat_score}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Inline Editing vs Normal content */}
                {isEditing ? (
                  <div className="space-y-4 pt-2 border-t border-slate-800/40 text-xs">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="flex flex-col">
                        <label className="text-slate-500 font-semibold uppercase tracking-wider block mb-1">Status</label>
                        <select
                          value={editStatus}
                          onChange={(e) => setEditStatus(e.target.value)}
                          className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-slate-300 outline-none focus:border-slate-700"
                        >
                          <option value="Open">Open</option>
                          <option value="In Progress">In Progress</option>
                          <option value="Resolved">Resolved</option>
                        </select>
                      </div>

                      <div className="flex flex-col">
                        <label className="text-slate-500 font-semibold uppercase tracking-wider block mb-1">Assigned Analyst</label>
                        <input
                          type="text"
                          value={editAnalyst}
                          onChange={(e) => setEditAnalyst(e.target.value)}
                          placeholder="e.g. Analyst A"
                          className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 outline-none focus:border-slate-700 font-sans"
                        />
                      </div>
                    </div>

                    <div className="flex flex-col">
                      <label className="text-slate-500 font-semibold uppercase tracking-wider block mb-1">Resolution / Analyst Notes</label>
                      <textarea
                        value={editNotes}
                        onChange={(e) => setEditNotes(e.target.value)}
                        rows={3}
                        placeholder="Add investigative updates, block details, or mitigation remarks here..."
                        className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 outline-none focus:border-slate-700 font-sans resize-none"
                      />
                    </div>

                    <div className="flex justify-end space-x-2 pt-2 border-t border-slate-850">
                      <button
                        onClick={() => setEditingId(null)}
                        className="px-4 py-2 bg-slate-800 hover:bg-slate-750 text-slate-400 font-semibold rounded-lg transition-colors"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={() => handleSave(incident.id)}
                        className="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-lg transition-colors shadow-[0_0_10px_rgba(37,99,235,0.3)]"
                      >
                        Save Incident
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="grid grid-cols-2 gap-4 text-xs pt-2 border-t border-slate-800/40">
                    <div>
                      <span className="text-slate-500 font-semibold uppercase tracking-wider block mb-1">Assigned Analyst</span>
                      <p className="flex items-center text-slate-300 font-sans font-medium">
                        <User className="w-3.5 h-3.5 mr-1.5 text-slate-500" />
                        {incident.assigned_analyst || 'Unassigned'}
                      </p>
                    </div>
                    <div>
                      <span className="text-slate-500 font-semibold uppercase tracking-wider block mb-1">Resolution Notes</span>
                      <p className="text-slate-300 font-sans flex items-start leading-relaxed bg-slate-950/20 p-2.5 border border-slate-900 rounded-lg">
                        <FileText className="w-3.5 h-3.5 mr-2 mt-0.5 text-slate-500 shrink-0" />
                        {incident.analyst_notes || 'No investigative updates recorded.'}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
