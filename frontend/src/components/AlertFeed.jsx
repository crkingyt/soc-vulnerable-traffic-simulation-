import React, { useState } from 'react';
import { Shield, ShieldAlert, ShieldOff, CheckCircle2, ChevronDown, ChevronUp, Loader, FolderPlus } from 'lucide-react';

export default function AlertFeed({ alerts, onBlock, onDismiss, onEscalate }) {
  const [expandedAlertId, setExpandedAlertId] = useState(null);
  const [intelData, setIntelData] = useState({});
  const [loadingIntel, setLoadingIntel] = useState(false);

  const fetchIntel = async (ip) => {
    if (intelData[ip]) return;
    setLoadingIntel(true);
    try {
      const res = await fetch(`/api/intel/${ip}`);
      if (res.ok) {
        const data = await res.json();
        setIntelData(prev => ({ ...prev, [ip]: data }));
      }
    } catch (e) {
      console.error("Failed to fetch threat intelligence", e);
    } finally {
      setLoadingIntel(false);
    }
  };

  const toggleExpand = (alert) => {
    if (expandedAlertId === alert.id) {
      setExpandedAlertId(null);
    } else {
      setExpandedAlertId(alert.id);
      fetchIntel(alert.source_ip);
    }
  };

  const getSeverityStyles = (severity) => {
    switch (severity) {
      case 'Critical':
        return 'bg-red-500/10 text-red-500 border border-red-500/30 shadow-[0_0_8px_rgba(239,68,68,0.2)]';
      case 'High':
        return 'bg-orange-500/10 text-orange-500 border border-orange-500/30';
      case 'Medium':
        return 'bg-amber-500/10 text-amber-400 border border-amber-500/20';
      case 'Low':
      default:
        return 'bg-slate-500/10 text-slate-400 border border-slate-500/20';
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-lg font-semibold text-slate-100 flex items-center">
          <ShieldAlert className="w-5 h-5 mr-2 text-red-500" />
          Real-Time Alert Feed
        </h2>
        <span className="text-xs text-slate-500 font-mono">Showing last {alerts.length} events</span>
      </div>

      <div className="flex-1 overflow-y-auto space-y-3 pr-2" style={{ maxHeight: '720px' }}>
        {alerts.length === 0 ? (
          <div className="h-64 flex flex-col justify-center items-center text-slate-500 border border-dashed border-slate-800 rounded-xl">
            <CheckCircle2 className="w-8 h-8 text-emerald-500/60 mb-2" />
            <p className="text-sm">No active alerts detected.</p>
            <p className="text-xs text-slate-600">Simulator benign requests active...</p>
          </div>
        ) : (
          alerts.map((alert) => {
            const isExpanded = expandedAlertId === alert.id;
            const isBlocked = alert.status === 'Escalated' || alert.auto_blocked;
            const isDismissed = alert.status === 'Dismissed';
            const ipIntel = intelData[alert.source_ip];

            if (isDismissed) return null;

            return (
              <div 
                key={alert.id} 
                className={`rounded-xl border transition-all ${
                  isExpanded ? 'bg-slate-900/60 border-slate-700' : 'bg-slate-900/30 border-slate-800/80 hover:border-slate-800'
                }`}
              >
                {/* Header row */}
                <div 
                  onClick={() => toggleExpand(alert)}
                  className="p-4 flex items-center justify-between cursor-pointer select-none"
                >
                  <div className="flex items-center space-x-3.5">
                    {/* Severity Badge */}
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] uppercase font-bold tracking-wider ${getSeverityStyles(alert.severity)}`}>
                      {alert.severity}
                    </span>
                    
                    <div>
                      <h4 className="font-semibold text-sm text-slate-200">{alert.attack_type}</h4>
                      <p className="text-xs text-slate-500 font-mono mt-0.5">
                        {alert.source_ip} &rarr; <span className="text-blue-400 font-bold">{alert.server.toUpperCase()}</span>
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-6">
                    {/* Threat Score Gauge */}
                    <div className="flex flex-col items-end">
                      <span className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold">Threat Score</span>
                      <div className="flex items-center space-x-1.5 mt-0.5">
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div 
                            className={`h-full rounded-full ${
                              alert.threat_score >= 80 ? 'bg-red-500' : alert.threat_score >= 50 ? 'bg-orange-500' : 'bg-amber-500'
                            }`}
                            style={{ width: `${alert.threat_score}%` }}
                          />
                        </div>
                        <span className="text-xs font-mono font-bold text-slate-300">{alert.threat_score}/100</span>
                      </div>
                    </div>

                    {/* Expand Chevron */}
                    {isExpanded ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
                  </div>
                </div>

                {/* Expanded Details Section */}
                {isExpanded && (
                  <div className="px-4 pb-4 border-t border-slate-800/80 pt-4 space-y-4 text-xs text-slate-300 bg-slate-950/20 rounded-b-xl">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <span className="text-slate-500 font-semibold uppercase tracking-wider block mb-1">MITRE Technique</span>
                        <p className="font-mono text-blue-400">{alert.mitre_id} ({alert.kill_chain_stage})</p>
                      </div>
                      <div>
                        <span className="text-slate-500 font-semibold uppercase tracking-wider block mb-1">Timestamp</span>
                        <p className="font-mono">{alert.timestamp.replace('T', ' ').slice(0, 19)}</p>
                      </div>
                    </div>

                    <div>
                      <span className="text-slate-500 font-semibold uppercase tracking-wider block mb-1">Recommended Mitigation</span>
                      <p className="bg-slate-900/50 p-2.5 rounded-lg border border-slate-800 text-slate-300">
                        {alert.mitre_id === 'T1190' ? 'Use parameterized queries, validate inputs, WAF.' : 
                         alert.mitre_id === 'T1059.007' ? 'Context encoding, strict CSP, sanitize output.' :
                         alert.mitre_id === 'T1083' ? 'Restrict root directories, path validation, chroot.' :
                         alert.mitre_id === 'T1110' ? 'Multi-factor auth, lockouts, limit rate.' :
                         alert.mitre_id === 'T1059' ? 'Avoid direct execution, sanitize host shells.' : 
                         'Block scanning IPs, set limit rate, deploy honeypot.'}
                      </p>
                    </div>

                    {/* Threat Intel Sub-panel */}
                    <div className="bg-slate-900/40 p-3 rounded-lg border border-slate-800/50">
                      <span className="text-slate-500 font-semibold uppercase tracking-wider block mb-2">Threat Intel Reputation</span>
                      {loadingIntel ? (
                        <div className="flex items-center space-x-2 text-slate-500">
                          <Loader className="w-3.5 h-3.5 animate-spin" />
                          <span>Querying Reputation feeds...</span>
                        </div>
                      ) : ipIntel ? (
                        <div className="grid grid-cols-3 gap-2 font-mono text-[11px]">
                          <div>
                            <span className="text-slate-500 block">Reputation:</span>
                            <span className={ipIntel.matched ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                              {ipIntel.reputation_score}/100
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-500 block">Class:</span>
                            <span className="text-slate-300">{ipIntel.threat_classification}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block">Feed Source:</span>
                            <span className="text-slate-400">{ipIntel.provider}</span>
                          </div>
                        </div>
                      ) : (
                        <span className="text-slate-500">Reputation metrics offline</span>
                      )}
                    </div>

                    <div>
                      <span className="text-slate-500 font-semibold uppercase tracking-wider block mb-1">Raw Payload Log</span>
                      <pre className="bg-slate-950 p-2.5 rounded-lg border border-slate-900 font-mono text-[10px] text-slate-400 overflow-x-auto whitespace-pre-wrap">
                        {alert.raw_log}
                      </pre>
                    </div>

                    {/* Actions Panel */}
                    <div className="flex justify-end space-x-2 pt-2 border-t border-slate-800/40">
                      {onEscalate && alert.status !== 'Escalated' && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onEscalate({
                              attack_type: alert.attack_type,
                              severity: alert.severity,
                              alert_ids: [alert.id],
                              analyst_notes: `Escalated from Real-Time Alert Feed. IP: ${alert.source_ip} querying ${alert.server.toUpperCase()}`
                            });
                          }}
                          className="flex items-center space-x-1.5 px-3.5 py-1.5 bg-blue-600/10 hover:bg-blue-600 text-blue-400 hover:text-white border border-blue-500/20 rounded-lg transition-all font-medium"
                        >
                          <FolderPlus className="w-4 h-4" />
                          <span>Escalate Alert</span>
                        </button>
                      )}

                      {isBlocked ? (
                        <span className="flex items-center text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 rounded-lg font-semibold space-x-1.5">
                          <Shield className="w-4 h-4" />
                          <span>Defensively Blocked</span>
                        </span>
                      ) : (
                        <>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onDismiss(alert.id);
                            }}
                            className="flex items-center space-x-1.5 px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors font-medium"
                          >
                            <ShieldOff className="w-4 h-4" />
                            <span>Dismiss</span>
                          </button>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onBlock(alert.id);
                            }}
                            className="flex items-center space-x-1.5 px-3.5 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors font-medium shadow-[0_0_10px_rgba(220,38,38,0.3)]"
                          >
                            <Shield className="w-4 h-4" />
                            <span>Block Attacker</span>
                          </button>
                        </>
                      )}
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
