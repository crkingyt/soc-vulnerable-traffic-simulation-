import React, { useState } from 'react';
import { UserMinus, CheckCircle, RefreshCw, Trash2, Loader } from 'lucide-react';

export default function BlockedIpsManager({ blockedIpsList, triggerRefresh }) {
  const [unblockingIp, setUnblockingIp] = useState(null);

  const getCleanTime = (ts) => {
    try {
      if (ts.includes('T')) {
        return ts.replace('T', ' ').substring(0, 19);
      }
      return ts;
    } catch {
      return ts;
    }
  };

  const getCleanReason = (reason) => {
    if (!reason) return 'Malicious Traffic';
    return reason;
  };

  const handleUnblock = async (ip) => {
    setUnblockingIp(ip);
    try {
      const res = await fetch(`/api/blocked-ips/${ip}/unblock`, {
        method: 'POST'
      });
      if (res.ok) {
        // Refresh blocklist data
        triggerRefresh();
      }
    } catch (e) {
      console.error("Failed to unblock IP address", e);
    } finally {
      setUnblockingIp(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center mb-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center">
            <UserMinus className="w-5 h-5 mr-2 text-rose-500" />
            Firewall Blocked IPs
          </h2>
          <p className="text-xs text-slate-500">Active server-side rule blocklists. Analysts can restore connections dynamically.</p>
        </div>
        <button
          onClick={triggerRefresh}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 border border-slate-750 rounded-lg transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Firewall</span>
        </button>
      </div>

      <div className="glass-panel p-5 rounded-2xl border border-slate-800/80">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 font-semibold uppercase tracking-wider pb-3">
                <th className="pb-3">Block Time</th>
                <th className="pb-3">IP Address</th>
                <th className="pb-3">Threat Score</th>
                <th className="pb-3">Blocked By</th>
                <th className="pb-3">Reason</th>
                <th className="pb-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900 font-sans">
              {(!blockedIpsList || blockedIpsList.length === 0) ? (
                <tr>
                  <td colSpan={6} className="text-center py-16 text-slate-600">
                    <CheckCircle className="w-8 h-8 text-emerald-500/60 mx-auto mb-2" />
                    <p className="text-sm font-semibold">Firewall block list is clean.</p>
                    <p className="text-xs text-slate-700 mt-0.5">No IP addresses are currently blacklisted on simulation networks.</p>
                  </td>
                </tr>
              ) : (
                blockedIpsList.map((row, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/10">
                    <td className="py-3.5 font-mono text-slate-500">{getCleanTime(row.timestamp)}</td>
                    <td className="py-3.5 font-mono text-slate-300 font-bold">{row.ip}</td>
                    <td className="py-3.5">
                      <span className="px-2 py-0.5 bg-rose-950/20 border border-rose-900/40 text-rose-400 font-bold font-mono rounded">
                        {row.threat_score || 85}
                      </span>
                    </td>
                    <td className="py-3.5">
                      <span className={`px-2 py-0.5 rounded text-[9px] uppercase font-bold tracking-wider ${
                        row.blocked_by === 'auto'
                          ? 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                          : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                      }`}>
                        {row.blocked_by === 'auto' ? 'SOAR AUTO' : 'ANALYST'}
                      </span>
                    </td>
                    <td className="py-3.5 text-slate-400 max-w-[200px] truncate" title={row.reason}>
                      {getCleanReason(row.reason)}
                    </td>
                    <td className="py-3.5 text-right">
                      <button
                        onClick={() => handleUnblock(row.ip)}
                        disabled={unblockingIp === row.ip}
                        className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-800 text-slate-950 hover:text-white font-bold rounded-lg text-[10px] transition-all flex items-center space-x-1.5 ml-auto"
                      >
                        {unblockingIp === row.ip ? (
                          <Loader className="w-3 h-3 animate-spin" />
                        ) : (
                          <Trash2 className="w-3.5 h-3.5" />
                        )}
                        <span>Unblock Remote</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
