import React from 'react';
import { PlayCircle } from 'lucide-react';

export default function AutoResponse({ blockedIpsList }) {
  const getCleanTime = (ts) => {
    try {
      if (ts.includes('T')) {
        return ts.split('T')[1].substring(0, 8);
      }
      return ts.substring(11, 19) || ts;
    } catch (e) {
      return ts;
    }
  };

  // Extract reason category (e.g., "Manual analyst block: Alert ID X (SQL Injection)" -> "SQL Injection")
  const getCleanReason = (reason) => {
    if (!reason) return 'Malicious Traffic';
    if (reason.includes('(')) {
      return reason.split('(')[1].replace(')', '');
    }
    if (reason.includes('score')) {
      const parts = reason.split(':');
      if (parts.length > 1) {
        return parts[1].split('threat')[0].trim();
      }
    }
    return reason;
  };

  const getActionType = (blockedBy) => {
    return blockedBy === 'auto' ? 'Auto Block' : 'IP Blocked';
  };

  return (
    <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col h-full space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center">
          <PlayCircle className="w-4 h-4 mr-2 text-emerald-500" />
          Automated Response Actions
        </h3>
        <span className="text-[10px] text-blue-400 cursor-pointer hover:underline">
          View All Actions &rarr;
        </span>
      </div>

      <div className="overflow-x-auto flex-1">
        <table className="w-full text-left text-[10px]">
          <thead>
            <tr className="border-b border-slate-800 text-slate-500 font-semibold uppercase tracking-wider">
              <th className="pb-2">Time</th>
              <th className="pb-2">Action</th>
              <th className="pb-2">Target</th>
              <th className="pb-2">Reason</th>
              <th className="pb-2 text-right">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-900 font-sans">
            {(!blockedIpsList || blockedIpsList.length === 0) ? (
              <tr>
                <td colSpan={5} className="text-center py-8 text-slate-600">
                  No automated SOAR responses triggered yet.
                </td>
              </tr>
            ) : (
              blockedIpsList.slice(0, 5).map((row, idx) => (
                <tr key={idx} className="hover:bg-slate-900/30">
                  <td className="py-2.5 font-mono text-slate-500">{getCleanTime(row.timestamp)}</td>
                  <td className="py-2.5 font-semibold text-slate-300">
                    <span className="bg-slate-900 px-2 py-0.5 rounded border border-slate-800 text-[9px] text-slate-400">
                      {getActionType(row.blocked_by)}
                    </span>
                  </td>
                  <td className="py-2.5 font-mono text-slate-300">{row.ip}</td>
                  <td className="py-2.5 text-slate-400 truncate max-w-[130px]" title={row.reason}>
                    {getCleanReason(row.reason)}
                  </td>
                  <td className="py-2.5 text-right font-bold text-emerald-400 font-mono">
                    SUCCESS
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
