import React from 'react';
import { ShieldAlert } from 'lucide-react';

export default function BlockedIPs({ blockedIpsList }) {
  const getCleanTime = (ts) => {
    try {
      if (ts.includes('T')) {
        return ts.split('T')[1].substring(0, 8);
      }
      return ts.substring(11, 19) || ts;
    } catch {
      return ts;
    }
  };

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

  return (
    <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col h-full space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center">
          <ShieldAlert className="w-4 h-4 mr-2 text-rose-500" />
          Blocked IPs
        </h3>
        <span className="text-[10px] text-blue-400 cursor-pointer hover:underline">
          View All &rarr;
        </span>
      </div>

      <div className="overflow-y-auto flex-1 max-h-[190px] pr-1">
        {(!blockedIpsList || blockedIpsList.length === 0) ? (
          <div className="text-center py-10 text-slate-600 font-sans">
            No active firewall blocks.
          </div>
        ) : (
          <div className="space-y-2">
            {blockedIpsList.slice(0, 5).map((row, idx) => (
              <div 
                key={idx} 
                className="flex items-center justify-between p-2 rounded-lg bg-slate-950/40 border border-slate-900 font-mono text-[10px]"
              >
                <div className="flex items-center space-x-2.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-rose-500 shrink-0" />
                  <div>
                    <p className="font-bold text-slate-300">{row.ip}</p>
                    <p className="text-[9px] text-slate-500 font-sans mt-0.5">{getCleanReason(row.reason)}</p>
                  </div>
                </div>
                
                <span className="text-slate-500">{getCleanTime(row.timestamp)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
