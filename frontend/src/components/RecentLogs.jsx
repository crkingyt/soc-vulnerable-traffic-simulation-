import React from 'react';
import { FileCode } from 'lucide-react';

export default function RecentLogs({ logs }) {
  const getCleanTime = (ts) => {
    try {
      // E.g. "2026-06-26T15:24:35.000Z" -> "15:24:35"
      if (ts.includes('T')) {
        return ts.split('T')[1].substring(0, 8);
      }
      return ts.substring(11, 19) || ts;
    } catch {
      return ts;
    }
  };

  const getStatusColor = (code) => {
    const numericCode = parseInt(code);
    if (numericCode >= 500) return 'text-red-500 font-bold';
    if (numericCode >= 400) return 'text-orange-400 font-bold';
    return 'text-emerald-500 font-bold';
  };

  return (
    <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col h-full space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center">
          <FileCode className="w-4 h-4 mr-2 text-blue-500" />
          Recent Logs
        </h3>
        <span className="text-[10px] text-blue-400 cursor-pointer hover:underline">
          View All Logs &rarr;
        </span>
      </div>

      <div className="overflow-x-auto flex-1">
        <table className="w-full text-left text-[10px]">
          <thead>
            <tr className="border-b border-slate-800 text-slate-500 font-semibold uppercase tracking-wider">
              <th className="pb-2">Time</th>
              <th className="pb-2">Method</th>
              <th className="pb-2">URL</th>
              <th className="pb-2">Source IP</th>
              <th className="pb-2">Status</th>
              <th className="pb-2">User Agent</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-900 font-mono">
            {logs.length === 0 ? (
              <tr>
                <td colSpan={6} className="text-center py-10 text-slate-600 font-sans">
                  Awaiting live server activity...
                </td>
              </tr>
            ) : (
              logs.map((log, idx) => (
                <tr key={idx} className="hover:bg-slate-900/30">
                  <td className="py-2 text-slate-500">{getCleanTime(log.timestamp)}</td>
                  <td className="py-2 text-slate-300 font-semibold">{log.method}</td>
                  <td className="py-2 text-slate-400 truncate max-w-[150px]" title={log.uri}>
                    {log.uri}
                  </td>
                  <td className="py-2 text-slate-300">{log.source_ip}</td>
                  <td className={`py-2 ${getStatusColor(log.status_code)}`}>
                    {log.status_code}
                  </td>
                  <td className="py-2 text-slate-500 truncate max-w-[100px]" title={log.user_agent}>
                    {log.user_agent}
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
