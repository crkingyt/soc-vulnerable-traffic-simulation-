import React from 'react';
import { Skull, ShieldAlert } from 'lucide-react';

export default function TopAttackers({ metrics }) {
  // Extract top IPs
  const topIps = metrics?.top_attacking_ips || [];
  
  // Extract top attack types from attack_distribution object
  const attackDist = metrics?.attack_distribution || {};
  const topTypes = Object.entries(attackDist)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  const colors = ['bg-red-500', 'bg-orange-500', 'bg-yellow-500', 'bg-emerald-500', 'bg-blue-500'];

  // Fallbacks if data is empty on startup
  const displayIps = topIps.length > 0 ? topIps : [
    { ip: '192.168.1.10', count: 0 },
    { ip: '10.10.10.5', count: 0 },
    { ip: '172.16.1.20', count: 0 },
    { ip: '203.0.113.15', count: 0 },
    { ip: '198.51.100.8', count: 0 }
  ];

  const displayTypes = topTypes.length > 0 ? topTypes : [
    { name: 'SQL Injection', count: 0 },
    { name: 'Brute Force', count: 0 },
    { name: 'XSS Attack', count: 0 },
    { name: 'Directory Traversal', count: 0 },
    { name: 'Command Injection', count: 0 }
  ];

  // Get max values for percentage calculations
  const maxIpCount = Math.max(...displayIps.map(i => i.count), 1);
  const maxTypeCount = Math.max(...displayTypes.map(t => t.count), 1);

  return (
    <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col h-full space-y-5">
      {/* 1. Top Attacking IPs Section */}
      <div className="space-y-3.5">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center">
          <Skull className="w-4 h-4 mr-2 text-red-500" />
          Top Attacking IPs
        </h3>
        
        <div className="space-y-2.5">
          {displayIps.slice(0, 5).map((row, idx) => {
            const percentage = Math.max(5, (row.count / maxIpCount) * 100);
            return (
              <div key={idx} className="space-y-1">
                <div className="flex justify-between items-center text-[10px]">
                  <span className="font-mono text-slate-300 font-semibold">{row.ip}</span>
                  <span className="font-bold text-slate-400 font-mono">{row.count}</span>
                </div>
                <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden">
                  <div 
                    className={`h-full ${colors[idx % colors.length]} rounded-full transition-all duration-500`}
                    style={{ width: `${row.count > 0 ? percentage : 0}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 2. Top Attack Types Section */}
      <div className="space-y-3.5 border-t border-slate-900 pt-4">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center">
          <ShieldAlert className="w-4 h-4 mr-2 text-orange-500" />
          Top Attack Types
        </h3>
        
        <div className="space-y-2.5">
          {displayTypes.map((row, idx) => {
            const percentage = Math.max(5, (row.count / maxTypeCount) * 100);
            return (
              <div key={idx} className="space-y-1">
                <div className="flex justify-between items-center text-[10px]">
                  <span className="text-slate-300 font-semibold">{row.name}</span>
                  <span className="font-bold text-slate-400 font-mono">{row.count}</span>
                </div>
                <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden">
                  <div 
                    className={`h-full ${colors[idx % colors.length]} rounded-full transition-all duration-500`}
                    style={{ width: `${row.count > 0 ? percentage : 0}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
