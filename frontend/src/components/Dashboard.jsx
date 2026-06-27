import React, { useState, useEffect } from 'react';
import { 
  Zap, Database, ShieldAlert, Skull, CheckCircle, UserMinus, 
  Play, Square, Sliders, AlertTriangle, Activity, SlidersHorizontal 
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area } from 'recharts';

import Charts from './Charts';
import RecentLogs from './RecentLogs';
import MitreAttck from './MitreAttck';
import KillChain from './KillChain';
import PredictedAttack from './PredictedAttack';
import TopAttackers from './TopAttackers';
import AutoResponse from './AutoResponse';
import IncidentSummary from './IncidentSummary';
import BlockedIPs from './BlockedIPs';

export default function Dashboard({ 
  metrics, 
  alerts, 
  latestAlert, 
  epsHistory, 
  onBlock, 
  onDismiss, 
  onConfigChange,
  logs = [],
  setActiveTab,
  incidents = []
}) {
  const [eps, setEps] = useState(metrics.current_eps || 10);
  const [vulnPercent, setVulnPercent] = useState(5.0);
  const [isRunning, setIsRunning] = useState(metrics.is_simulation_running || false);
  const [showConfig, setShowConfig] = useState(false);

  // Sync state with incoming metrics
  useEffect(() => {
    if (metrics.current_eps) {
      setEps(metrics.current_eps);
    }
    setIsRunning(metrics.is_simulation_running);
  }, [metrics]);

  const handleConfigSubmit = async (e) => {
    e.preventDefault();
    await onConfigChange({
      eps: parseInt(eps),
      vulnerable_percent: parseFloat(vulnPercent),
      is_running: isRunning
    });
  };

  const toggleSimulation = async () => {
    const nextState = !isRunning;
    setIsRunning(nextState);
    await onConfigChange({
      eps: parseInt(eps),
      vulnerable_percent: parseFloat(vulnPercent),
      is_running: nextState
    });
  };

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

  // Sparkline data generators
  const sparklineData = (val, multiplier = 1) => {
    const seed = parseFloat(val) || 0;
    if (seed === 0) return Array.from({ length: 8 }, () => ({ value: 0 }));
    return [
      { value: seed * 0.78 * multiplier },
      { value: seed * 0.95 * multiplier },
      { value: seed * 0.84 * multiplier },
      { value: seed * 1.12 * multiplier },
      { value: seed * 0.90 * multiplier },
      { value: seed * 1.05 * multiplier },
      { value: seed * 0.98 * multiplier },
      { value: seed * 1.00 * multiplier }
    ];
  };

  const totalAlerts = metrics.alerts_count || 0;
  const fpPercentage = totalAlerts > 0 
    ? ((metrics.false_positives / totalAlerts) * 100).toFixed(1) 
    : '0.0';

  return (
    <div className="space-y-6">
      
      {/* Simulation Collapsible Panel Gear */}
      <div className="flex justify-end -mb-4">
        <button
          onClick={() => setShowConfig(!showConfig)}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200 rounded-lg text-xs font-semibold transition-all"
        >
          <SlidersHorizontal className="w-3.5 h-3.5" />
          <span>Simulator Panel</span>
        </button>
      </div>

      {showConfig && (
        <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 grid grid-cols-1 md:grid-cols-3 gap-6 items-center text-xs animate-fadeIn">
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-bold text-slate-300 uppercase tracking-wider">Attack Simulator Control</h3>
              <button
                onClick={toggleSimulation}
                className={`px-2.5 py-1 rounded text-[10px] font-bold transition-all ${
                  isRunning ? 'bg-red-600 hover:bg-red-500 text-white' : 'bg-emerald-600 hover:bg-emerald-500 text-white'
                }`}
              >
                {isRunning ? 'Halt Simulation' : 'Run Simulation'}
              </button>
            </div>
            <p className="text-[10px] text-slate-500">Modify attack event rates and payload ratios injected into mock paths.</p>
          </div>
          
          <form onSubmit={handleConfigSubmit} className="md:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-1">
              <div className="flex justify-between text-slate-400 font-semibold">
                <span>EPS Rate:</span>
                <span className="text-blue-400 font-mono">{eps}/s</span>
              </div>
              <input 
                type="range" min="2" max="30" value={eps} 
                onChange={(e) => setEps(parseInt(e.target.value))}
                className="w-full h-1 bg-slate-900 rounded-lg appearance-none cursor-pointer accent-blue-500"
              />
            </div>
            <div className="space-y-1">
              <div className="flex justify-between text-slate-400 font-semibold">
                <span>Attack Ratio:</span>
                <span className="text-blue-400 font-mono">{vulnPercent}%</span>
              </div>
              <input 
                type="range" min="2" max="30" step="0.5" value={vulnPercent} 
                onChange={(e) => setVulnPercent(parseFloat(e.target.value))}
                className="w-full h-1 bg-slate-900 rounded-lg appearance-none cursor-pointer accent-blue-500"
              />
            </div>
            <button type="submit" className="sm:col-span-2 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded font-bold transition-colors">
              Apply Simulator Parameters
            </button>
          </form>
        </div>
      )}

      {/* 1. Metric Cards Grid (6 columns) */}
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-4">
        {/* EPS Card */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800/80 flex flex-col justify-between h-24">
          <div className="flex items-center justify-between text-slate-500 font-semibold uppercase tracking-wider text-[9px]">
            <span>Events Per Second</span>
            <Zap className="w-3.5 h-3.5 text-sky-400 shrink-0" />
          </div>
          <div className="my-1.5 flex items-baseline justify-between">
            <h3 className="text-xl font-bold text-slate-100 font-mono">
              {metrics.current_eps || 0} <span className="text-[10px] text-slate-400 font-normal">/sec</span>
            </h3>
            <span className="text-[9px] text-emerald-400 font-bold">↑ 18%</span>
          </div>
          <div className="h-4 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={sparklineData(metrics.current_eps || 8)}>
                <Area type="monotone" dataKey="value" stroke="#38bdf8" fill="#38bdf810" strokeWidth={1} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Total Events */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800/80 flex flex-col justify-between h-24">
          <div className="flex items-center justify-between text-slate-500 font-semibold uppercase tracking-wider text-[9px]">
            <span>Total Events</span>
            <Database className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
          </div>
          <div className="my-1.5 flex items-baseline justify-between">
            <h3 className="text-xl font-bold text-slate-100 font-mono">
              {metrics.total_events?.toLocaleString() || 0}
            </h3>
            <span className="text-[9px] text-emerald-400 font-bold">↑ 22%</span>
          </div>
          <div className="h-4 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={sparklineData(metrics.total_events || 15000, 0.1)}>
                <Area type="monotone" dataKey="value" stroke="#6366f1" fill="#6366f110" strokeWidth={1} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Alerts count */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800/80 flex flex-col justify-between h-24">
          <div className="flex items-center justify-between text-slate-500 font-semibold uppercase tracking-wider text-[9px]">
            <span>Alerts</span>
            <ShieldAlert className="w-3.5 h-3.5 text-red-500 shrink-0" />
          </div>
          <div className="my-1.5 flex items-baseline justify-between">
            <h3 className="text-xl font-bold text-red-500 font-mono">
              {metrics.alerts_count || 0}
            </h3>
            <span className="text-[9px] text-red-400 font-bold">↑ 15%</span>
          </div>
          <div className="h-4 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={sparklineData(metrics.alerts_count || 120)}>
                <Area type="monotone" dataKey="value" stroke="#ef4444" fill="#ef444410" strokeWidth={1} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Score Card */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800/80 flex flex-col justify-between h-24">
          <div className="flex items-center justify-between text-slate-500 font-semibold uppercase tracking-wider text-[9px]">
            <span>Threat Score</span>
            <Skull className="w-3.5 h-3.5 text-orange-400 shrink-0" />
          </div>
          <div className="my-1 flex items-baseline justify-between">
            <h3 className="text-xl font-bold text-orange-400 font-mono">
              {latestAlert?.threat_score || 84}<span className="text-xs text-slate-400 font-normal">/100</span>
            </h3>
            <span className="text-[8px] px-1 bg-red-950/40 border border-red-900/60 rounded text-red-400 font-bold font-sans">
              ▲ High Risk
            </span>
          </div>
          <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden">
            <div 
              className="h-full bg-orange-500 shadow-[0_0_8px_#f97316] transition-all duration-300"
              style={{ width: `${latestAlert?.threat_score || 84}%` }}
            />
          </div>
        </div>

        {/* False Positive Rate */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800/80 flex flex-col justify-between h-24">
          <div className="flex items-center justify-between text-slate-500 font-semibold uppercase tracking-wider text-[9px]">
            <span>False Positives</span>
            <CheckCircle className="w-3.5 h-3.5 text-purple-400 shrink-0" />
          </div>
          <div className="my-1.5 flex items-baseline justify-between">
            <h3 className="text-xl font-bold text-purple-400 font-mono">
              {metrics.false_positives || 0} <span className="text-[10px] text-slate-500 font-normal">({fpPercentage}%)</span>
            </h3>
            <span className="text-[9px] text-emerald-400 font-bold">↓ 6%</span>
          </div>
          <div className="h-4 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={sparklineData(metrics.false_positives || 15)}>
                <Area type="monotone" dataKey="value" stroke="#a855f7" fill="#a855f710" strokeWidth={1} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Blocked IPs count */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800/80 flex flex-col justify-between h-24">
          <div className="flex items-center justify-between text-slate-500 font-semibold uppercase tracking-wider text-[9px]">
            <span>Blocked IPs</span>
            <UserMinus className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
          </div>
          <div className="my-1.5 flex items-baseline justify-between">
            <h3 className="text-xl font-bold text-emerald-400 font-mono">
              {metrics.blocked_ips || 0}
            </h3>
            <span className="text-[9px] text-emerald-400 font-bold">↑ 3</span>
          </div>
          <div className="h-4 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={sparklineData(metrics.blocked_ips || 18)}>
                <Area type="monotone" dataKey="value" stroke="#10b981" fill="#10b98110" strokeWidth={1} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* 2. Charts Section */}
      <Charts metrics={metrics} epsHistory={epsHistory} />

      {/* 3. Third Row Grid Layout */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        
        {/* Live Alert Feed table (col-span-5) */}
        <div className="xl:col-span-5 glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col h-[320px]">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center">
              <ShieldAlert className="w-4 h-4 mr-2 text-red-500" />
              Live Alert Feed
            </h3>
            <span 
              onClick={() => setActiveTab('alerts')}
              className="text-[10px] text-blue-400 cursor-pointer hover:underline"
            >
              View All Alerts &rarr;
            </span>
          </div>
          
          <div className="overflow-x-auto flex-1">
            <table className="w-full text-left text-[10px]">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 font-semibold uppercase tracking-wider">
                  <th className="pb-2">Time</th>
                  <th className="pb-2">Severity</th>
                  <th className="pb-2">Attack</th>
                  <th className="pb-2">Source IP</th>
                  <th className="pb-2 text-right">Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-900 font-sans">
                {alerts.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="text-center py-12 text-slate-600">
                      No security triggers recorded.
                    </td>
                  </tr>
                ) : (
                  alerts.slice(0, 6).map((al) => {
                    const isBlocked = al.auto_blocked || al.threat_score >= 80 || al.status === 'Escalated';
                    return (
                      <tr key={al.id} className="hover:bg-slate-900/30">
                        <td className="py-2 font-mono text-slate-500">{getCleanTime(al.timestamp)}</td>
                        <td className="py-2">
                          <span 
                            className="px-1.5 py-0.5 rounded font-bold text-[8px] uppercase"
                            style={{ 
                              backgroundColor: al.severity === 'Critical' ? '#ef444415' : 
                                               al.severity === 'High' ? '#f9731615' : 
                                               al.severity === 'Medium' ? '#eab30815' : '#10b98115',
                              color: al.severity === 'Critical' ? '#ef4444' : 
                                     al.severity === 'High' ? '#f97316' : 
                                     al.severity === 'Medium' ? '#eab308' : '#10b981'
                            }}
                          >
                            {al.severity}
                          </span>
                        </td>
                        <td className="py-2 font-semibold text-slate-300 truncate max-w-[110px]" title={al.attack_type}>
                          {al.attack_type}
                        </td>
                        <td className="py-2 font-mono text-slate-400">{al.source_ip}</td>
                        <td className="py-2 text-right">
                          {isBlocked ? (
                            <span className="px-1.5 py-0.5 bg-red-950/40 text-red-500 font-bold border border-red-900/60 rounded text-[9px]">
                              AUTO BLOCKED
                            </span>
                          ) : al.status === 'Dismissed' ? (
                            <span className="text-[9px] text-slate-600 font-semibold">Dismissed</span>
                          ) : (
                            <div className="flex justify-end space-x-1">
                              <button 
                                onClick={() => onBlock(al.id)}
                                className="px-2 py-0.5 bg-red-600 text-white font-bold rounded hover:bg-red-500 text-[9px] shadow-[0_0_8px_rgba(239,68,68,0.2)]"
                              >
                                Block
                              </button>
                              <button 
                                onClick={() => onDismiss(al.id)}
                                className="px-2 py-0.5 bg-slate-800 text-slate-400 font-semibold rounded hover:bg-slate-700 text-[9px]"
                              >
                                Dismiss
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
          
          <div className="mt-2.5 pt-2.5 border-t border-slate-900 flex justify-between text-[8px] text-slate-500 font-semibold">
            <span className="flex items-center"><span className="w-1.5 h-1.5 rounded-full bg-red-500 mr-1" /> Score &ge; 80: Auto Blocked</span>
            <span className="flex items-center"><span className="w-1.5 h-1.5 rounded-full bg-orange-500 mr-1" /> Score &lt; 80: Analyst Decision Required</span>
          </div>
        </div>

        {/* Recent Logs (col-span-4) */}
        <div className="xl:col-span-4 h-[320px]">
          <RecentLogs logs={logs} />
        </div>

        {/* Top Attackers (col-span-3) */}
        <div className="xl:col-span-3 h-[320px]">
          <TopAttackers metrics={metrics} />
        </div>
      </div>

      {/* 4. Fourth Row Grid Layout */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        
        {/* MITRE Top Techniques table (col-span-4) */}
        <div className="xl:col-span-4 h-[220px]">
          <MitreAttck topTechniques={metrics.top_mitre_techniques} />
        </div>

        {/* Cyber Kill Chain flow diagram (col-span-5) */}
        <div className="xl:col-span-5 h-[220px]">
          <KillChain alerts={alerts} />
        </div>

        {/* Predicted Next Attack (col-span-3) */}
        <div className="xl:col-span-3 h-[220px]">
          <PredictedAttack latestAlert={latestAlert} />
        </div>
      </div>

      {/* 5. Fifth Row Grid Layout */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        
        {/* Automated Response Actions (col-span-4) */}
        <div className="xl:col-span-4 h-[250px]">
          <AutoResponse blockedIpsList={metrics.blocked_ips_list} />
        </div>

        {/* Incident Summary tiles (col-span-5) */}
        <div className="xl:col-span-5 h-[250px]">
          <IncidentSummary incidents={incidents} setActiveTab={setActiveTab} />
        </div>

        {/* Blocked IPs list (col-span-3) */}
        <div className="xl:col-span-3 h-[250px]">
          <BlockedIPs blockedIpsList={metrics.blocked_ips_list} />
        </div>
      </div>

    </div>
  );
}
