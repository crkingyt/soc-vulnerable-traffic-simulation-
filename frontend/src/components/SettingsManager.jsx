import React, { useState } from 'react';
import { Settings, Play, Square, Sliders, AlertOctagon, RefreshCw, Trash2, CheckCircle2, Loader } from 'lucide-react';

export default function SettingsManager({ metrics, onConfigChange, triggerRefresh }) {
  const [eps, setEps] = useState(metrics.current_eps || 10);
  const [vulnPercent, setVulnPercent] = useState(5.0);
  const [isRunning, setIsRunning] = useState(metrics.is_simulation_running || false);
  const [purging, setPurging] = useState(false);
  const [purgeSuccess, setPurgeSuccess] = useState(false);

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

  const handlePurge = async () => {
    if (!window.confirm("WARNING: This will completely purge all logs, alerts, incidents, and blocked IPs from the database. This action CANNOT be undone. Are you sure you want to reset the platform?")) {
      return;
    }
    setPurging(true);
    try {
      const res = await fetch('/api/settings/purge', {
        method: 'POST'
      });
      if (res.ok) {
        setPurgeSuccess(true);
        setTimeout(() => setPurgeSuccess(false), 4000);
        if (triggerRefresh) {
          triggerRefresh();
        }
      }
    } catch (e) {
      console.error("Purge query request failed", e);
    } finally {
      setPurging(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h2 className="text-lg font-bold text-slate-100 flex items-center">
          <Settings className="w-5 h-5 mr-2 text-slate-400" />
          SOC Platform Settings
        </h2>
        <p className="text-xs text-slate-500">Configure simulator event rates, attack thresholds, and database maintenance logs.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Simulator Panel card */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 space-y-4">
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-widest flex items-center">
            <Sliders className="w-4 h-4 mr-2 text-blue-500" />
            Attack Simulator Settings
          </h3>

          <form onSubmit={handleConfigSubmit} className="space-y-4 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 font-semibold">Simulator State:</span>
              <button
                type="button"
                onClick={toggleSimulation}
                className={`px-3 py-1.5 rounded-lg text-[10px] font-bold transition-all flex items-center space-x-1.5 text-white ${
                  isRunning ? 'bg-rose-600 hover:bg-rose-500 shadow-[0_0_8px_rgba(239,68,68,0.3)]' : 'bg-emerald-600 hover:bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.3)]'
                }`}
              >
                {isRunning ? (
                  <>
                    <Square className="w-3 h-3 fill-white" />
                    <span>Halt Simulation</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3 h-3 fill-white" />
                    <span>Run Simulation</span>
                  </>
                )}
              </button>
            </div>

            <div className="space-y-1 pt-1.5">
              <div className="flex justify-between text-slate-400 font-semibold">
                <span>Events Per Second (EPS):</span>
                <span className="text-blue-400 font-mono font-bold">{eps} / sec</span>
              </div>
              <input
                type="range"
                min="2"
                max="30"
                value={eps}
                onChange={(e) => setEps(parseInt(e.target.value))}
                className="w-full h-1 bg-slate-950 rounded-lg appearance-none cursor-pointer accent-blue-500"
              />
            </div>

            <div className="space-y-1 pt-1.5">
              <div className="flex justify-between text-slate-400 font-semibold">
                <span>Vulnerability Injection Ratio:</span>
                <span className="text-blue-400 font-mono font-bold">{vulnPercent}%</span>
              </div>
              <input
                type="range"
                min="2"
                max="30"
                step="0.5"
                value={vulnPercent}
                onChange={(e) => setVulnPercent(parseFloat(e.target.value))}
                className="w-full h-1 bg-slate-950 rounded-lg appearance-none cursor-pointer accent-blue-500"
              />
            </div>

            <button
              type="submit"
              className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-lg transition-colors text-center"
            >
              Apply Settings
            </button>
          </form>
        </div>

        {/* Database purge card */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <h3 className="text-xs font-bold text-rose-400 uppercase tracking-widest flex items-center">
              <AlertOctagon className="w-4 h-4 mr-2 text-rose-500" />
              Maintenance & Reset
            </h3>
            <p className="text-[11px] text-slate-500 leading-relaxed font-sans">
              Purges all databases to restart the simulation under clean scenarios. Deletes all escalated incidents, normal HTTP events, firewall rule blocks, and reports.
            </p>
          </div>

          <div className="space-y-3">
            {purgeSuccess && (
              <div className="p-3 bg-emerald-950/20 border border-emerald-900/40 text-emerald-400 rounded-xl text-[10px] flex items-center space-x-2 animate-fadeIn">
                <CheckCircle2 className="w-4 h-4" />
                <span>Database successfully reset to pristine status.</span>
              </div>
            )}

            <button
              type="button"
              onClick={handlePurge}
              disabled={purging}
              className="w-full py-2 bg-rose-600/10 hover:bg-rose-600 text-rose-500 hover:text-white font-bold rounded-lg transition-colors border border-rose-900/30 hover:border-rose-600 text-xs flex justify-center items-center space-x-1.5"
            >
              {purging ? (
                <Loader className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Trash2 className="w-3.5 h-3.5" />
              )}
              <span>Purge DB & Reset Platform</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
