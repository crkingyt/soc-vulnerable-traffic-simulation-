import React, { useState } from 'react';
import { Globe, Search, ShieldX, Skull, Loader } from 'lucide-react';

export default function ThreatIntelManager({ alerts }) {
  const [ipInput, setIpInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [intelResult, setIntelResult] = useState(null);

  // Extract unique attacker IPs from alert history
  const suspectIps = Array.from(new Set(alerts.map(a => a.source_ip))).slice(0, 8);

  const handleLookup = async (ip) => {
    if (!ip) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/intel/${ip}`);
      if (res.ok) {
        const data = await res.json();
        setIntelResult(data);
      }
    } catch (e) {
      console.error("Failed to query threat intelligence database", e);
    } finally {
      setLoading(false);
    }
  };

  const handleFormSubmit = (e) => {
    e.preventDefault();
    handleLookup(ipInput);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-slate-100 flex items-center">
          <Globe className="w-5 h-5 mr-2 text-blue-500" />
          Threat Intelligence Lookup
        </h2>
        <p className="text-xs text-slate-500">Query classification reputations and blacklists status for specific external IP addresses.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Grid: Lookup Bar & Result Panel */}
        <div className="lg:col-span-2 space-y-5">
          {/* Query Input Bar */}
          <div className="glass-panel p-5 rounded-2xl border border-slate-800/80">
            <form onSubmit={handleFormSubmit} className="flex space-x-3.5">
              <div className="relative flex-1">
                <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                <input
                  type="text"
                  placeholder="Enter IP Address (e.g. 192.168.1.10, 10.10.10.5)"
                  value={ipInput}
                  onChange={(e) => setIpInput(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-slate-950/60 border border-slate-800/80 focus:border-blue-500 rounded-xl text-xs text-slate-200 outline-none transition-colors"
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="px-5 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white text-xs font-bold rounded-xl transition-colors shrink-0 flex items-center space-x-1.5"
              >
                {loading && <Loader className="w-3.5 h-3.5 animate-spin" />}
                <span>Analyze Reputation</span>
              </button>
            </form>
          </div>

          {/* Results Panel */}
          {loading ? (
            <div className="glass-panel p-16 rounded-2xl border border-slate-800/80 flex flex-col justify-center items-center text-center space-y-3">
              <Loader className="w-8 h-8 text-blue-500 animate-spin" />
              <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider animate-pulse">Running Reputation Sandbox Scans...</p>
            </div>
          ) : intelResult ? (
            <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 animate-fadeIn space-y-4">
              <div className="flex justify-between items-start border-b border-slate-900 pb-3">
                <div>
                  <h3 className="text-sm font-bold text-slate-100 font-mono">{intelResult.ip}</h3>
                  <p className="text-[10px] text-slate-500 mt-0.5">Classification scan summary compiled successfully.</p>
                </div>
                <span className={`px-2.5 py-0.5 border text-[10px] font-bold rounded-full ${
                  intelResult.matched
                    ? 'bg-rose-500/10 text-rose-500 border-rose-500/20'
                    : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                }`}>
                  {intelResult.matched ? 'KNOWN MALICIOUS' : 'CLEAN / UNCLASSIFIED'}
                </span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-xs">
                {/* Risk Score */}
                <div className="bg-slate-950/40 border border-slate-900 rounded-xl p-3 flex flex-col justify-between">
                  <span className="text-[9px] text-slate-500 uppercase font-semibold">Reputation Risk</span>
                  <div className="flex items-baseline space-x-1 mt-1.5">
                    <span className={`text-xl font-bold font-mono ${intelResult.matched ? 'text-rose-500' : 'text-emerald-400'}`}>
                      {intelResult.matched ? 'HIGH' : 'LOW'}
                    </span>
                  </div>
                </div>

                {/* Country */}
                <div className="bg-slate-950/40 border border-slate-900 rounded-xl p-3 flex flex-col justify-between">
                  <span className="text-[9px] text-slate-500 uppercase font-semibold">Geo Classification</span>
                  <p className="text-xs font-bold text-slate-300 mt-1.5">{intelResult.country || 'Global Private IP'}</p>
                </div>

                {/* Classification Category */}
                <div className="bg-slate-950/40 border border-slate-900 rounded-xl p-3 flex flex-col justify-between col-span-2 md:col-span-1">
                  <span className="text-[9px] text-slate-500 uppercase font-semibold">Threat Domain</span>
                  <p className="text-xs font-bold text-slate-300 mt-1.5">{intelResult.classification || 'None / Not listed'}</p>
                </div>
              </div>

              {/* Blacklists matches */}
              {intelResult.matched && (
                <div className="p-3 bg-red-950/20 border border-red-900/30 rounded-xl text-[10px] space-y-1">
                  <h4 className="font-bold text-rose-400 flex items-center">
                    <ShieldX className="w-3.5 h-3.5 mr-1.5" />
                    Threat Intel Indicators Tripped:
                  </h4>
                  <ul className="list-disc pl-5 text-slate-400 space-y-0.5">
                    <li>IP listed inside active attack database feed.</li>
                    <li>Matches automated Web Request scanning pattern sets.</li>
                    <li>Threat classification: {intelResult.classification}.</li>
                  </ul>
                </div>
              )}
            </div>
          ) : (
            <div className="glass-panel p-16 rounded-2xl border border-slate-800/80 flex flex-col justify-center items-center text-slate-600 text-center space-y-2">
              <Globe className="w-8 h-8 text-slate-700" />
              <p className="text-xs font-medium">Awaiting network reputation query...</p>
            </div>
          )}
        </div>

        {/* Right Grid: Suspect IPs shortcuts */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 h-fit space-y-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center">
            <Skull className="w-4 h-4 mr-2 text-red-500" />
            Recent Attacking IPs
          </h3>

          {suspectIps.length === 0 ? (
            <p className="text-[10px] text-slate-600 font-semibold py-4 text-center">No alert history recorded.</p>
          ) : (
            <div className="space-y-2">
              {suspectIps.map((ip, idx) => (
                <button
                  key={idx}
                  onClick={() => {
                    setIpInput(ip);
                    handleLookup(ip);
                  }}
                  className="w-full flex items-center justify-between p-2 rounded-xl bg-slate-950/40 border border-slate-900 hover:border-slate-800 transition-colors text-left text-xs text-slate-300 font-mono"
                >
                  <span>{ip}</span>
                  <span className="text-[9px] text-blue-500 font-bold font-sans">Query &rarr;</span>
                </button>
              ))}
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
