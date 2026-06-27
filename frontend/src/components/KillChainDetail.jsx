import React, { useState } from 'react';
import { Activity, ShieldCheck, Compass, HelpCircle, AlertTriangle, HelpCircle as HelpIcon } from 'lucide-react';

const STAGES = [
  {
    id: 'Reconnaissance',
    label: 'Reconnaissance',
    tactic: 'Initial reconnaissance to select targets.',
    tech: 'T1595 - Active Scanning',
    recomm: 'Block scanning IPs, set rate-limits, and audit exposed endpoints.'
  },
  {
    id: 'Weaponization',
    label: 'Weaponization',
    tactic: 'Setup malicious payloads, backdoors, or tools.',
    tech: 'T1587 - Gather/Develop Exploits',
    recomm: 'Keep network signatures updated, use WAF inspection rules.'
  },
  {
    id: 'Delivery',
    label: 'Delivery',
    tactic: 'Transmit payloads or exploits to application path.',
    tech: 'T1190 - Exploit Public-Facing App',
    recomm: 'Apply patches for Apache HTTP server and IIS services.'
  },
  {
    id: 'Exploitation',
    label: 'Exploitation',
    tactic: 'Code trigger execution targeting vulnerability.',
    tech: 'T1203 - Exploit Client-Execution',
    recomm: 'Disable execute permissions on upload folders, monitor process spans.'
  },
  {
    id: 'Installation',
    label: 'Installation',
    tactic: 'Establish persistent backdoor footprint.',
    tech: 'T1543 - Create System Service',
    recomm: 'Audit auto-start scripts, verify critical binaries integrity.'
  },
  {
    id: 'Command & Control',
    label: 'Command and Control',
    tactic: 'Open remote communication control sockets.',
    tech: 'T1071 - Application Layer Protocols',
    recomm: 'Restrict outbound traffic to known domains, check DNS query telemetry.'
  },
  {
    id: 'Actions on Objectives',
    label: 'Actions on Objectives',
    tactic: 'Exfiltrate sensitive data files, dump DB, encrypt systems.',
    tech: 'T1083 - File System Discovery / Exfiltration',
    recomm: 'Enable file audit tracking, isolate core assets, deploy encrypt guards.'
  }
];

export default function KillChainDetail({ alerts, latestAlert }) {
  const [activeStage, setActiveStage] = useState(null);

  // 1. Determine triggered stages
  const triggeredStages = new Set(
    alerts.map((a) => {
      if (a.kill_chain_stage === 'Command & Control') return 'Command and Control';
      return a.kill_chain_stage;
    })
  );

  // 2. Determine predictions
  const predictions = latestAlert?.predictions || [];
  const predictionMap = {};
  predictions.forEach(p => {
    const stageKey = p.predicted_stage === 'Command & Control' ? 'Command and Control' : p.predicted_stage;
    predictionMap[stageKey] = p.confidence;
  });

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-slate-100 flex items-center">
          <Activity className="w-5 h-5 mr-2 text-sky-400" />
          Cyber Kill Chain flow diagram
        </h2>
        <p className="text-xs text-slate-500">Live monitoring of adversary steps from initial scan to objectives execution.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Side: Vertical Stage Flow */}
        <div className="lg:col-span-2 space-y-4">
          {STAGES.map((stage, idx) => {
            const mappedLabel = stage.id === 'Command & Control' ? 'Command and Control' : stage.label;
            const isTriggered = triggeredStages.has(mappedLabel) || triggeredStages.has(stage.id);
            const predictionConf = predictionMap[mappedLabel];

            return (
              <div
                key={stage.id}
                onClick={() => setActiveStage(stage)}
                className={`p-4 rounded-xl border cursor-pointer transition-all duration-300 relative ${
                  activeStage?.id === stage.id ? 'ring-2 ring-blue-500/50' : ''
                } ${
                  isTriggered
                    ? 'bg-emerald-500/5 border-emerald-500/30 text-emerald-400 shadow-[0_0_12px_rgba(16,185,129,0.15)]'
                    : predictionConf
                      ? 'bg-blue-500/5 border-blue-500/30 text-blue-400 border-dashed'
                      : 'bg-slate-900/40 border-slate-800 text-slate-400'
                }`}
              >
                {/* Visual connectors */}
                {idx < STAGES.length - 1 && (
                  <div className="absolute top-[48px] left-[27px] w-[2px] h-[34px] bg-slate-800 -z-10" />
                )}

                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3.5">
                    {/* Circle counter */}
                    <span className={`w-7 h-7 rounded-full flex items-center justify-center font-bold text-xs ${
                      isTriggered
                        ? 'bg-emerald-500 text-slate-950 glow-green'
                        : predictionConf
                          ? 'bg-blue-500 text-slate-950 animate-pulse'
                          : 'bg-slate-950 text-slate-600 border border-slate-800'
                    }`}>
                      {idx + 1}
                    </span>
                    <div>
                      <h4 className="text-xs font-bold uppercase tracking-wider">{stage.label}</h4>
                      <p className="text-[10px] text-slate-500 font-medium mt-0.5">{stage.tech}</p>
                    </div>
                  </div>

                  {/* Status labels */}
                  <div className="flex items-center space-x-2 font-mono text-[9px]">
                    {isTriggered ? (
                      <span className="px-2 py-0.5 bg-emerald-950/40 text-emerald-500 font-bold border border-emerald-900/40 rounded">
                        TRIGGERED
                      </span>
                    ) : predictionConf ? (
                      <span className="px-2 py-0.5 bg-blue-950/40 text-blue-400 font-bold border border-blue-900/40 rounded animate-pulse">
                        FORECASTED ({predictionConf}%)
                      </span>
                    ) : (
                      <span className="text-slate-600">DORMANT</span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right Side: Investigation Details Drawer */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 h-fit space-y-5">
          {activeStage ? (
            <div className="space-y-4 text-xs animate-fadeIn">
              <div>
                <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest block mb-1">Active Selection</span>
                <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wide">{activeStage.label}</h3>
              </div>

              <div className="space-y-3 pt-2">
                <div className="space-y-1">
                  <span className="text-[9px] text-slate-500 font-semibold uppercase">Tactical Objective</span>
                  <p className="text-slate-400 font-sans leading-relaxed">{activeStage.tactic}</p>
                </div>

                <div className="space-y-1 pt-1.5">
                  <span className="text-[9px] text-slate-500 font-semibold uppercase">Associated Techniques</span>
                  <p className="text-slate-300 font-mono text-[10px] bg-slate-950/60 p-2 border border-slate-900 rounded">{activeStage.tech}</p>
                </div>

                <div className="space-y-1 pt-1.5 border-t border-slate-900">
                  <span className="text-[9px] text-orange-500 font-bold uppercase flex items-center">
                    <ShieldCheck className="w-3.5 h-3.5 mr-1" />
                    Response Remediation Playbook
                  </span>
                  <p className="text-slate-400 font-sans leading-relaxed text-[11px] mt-1">{activeStage.recomm}</p>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex flex-col justify-center items-center text-center p-10 text-slate-600 space-y-2">
              <HelpIcon className="w-8 h-8 text-slate-700" />
              <p className="text-xs">Click any Cyber Kill Chain stage on the left to load operational details and mitigations playbook.</p>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
