import React, { useState } from 'react';
import { Eye, Hammer, Send, Zap, Wrench, Radio, Target, HelpCircle } from 'lucide-react';

const STAGES = [
  { id: 'Reconnaissance', label: 'Reconnaissance', icon: Eye, tech: 'T1595', desc: 'Active scanning to gather targets' },
  { id: 'Weaponization', label: 'Weaponization', icon: Hammer, tech: 'T1587', desc: 'Crafting malicious payload tools' },
  { id: 'Delivery', label: 'Delivery', icon: Send, tech: 'T1190', desc: 'Transmitting payload to the application' },
  { id: 'Exploitation', label: 'Exploitation', icon: Zap, tech: 'T1203', desc: 'Triggering exploit code execution' },
  { id: 'Installation', label: 'Installation', icon: Wrench, tech: 'T1543', desc: 'Establishing persistent footprint' },
  { id: 'Command & Control', label: 'Command & Control', icon: Radio, tech: 'T1071', desc: 'Opening outbound control channel' },
  { id: 'Actions on Objectives', label: 'Actions on Objectives', icon: Target, tech: 'T1083', desc: 'Data theft, encryption, discovery' }
];

export default function MitreKillChain({ alerts, latestAlert }) {
  const [selectedStage, setSelectedStage] = useState(null);

  // 1. Determine which stages have been triggered by checking alert history
  const triggeredStages = new Set(alerts.map(a => a.kill_chain_stage));

  // 2. Extract predictions from latest alert
  const predictions = latestAlert?.predictions || [];
  const predictionMap = {};
  predictions.forEach(p => {
    predictionMap[p.predicted_stage] = p.confidence;
  });

  return (
    <div className="glass-panel p-5 rounded-2xl border border-slate-800/80">
      <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-widest mb-6 flex items-center">
        <ActivityIcon className="w-4 h-4 mr-2 text-blue-500" />
        MITRE ATT&CK Cyber Kill Chain
      </h3>

      {/* Horizontal Chain Flow */}
      <div className="grid grid-cols-7 gap-3 mb-6 relative">
        {STAGES.map((stage, idx) => {
          const Icon = stage.icon;
          const isTriggered = triggeredStages.has(stage.id);
          const predictionConf = predictionMap[stage.id];
          
          return (
            <div 
              key={stage.id} 
              onClick={() => setSelectedStage(stage)}
              className="flex flex-col items-center group cursor-pointer"
            >
              {/* Node Circle */}
              <div className={`w-12 h-12 rounded-full flex items-center justify-center transition-all duration-500 relative z-10 ${
                isTriggered 
                  ? 'bg-emerald-500/25 border-2 border-emerald-500 text-emerald-400 glow-green' 
                  : predictionConf 
                    ? 'bg-blue-500/10 border border-dashed border-blue-500/50 text-blue-400' 
                    : 'bg-slate-900 border border-slate-800 text-slate-500 group-hover:border-slate-700'
              }`}>
                <Icon className="w-5 h-5" />
                
                {/* Connection line helper */}
                {idx < 6 && (
                  <div className="absolute top-1/2 left-full w-full h-[1px] bg-slate-800 -z-10 group-hover:bg-slate-700 transition-colors" style={{ width: 'calc(100% + 12px)' }} />
                )}
              </div>

              {/* Node Title */}
              <span className="text-[10px] text-center font-medium mt-3 text-slate-400 truncate max-w-full group-hover:text-slate-200">
                {stage.label}
              </span>

              {/* Node Prediction Bar */}
              <div className="w-full mt-2 h-1 bg-slate-950 rounded-full overflow-hidden">
                {predictionConf ? (
                  <div 
                    className="h-full bg-blue-500 shadow-[0_0_8px_#3b82f6]" 
                    style={{ width: `${predictionConf}%` }} 
                  />
                ) : isTriggered ? (
                  <div className="h-full bg-emerald-500" style={{ width: '100%' }} />
                ) : (
                  <div className="h-full bg-transparent" />
                )}
              </div>
              
              {/* Prediction Probability tooltip text */}
              {predictionConf && (
                <span className="text-[9px] text-blue-400 mt-1 font-mono">{predictionConf}% Prob</span>
              )}
            </div>
          );
        })}
      </div>

      {/* Selected Stage Detail Panel */}
      {selectedStage ? (
        <div className="bg-slate-950/40 p-4 rounded-xl border border-slate-900 text-xs transition-all duration-300">
          <div className="flex justify-between items-center mb-2">
            <h4 className="font-semibold text-slate-200 text-sm flex items-center">
              <span className={`w-2.5 h-2.5 rounded-full mr-2 ${triggeredStages.has(selectedStage.id) ? 'bg-emerald-500' : 'bg-slate-600'}`} />
              {selectedStage.label}
            </h4>
            <span className="text-slate-500 font-mono text-[10px]">Mapping Technique: {selectedStage.tech}</span>
          </div>
          <p className="text-slate-400 mb-3">{selectedStage.desc}</p>
          
          {/* Custom Mitigation Tip */}
          <div className="bg-slate-900/50 p-2.5 rounded-lg border border-slate-800/80">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block mb-1">CKC Mitigation Recommendation</span>
            <span className="text-slate-300">
              {selectedStage.id === 'Reconnaissance' && 'Block scanning IP ranges, apply ingress rate limiting.'}
              {selectedStage.id === 'Weaponization' && 'Inspect content filters and enforce email gateway protections.'}
              {selectedStage.id === 'Delivery' && 'Deploy active WAF signatures and restrict file uploads.'}
              {selectedStage.id === 'Exploitation' && 'Apply compiler options, input parameter bounds, sanitization.'}
              {selectedStage.id === 'Installation' && 'Enforce application whitelisting and monitor system service startups.'}
              {selectedStage.id === 'Command & Control' && 'Monitor dns request anomalies and detect beaconing frequencies.'}
              {selectedStage.id === 'Actions on Objectives' && 'Audit file discovery requests and restrict exfiltration volumes.'}
            </span>
          </div>
        </div>
      ) : (
        <div className="flex items-center text-slate-500 justify-center h-16 bg-slate-950/20 border border-slate-900 border-dashed rounded-xl text-xs">
          <HelpCircle className="w-4 h-4 mr-2" />
          Click on a kill chain node to view description and mitigation recommendations.
        </div>
      )}
    </div>
  );
}

// ActivityIcon helper
function ActivityIcon(props) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
    </svg>
  );
}
