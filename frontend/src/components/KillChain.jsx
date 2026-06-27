import React from 'react';
import { Eye, Hammer, Send, Zap, Wrench, Radio, Target, HelpCircle } from 'lucide-react';

const STAGES = [
  { id: 'Reconnaissance', label: 'Reconnaissance', icon: Eye },
  { id: 'Weaponization', label: 'Weaponization', icon: Hammer },
  { id: 'Delivery', label: 'Delivery', icon: Send },
  { id: 'Exploitation', label: 'Exploitation', icon: Zap },
  { id: 'Installation', label: 'Installation', icon: Wrench },
  { id: 'Command & Control', label: 'Command and Control', icon: Radio },
  { id: 'Actions on Objectives', label: 'Actions on Objectives', icon: Target }
];

export default function KillChain({ alerts }) {
  // Determine which stages have been triggered by checking alert history
  // Map standard stage name mappings if they differ
  const triggeredStages = new Set(
    alerts.map((a) => {
      if (a.kill_chain_stage === 'Command & Control') return 'Command and Control';
      return a.kill_chain_stage;
    })
  );

  return (
    <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col h-full space-y-4">
      <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
        Cyber Kill Chain
      </h3>

      <div className="flex items-center justify-between px-4 py-6 relative w-full overflow-x-auto min-w-[500px]">
        {/* Horizontal Connection Line */}
        <div className="absolute top-1/2 left-8 right-8 h-[2px] bg-slate-800 -translate-y-1/2 z-0" />

        {STAGES.map((stage, idx) => {
          const Icon = stage.icon;
          const isTriggered = triggeredStages.has(stage.label) || triggeredStages.has(stage.id);
          
          return (
            <div key={stage.id} className="flex flex-col items-center relative z-10 space-y-3.5">
              {/* Stage Circle Node */}
              <div 
                className={`w-10 h-10 rounded-full flex items-center justify-center transition-all duration-500 ${
                  isTriggered 
                    ? 'bg-emerald-500/10 border border-emerald-500 text-emerald-400 shadow-[0_0_12px_rgba(16,185,129,0.4)]' 
                    : 'bg-slate-950 border border-slate-800 text-slate-600'
                }`}
                title={stage.label}
              >
                <Icon className="w-4 h-4" />
              </div>

              {/* Title under node */}
              <span className={`text-[9px] text-center font-semibold leading-tight max-w-[80px] ${
                isTriggered ? 'text-emerald-400 font-bold' : 'text-slate-500'
              }`}>
                {stage.label}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
