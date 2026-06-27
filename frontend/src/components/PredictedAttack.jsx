import React from 'react';
import { Compass } from 'lucide-react';

export default function PredictedAttack({ latestAlert }) {
  // Extract predictions from the latest alert or fallback to default
  const predictions = latestAlert?.predictions || [];
  
  // Default values if no active alert/predictions are present
  const predictedStage = predictions[0]?.predicted_stage || 'Credential Access';
  const predictedTech = predictions[0]?.predicted_technique || 'T1110';
  const confidence = predictions[0]?.confidence || 87;

  // Human-readable technique label mappings
  const techNames = {
    'T1110': 'Brute Force',
    'T1190': 'Exploit Public-Facing App',
    'T1059': 'Command Interpreter',
    'T1059.007': 'JavaScript Interpreter',
    'T1083': 'File/Directory Discovery',
    'T1595': 'Active Scanning'
  };
  const techName = techNames[predictedTech] || 'Malicious Execution';

  return (
    <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col h-full space-y-4">
      <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
        Predicted Next Attack
      </h3>

      <div className="flex items-center space-x-6 flex-1 py-1">
        {/* Animated Target / Radar Scan */}
        <div className="relative w-16 h-16 rounded-full border border-sky-500/20 flex items-center justify-center shrink-0">
          {/* Rotating scan line */}
          <div className="absolute inset-0 rounded-full border border-dashed border-sky-500/40 animate-spin" style={{ animationDuration: '6s' }} />
          {/* Concentric rings */}
          <div className="absolute w-10 h-10 rounded-full border border-sky-500/30" />
          <div className="absolute w-4 h-4 rounded-full bg-sky-500/10 animate-ping" />
          
          <Compass className="w-5 h-5 text-sky-400" />
        </div>

        {/* Text descriptions */}
        <div className="flex-1 space-y-2.5 min-w-0">
          <div>
            <h4 className="text-sm font-bold text-slate-100 truncate">{predictedStage}</h4>
            <p className="text-[10px] text-slate-500 mt-0.5">({predictedTech} - {techName})</p>
          </div>

          <div className="space-y-1">
            <div className="flex justify-between items-center text-[10px] font-mono">
              <span className="text-slate-500">Confidence Score</span>
              <span className="text-emerald-400 font-bold">{confidence}%</span>
            </div>
            <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden">
              <div 
                className="h-full bg-emerald-500 shadow-[0_0_8px_#10b981] transition-all duration-500" 
                style={{ width: `${confidence}%` }} 
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
