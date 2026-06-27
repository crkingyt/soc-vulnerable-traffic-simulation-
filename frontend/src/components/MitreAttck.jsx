import React from 'react';
import { Target } from 'lucide-react';

export default function MitreAttck({ topTechniques }) {
  const getTechniqueDetails = (techId, attackType) => {
    // Map technique ID to the exact labels shown in the mock design
    const mapping = {
      'T1190': { name: 'Initial Access', tactic: 'Initial Access' },
      'T1110': { name: 'Brute Force', tactic: 'Credential Access' },
      'T1059': { name: 'Command and Scripting Interpreter', tactic: 'Execution' },
      'T1059.007': { name: 'Command and Scripting Interpreter', tactic: 'Execution' },
      'T1083': { name: 'Path Traversal', tactic: 'Discovery' },
      'T1595': { name: 'Active Scanning', tactic: 'Reconnaissance' }
    };

    return mapping[techId] || { name: attackType || 'Unclassified Tactic', tactic: 'Execution' };
  };

  // Color mappings for bullet indicators
  const getBulletColor = (techId) => {
    const colors = {
      'T1190': 'bg-red-500',
      'T1110': 'bg-orange-500',
      'T1059': 'bg-yellow-500',
      'T1059.007': 'bg-yellow-500',
      'T1083': 'bg-blue-500',
      'T1595': 'bg-emerald-500'
    };
    return colors[techId] || 'bg-slate-500';
  };

  return (
    <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col h-full space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center">
          <Target className="w-4 h-4 mr-2 text-red-500" />
          MITRE ATT&CK Top Techniques
        </h3>
        <span className="text-[10px] text-blue-400 cursor-pointer hover:underline">
          View All &rarr;
        </span>
      </div>

      <div className="overflow-x-auto flex-1">
        <table className="w-full text-left text-[10px]">
          <thead>
            <tr className="border-b border-slate-800 text-slate-500 font-semibold uppercase tracking-wider">
              <th className="pb-2">Technique</th>
              <th className="pb-2">ID</th>
              <th className="pb-2">Tactic</th>
              <th className="pb-2 text-right">Count</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-900 font-sans">
            {(!topTechniques || topTechniques.length === 0) ? (
              <tr>
                <td colSpan={4} className="text-center py-8 text-slate-600">
                  No attack vectors detected yet.
                </td>
              </tr>
            ) : (
              topTechniques.map((tech, idx) => {
                const details = getTechniqueDetails(tech.technique_id, tech.attack_type);
                return (
                  <tr key={idx} className="hover:bg-slate-900/30">
                    <td className="py-2.5 flex items-center space-x-2 text-slate-300 font-semibold">
                      <span className={`w-1.5 h-1.5 rounded-full ${getBulletColor(tech.technique_id)}`} />
                      <span>{details.name}</span>
                    </td>
                    <td className="py-2.5 font-mono text-slate-400">{tech.technique_id}</td>
                    <td className="py-2.5 text-slate-400">{details.tactic}</td>
                    <td className="py-2.5 text-right font-bold font-mono text-red-400">{tech.count}</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
