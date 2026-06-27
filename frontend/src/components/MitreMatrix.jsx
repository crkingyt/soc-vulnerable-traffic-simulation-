import React, { useState } from 'react';
import { Target, ShieldAlert, Award } from 'lucide-react';

const TACTICS = [
  {
    name: 'Reconnaissance',
    id: 'TA0043',
    techniques: [
      { id: 'T1595', name: 'Active Scanning', desc: 'Scanning public-facing services for vulnerabilities.' },
      { id: 'T1592', name: 'Gather Host Info', desc: 'Collecting host IP addresses and hostnames.' }
    ]
  },
  {
    name: 'Initial Access',
    id: 'TA0001',
    techniques: [
      { id: 'T1190', name: 'Exploit Public App', desc: 'Exploiting software vulnerabilities in Apache/IIS.' },
      { id: 'T1133', name: 'External Services', desc: 'Accessing via VPN or remote access gateways.' }
    ]
  },
  {
    name: 'Execution',
    id: 'TA0002',
    techniques: [
      { id: 'T1059', name: 'Command Interpreter', desc: 'Executing system command strings via web shells.' },
      { id: 'T1204', name: 'User Execution', desc: 'Tricking the user into running malicious payloads.' }
    ]
  },
  {
    name: 'Persistence',
    id: 'TA0003',
    techniques: [
      { id: 'T1543', name: 'System Process Mods', desc: 'Creating or modifying persistent service configs.' },
      { id: 'T1547', name: 'Boot Autostart', desc: 'Setting boot or logon autostart entry scripts.' }
    ]
  },
  {
    name: 'Credential Access',
    id: 'TA0006',
    techniques: [
      { id: 'T1110', name: 'Brute Force', desc: 'Password spraying or guessing web forms.' },
      { id: 'T1003', name: 'OS Credential Dumping', desc: 'Reading passwords from process memory.' }
    ]
  },
  {
    name: 'Discovery',
    id: 'TA0007',
    techniques: [
      { id: 'T1083', name: 'File Discovery', desc: 'Searching local directory paths for sensitive files.' },
      { id: 'T1082', name: 'System Info Discovery', desc: 'Gathering OS versions, patch counts, and hardware.' }
    ]
  },
  {
    name: 'Command & Control',
    id: 'TA0011',
    techniques: [
      { id: 'T1071', name: 'App Layer Protocol', desc: 'Using HTTP/HTTPS to communicate with external command servers.' },
      { id: 'T1090', name: 'Proxy Redirection', desc: 'Routing packets through intermediate networks.' }
    ]
  }
];

export default function MitreMatrix({ alerts }) {
  const [selectedTech, setSelectedTech] = useState(null);

  // Map of technique_id -> count of alerts
  const techniqueCounts = {};
  alerts.forEach(al => {
    const id = al.mitre_id;
    if (id) {
      techniqueCounts[id] = (techniqueCounts[id] || 0) + 1;
    }
  });

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center mb-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center">
            <Target className="w-5 h-5 mr-2 text-red-500" />
            MITRE ATT&CK Matrix
          </h2>
          <p className="text-xs text-slate-500">Interactive matrix detailing tactical mappings of observed simulator threat events.</p>
        </div>
      </div>

      {/* Columns Grid Layout */}
      <div className="grid grid-cols-1 md:grid-cols-7 gap-3.5">
        {TACTICS.map((tactic) => (
          <div key={tactic.id} className="flex flex-col space-y-2.5">
            {/* Tactic Title Block */}
            <div className="bg-[#0b111e] border border-slate-800 p-2.5 rounded-xl text-center">
              <h3 className="text-[10px] font-bold text-slate-300 uppercase tracking-widest leading-normal">{tactic.name}</h3>
              <span className="text-[9px] text-slate-600 font-semibold font-mono">{tactic.id}</span>
            </div>

            {/* Techniques Stack */}
            <div className="space-y-2 flex-1">
              {tactic.techniques.map((tech) => {
                const triggerCount = techniqueCounts[tech.id] || 0;
                const isTriggered = triggerCount > 0;

                return (
                  <div
                    key={tech.id}
                    onClick={() => setSelectedTech({ ...tech, count: triggerCount })}
                    className={`p-3 rounded-xl border text-left cursor-pointer transition-all duration-300 ${
                      isTriggered
                        ? 'bg-emerald-500/10 border-emerald-500/40 hover:border-emerald-500 text-emerald-300 glow-green'
                        : 'bg-slate-900/40 border-slate-800/80 hover:border-slate-700 text-slate-400'
                    }`}
                  >
                    <div className="flex justify-between items-start space-x-1.5 mb-1.5">
                      <span className="text-[10px] font-bold font-mono text-slate-500">{tech.id}</span>
                      {isTriggered && (
                        <span className="px-1.5 py-0.5 bg-emerald-500 text-slate-950 font-bold font-mono text-[8px] rounded-full">
                          {triggerCount}
                        </span>
                      )}
                    </div>
                    <p className="text-[10px] font-semibold leading-tight">{tech.name}</p>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Selected Tech Detail Drawer */}
      {selectedTech && (
        <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 animate-fadeIn">
          <div className="flex justify-between items-start mb-3">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                <ShieldAlert className={`w-4.5 h-4.5 ${selectedTech.count > 0 ? 'text-emerald-400' : 'text-slate-500'}`} />
                <span>{selectedTech.name} ({selectedTech.id})</span>
              </h3>
              <p className="text-[10px] text-slate-500 mt-0.5 font-semibold">ATT&CK Technique Specification & Real-Time Aggregates</p>
            </div>
            <button
              onClick={() => setSelectedTech(null)}
              className="text-xs text-slate-500 hover:text-slate-300 font-bold"
            >
              Close Details
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 text-xs mt-4">
            <div className="md:col-span-3 space-y-2">
              <h4 className="font-semibold text-slate-400 uppercase tracking-wider text-[9px]">Description</h4>
              <p className="text-slate-300 leading-relaxed font-sans text-[11px]">{selectedTech.desc}</p>
            </div>

            <div className="bg-slate-950/40 border border-slate-900 rounded-xl p-4 flex flex-col justify-center items-center text-center space-y-2">
              <Award className="w-8 h-8 text-blue-500" />
              <div>
                <h4 className="font-semibold text-slate-500 text-[9px] uppercase">Active Alerts</h4>
                <p className="text-xl font-bold font-mono text-slate-100">{selectedTech.count}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
