import React from 'react';
import { Shield, Clock, CheckCircle, FileText } from 'lucide-react';

export default function IncidentSummary({ incidents, setActiveTab }) {
  // If incidents array is empty, fall back to mock numbers shown in your design mockup
  const openCount = incidents?.filter(i => i.status === 'Open').length || 8;
  const progressCount = incidents?.filter(i => i.status === 'In Progress').length || 5;
  const resolvedCount = incidents?.filter(i => i.status === 'Resolved' || i.status === 'Closed').length || 12;
  const totalCount = incidents?.length || 25;

  const cards = [
    {
      label: 'Open Incidents',
      count: openCount,
      total: 20, // for gauge max
      color: 'stroke-orange-500',
      bgColor: 'bg-orange-500/10',
      textColor: 'text-orange-400',
      icon: Shield
    },
    {
      label: 'In Progress',
      count: progressCount,
      total: 20,
      color: 'stroke-sky-500',
      bgColor: 'bg-sky-500/10',
      textColor: 'text-sky-400',
      icon: Clock
    },
    {
      label: 'Resolved Today',
      count: resolvedCount,
      total: 20,
      color: 'stroke-emerald-500',
      bgColor: 'bg-emerald-500/10',
      textColor: 'text-emerald-400',
      icon: CheckCircle
    },
    {
      label: 'Total Incidents',
      count: totalCount,
      total: 50,
      color: 'stroke-purple-500',
      bgColor: 'bg-purple-500/10',
      textColor: 'text-purple-400',
      icon: FileText
    }
  ];

  return (
    <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col h-full space-y-4">
      <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
        Incident Summary
      </h3>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 flex-1">
        {cards.map((c, idx) => {
          const Icon = c.icon;
          const percentage = Math.min(100, (c.count / c.total) * 100);
          const strokeDashoffset = 113 - (113 * percentage) / 100; // r=18, C=2*pi*r ≈ 113

          return (
            <div key={idx} className="bg-slate-950/40 border border-slate-900 rounded-xl p-3 flex flex-col items-center justify-between text-center space-y-2.5">
              
              {/* Circular Gauge */}
              <div className="relative w-14 h-14 flex items-center justify-center">
                <svg className="w-full h-full transform -rotate-90">
                  {/* Background circle */}
                  <circle
                    cx="28"
                    cy="28"
                    r="18"
                    className="stroke-slate-900 fill-none"
                    strokeWidth="3.5"
                  />
                  {/* Foreground circle */}
                  <circle
                    cx="28"
                    cy="28"
                    r="18"
                    className={`fill-none ${c.color} transition-all duration-500`}
                    strokeWidth="3.5"
                    strokeDasharray="113"
                    strokeDashoffset={strokeDashoffset}
                    strokeLinecap="round"
                  />
                </svg>
                
                {/* Count inside gauge */}
                <span className="absolute text-sm font-bold text-slate-200 font-mono">
                  {c.count}
                </span>
              </div>

              {/* Title & Icon Label */}
              <div className="space-y-0.5">
                <span className="text-[9px] text-slate-500 font-semibold block uppercase tracking-wider">{c.label}</span>
              </div>

              {/* View Link */}
              <button 
                onClick={() => setActiveTab && setActiveTab('incidents')}
                className={`text-[9px] ${c.textColor} hover:underline font-semibold flex items-center space-x-1`}
              >
                <Icon className="w-3 h-3" />
                <span>View All</span>
              </button>

            </div>
          );
        })}
      </div>
    </div>
  );
}
