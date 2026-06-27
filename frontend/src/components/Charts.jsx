import React from 'react';
import { 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  Legend, 
  AreaChart, 
  Area 
} from 'recharts';

export default function Charts({ metrics, epsHistory }) {
  // 1. Attack distribution data
  const attackData = Object.entries(metrics.attack_distribution || {}).map(([key, val]) => ({
    name: key,
    value: val
  }));

  const COLORS = ['#ef4444', '#f97316', '#3b82f6', '#10b981', '#a855f7', '#6366f1'];

  // 2. Severity distribution data
  const severityData = Object.entries(metrics.severity_distribution || {}).map(([key, val]) => ({
    name: key,
    count: val
  }));

  const SEV_COLORS = {
    'Critical': '#ef4444',
    'High': '#f97316',
    'Medium': '#eab308',
    'Low': '#10b981'
  };

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-[#0b111e] border border-slate-800 p-2.5 rounded-lg text-xs font-mono">
          <p className="text-slate-300">{`${payload[0].name}: ${payload[0].value}`}</p>
        </div>
      );
    }
    return null;
  };

  const totalAttacks = attackData.reduce((acc, curr) => acc + curr.value, 0);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
      {/* 1. Attack Type Donut Chart */}
      <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col justify-between h-72">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
          Attack Distribution
        </h3>
        <div className="h-44 relative">
          {attackData.length === 0 ? (
            <div className="absolute inset-0 flex items-center justify-center text-xs text-slate-500">
              No attack logs recorded
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={attackData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={75}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {attackData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          )}
          {/* Centered sum indicator */}
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="text-xl font-bold text-slate-200 font-mono">
              {totalAttacks}
            </span>
            <span className="text-[9px] text-slate-500 uppercase tracking-wider font-semibold">Total</span>
          </div>
        </div>
        
        {/* Horizontal Legend */}
        <div className="flex flex-wrap gap-x-2.5 gap-y-1 justify-center text-[9px] text-slate-500 font-semibold truncate max-h-[40px] overflow-y-auto">
          {attackData.map((item, idx) => (
            <span key={item.name} className="flex items-center">
              <span className="w-1.5 h-1.5 rounded-full mr-1 shrink-0" style={{ backgroundColor: COLORS[idx % COLORS.length] }} />
              {item.name} ({Math.round(totalAttacks > 0 ? (item.value / totalAttacks) * 100 : 0)}%)
            </span>
          ))}
        </div>
      </div>

      {/* 2. Severity distribution Bar Chart */}
      <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col justify-between h-72">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
          Severity Distribution
        </h3>
        <div className="h-48 flex-1 mt-4">
          {severityData.length === 0 ? (
            <div className="h-full flex items-center justify-center text-xs text-slate-500">
              No severity records active
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} margin={{ top: 10, right: 0, left: -25, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#475569" fontSize={9} tickLine={false} />
                <YAxis stroke="#475569" fontSize={9} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]} barSize={24}>
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={SEV_COLORS[entry.name] || '#64748b'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* 3. Events Over Time Area Chart */}
      <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col justify-between h-72">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
            Events Over Time (Real-Time)
          </h3>
          <select className="bg-slate-900 border border-slate-800 text-[10px] text-slate-400 rounded px-1.5 py-0.5 outline-none">
            <option>Last 24 Hours</option>
            <option>Last 1 Hour</option>
          </select>
        </div>
        
        <div className="h-48 flex-1 mt-4">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={epsHistory} margin={{ top: 10, right: 5, left: -25, bottom: 0 }}>
              <defs>
                <linearGradient id="epsGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2}/>
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <XAxis stroke="#475569" fontSize={8} tickLine={false} />
              <YAxis stroke="#475569" fontSize={8} tickLine={false} domain={[0, 'dataMax + 2']} />
              <Tooltip 
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    return (
                      <div className="bg-[#0b111e] border border-slate-800 p-2.5 rounded-lg text-xs font-mono">
                        <p className="text-slate-300">{`EPS: ${payload[0].value.toFixed(1)}/sec`}</p>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Area 
                type="monotone" 
                dataKey="eps" 
                stroke="#3b82f6" 
                fillOpacity={1}
                fill="url(#epsGrad)"
                strokeWidth={2}
                activeDot={{ r: 4 }}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
