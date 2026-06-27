import React, { useState, useEffect } from 'react';
import { Server, Activity, Shield, Database as DbIcon } from 'lucide-react';

export default function SystemStatus() {
  const [status, setStatus] = useState({
    apache: false,
    iis: false,
    collector: false,
    detection: false,
    response: false,
    database: false
  });

  const checkHealth = async () => {
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      }
    } catch (err) {
      console.error("Health check request failed", err);
      // set all to false on network loss
      setStatus({
        apache: false,
        iis: false,
        collector: false,
        detection: false,
        response: false,
        database: false
      });
    }
  };

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 5000);
    return () => clearInterval(interval);
  }, []);

  const services = [
    { id: 'apache', label: 'Apache Server', icon: Server },
    { id: 'iis', label: 'IIS Server', icon: Server },
    { id: 'collector', label: 'Log Collector', icon: Activity },
    { id: 'detection', label: 'Detection Engine', icon: Shield },
    { id: 'response', label: 'Response Engine', icon: Shield },
    { id: 'database', label: 'Database', icon: DbIcon }
  ];

  return (
    <div className="space-y-3">
      <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-2 flex items-center">
        <Activity className="w-3.5 h-3.5 mr-1.5 text-slate-400" />
        System Status
      </h3>
      
      <div className="space-y-2 text-xs">
        {services.map((srv) => {
          const Icon = srv.icon;
          const isHealthy = status[srv.id];
          return (
            <div key={srv.id} className="flex items-center justify-between">
              <span className="text-slate-400 flex items-center">
                <Icon className="w-3.5 h-3.5 mr-2 text-slate-500" />
                {srv.label}
              </span>
              <span className="flex items-center space-x-1.5">
                <span className={`text-[10px] ${isHealthy ? 'text-emerald-500' : 'text-rose-500'}`}>
                  {isHealthy ? '• Running' : '• Offline'}
                </span>
                <span className={`w-2 h-2 rounded-full ${
                  isHealthy 
                    ? 'bg-emerald-500 shadow-[0_0_8px_#10b981]' 
                    : 'bg-rose-500 shadow-[0_0_8px_#ef4444]'
                }`} />
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
