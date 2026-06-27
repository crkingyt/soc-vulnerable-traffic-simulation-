import React from 'react';
import { 
  Shield, 
  LayoutDashboard, 
  AlertOctagon, 
  Compass, 
  Target, 
  Activity, 
  Globe, 
  FolderSearch, 
  UploadCloud, 
  UserMinus, 
  FileDown, 
  Settings
} from 'lucide-react';
import SystemStatus from './SystemStatus';

export default function Sidebar({ activeTab, setActiveTab, alertsCount = 127, incidentsCount = 8 }) {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'alerts', label: 'Alerts', icon: AlertOctagon, badge: alertsCount, badgeColor: 'bg-red-600' },
    { id: 'incidents', label: 'Incidents', icon: Compass, badge: incidentsCount, badgeColor: 'bg-orange-500' },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: Target },
    { id: 'killchain', label: 'Kill Chain', icon: Activity },
    { id: 'threatintel', label: 'Threat Intelligence', icon: Globe },
    { id: 'hunting', label: 'Log Explorer', icon: FolderSearch },
    { id: 'offline', label: 'Upload Logs', icon: UploadCloud },
    { id: 'blockedips', label: 'Blocked IPs', icon: UserMinus },
    { id: 'reports', label: 'Reports', icon: FileDown },
    { id: 'settings', label: 'Settings', icon: Settings }
  ];

  return (
    <div className="w-64 h-screen bg-[#0b111e]/90 border-r border-slate-800 flex flex-col justify-between p-4 glass-panel sticky top-0 shrink-0">
      <div>
        {/* Brand Logo */}
        <div className="flex items-center space-x-3 mb-6 px-2">
          <Shield className="w-8 h-8 text-blue-500 fill-blue-500/20 shrink-0" />
          <div>
            <h1 className="font-bold text-sm leading-tight tracking-wider text-slate-100 uppercase">SOC Platform</h1>
            <p className="text-[9px] text-slate-500 uppercase tracking-widest font-semibold">Security Operations Center</p>
          </div>
        </div>

        {/* Sidebar Menu Links */}
        <nav className="space-y-0.5">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
                  isActive 
                    ? 'bg-blue-600/10 text-blue-400 border-l-2 border-blue-500 font-bold' 
                    : 'text-slate-400 hover:bg-slate-800/40 hover:text-slate-200'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Icon className="w-4 h-4" />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && item.badge > 0 && (
                  <span className={`px-1.5 py-0.5 rounded-full text-[9px] text-white font-bold font-mono ${item.badgeColor}`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* System Status Indicators & Version Footnote */}
      <div className="border-t border-slate-800/60 pt-4 px-2 space-y-4">
        <SystemStatus />
        <div className="text-[10px] text-slate-600 text-center font-semibold">Version 1.0.0</div>
      </div>
    </div>
  );
}
