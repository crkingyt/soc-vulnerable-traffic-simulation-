import React, { useState, useEffect, useRef } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import ThreatHunting from './components/ThreatHunting';
import IncidentManager from './components/IncidentManager';
import ReportDownload from './components/ReportDownload';
import LogUpload from './components/LogUpload';
import AlertFeed from './components/AlertFeed';
import MitreMatrix from './components/MitreMatrix';
import KillChainDetail from './components/KillChainDetail';
import ThreatIntelManager from './components/ThreatIntelManager';
import BlockedIpsManager from './components/BlockedIpsManager';
import SettingsManager from './components/SettingsManager';
import { Radio, ShieldCheck } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [alerts, setAlerts] = useState([]);
  const [latestAlert, setLatestAlert] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [epsHistory, setEpsHistory] = useState([]);
  const [logs, setLogs] = useState([]);
  
  const [metrics, setMetrics] = useState({
    total_events: 0,
    current_eps: 0,
    alerts_count: 0,
    severity_distribution: { Critical: 0, High: 0, Medium: 0, Low: 0 },
    true_positives: 0,
    false_positives: 0,
    blocked_ips: 0,
    attack_distribution: {},
    top_attacking_ips: [],
    is_simulation_running: false,
    simulator_eps: 10,
    vulnerable_percent: 5.0
  });



  const wsRef = useRef(null);

  // 1. Fetch REST Metrics
  const fetchMetrics = async () => {
    try {
      const res = await fetch('/api/metrics');
      if (res.ok) {
        const data = await res.json();
        setMetrics(data);
        


        setEpsHistory(prev => {
          const newPoint = { 
            time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }), 
            eps: data.current_eps || 0 
          };
          const nextHistory = [...prev, newPoint];
          if (nextHistory.length > 20) {
            nextHistory.shift();
          }
          return nextHistory;
        });
      } else {
        // Handle database status error
      }
    } catch (e) {
      console.error("Failed to query API metrics", e);
    }
  };

  // 2. Fetch Incident lists
  const fetchIncidents = async () => {
    try {
      const res = await fetch('/api/incidents');
      if (res.ok) {
        const data = await res.json();
        setIncidents(data);
      }
    } catch (e) {
      console.error("Failed to query active incidents list", e);
    }
  };

  // Fetch initial alerts
  const fetchAlerts = async () => {
    try {
      const res = await fetch('/api/alerts?limit=50');
      if (res.ok) {
        const data = await res.json();
        setAlerts(data.results || []);
        if (data.results && data.results.length > 0) {
          setLatestAlert(data.results[0]);
        }
      }
    } catch (e) {
      console.error("Failed to query alerts history", e);
    }
  };

  // Fetch initial recent logs
  const fetchRecentLogs = async () => {
    try {
      const res = await fetch('/api/hunt?limit=20');
      if (res.ok) {
        const data = await res.json();
        setLogs(data.results || []);
      }
    } catch (e) {
      console.error("Failed to query recent logs history", e);
    }
  };

  // 3. Connect WebSockets Stream
  const connectWebSocket = () => {
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Use relative path routing, which is mapped via Vite configuration server.proxy
    const wsUrl = `${wsProto}//${window.location.host}/ws/stream`;
    
    console.log(`[WS] Attempting stream connection to ${wsUrl}`);
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        const { event_type, data } = payload;
        
        if (event_type === 'alert') {
          setAlerts(prev => {
            // Check for duplicates
            if (prev.some(a => a.id === data.id)) return prev;
            const updated = [data, ...prev];
            if (updated.length > 50) updated.pop();
            return updated;
          });
          setLatestAlert(data);
          
          // Re-fetch metrics to update counters immediately on alert trigger
          fetchMetrics();
        } else if (event_type === 'alert_update') {
          setAlerts(prev => prev.map(a => {
            if (a.id === data.id) {
              return { ...a, status: data.status, auto_blocked: data.blocked || a.auto_blocked };
            }
            return a;
          }));
          fetchMetrics();
        } else if (event_type === 'log') {
          // Increment total events count locally for fast responsiveness
          setMetrics(prev => ({
            ...prev,
            total_events: prev.total_events + 1
          }));
          setLogs(prev => {
            const updated = [data, ...prev];
            if (updated.length > 20) {
              updated.pop();
            }
            return updated;
          });
        }
      } catch (e) {
        console.error("[WS] Error parsing websocket event payload", e);
      }
    };

    ws.onclose = () => {
      console.log("[WS] Stream closed. Attempting reconnect in 4 seconds...");
      setTimeout(connectWebSocket, 4000);
    };

    ws.onerror = (err) => {
      console.error("[WS] Connection error:", err);
      ws.close();
    };
  };

  // Trigger metrics and incidents queries
  useEffect(() => {
    fetchMetrics();
    fetchIncidents();
    fetchAlerts();
    fetchRecentLogs();
    connectWebSocket();

    const metricsInterval = setInterval(fetchMetrics, 2000);
    const incidentInterval = setInterval(fetchIncidents, 5000);

    return () => {
      clearInterval(metricsInterval);
      clearInterval(incidentInterval);
      if (wsRef.current) wsRef.current.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 4. API Event Handlers

  const handleBlock = async (alertId) => {
    try {
      const res = await fetch(`/api/alerts/${alertId}/block`, { method: 'POST' });
      if (res.ok) {
        fetchMetrics();
      }
    } catch (e) {
      console.error("Defensive block call failed", e);
    }
  };

  const handleDismiss = async (alertId) => {
    try {
      const res = await fetch(`/api/alerts/${alertId}/dismiss`, { method: 'POST' });
      if (res.ok) {
        setAlerts(prev => prev.filter(a => a.id !== alertId));
        fetchMetrics();
      }
    } catch (e) {
      console.error("Dismiss event failed", e);
    }
  };

  const handleConfigChange = async (config) => {
    try {
      const res = await fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      });
      if (res.ok) {
        fetchMetrics();
      }
    } catch (e) {
      console.error("Configuration sync request failed", e);
    }
  };

  const handleCreateIncident = async (incidentData) => {
    try {
      const res = await fetch('/api/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(incidentData)
      });
      if (res.ok) {
        fetchIncidents();
        setActiveTab('incidents');
      }
    } catch (e) {
      console.error("Failed to create incident record", e);
    }
  };

  const handleUpdateIncident = async (id, updateData) => {
    try {
      const res = await fetch(`/api/incidents/${id}/update`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updateData)
      });
      if (res.ok) {
        fetchIncidents();
        return true;
      }
      return false;
    } catch (e) {
      console.error("Failed to update incident", e);
      return false;
    }
  };

  return (
    <div className="flex bg-[#080d1a] min-h-screen text-slate-200">
      {/* Navigation Sidebar */}
      <Sidebar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        alertsCount={metrics.alerts_count}
        incidentsCount={incidents.length}
      />

      {/* Main Panel Content container */}
      <main className="flex-1 p-6 overflow-y-auto space-y-6">
        {/* Top Header Navbar */}
        <header className="flex justify-between items-center pb-4 border-b border-slate-800/60">
          <div>
            <h2 className="text-xl font-bold tracking-tight text-slate-100 uppercase">
              {activeTab === 'dashboard' && 'SOC Dashboard Command Center'}
              {activeTab === 'alerts' && 'Live Alert Event Feeds'}
              {activeTab === 'hunting' && 'Advanced Threat Hunting Logs'}
              {activeTab === 'offline' && 'Offline Ingestion & Forensic Analytics'}
              {activeTab === 'incidents' && 'Escalated Incident Management'}
              {activeTab === 'reports' && 'SOC Audits & Export Download'}
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              {activeTab === 'dashboard' && 'Real-time overview of simulation logs, attacks, and firewall states.'}
              {activeTab === 'alerts' && 'Continuous review panel for active security log triggers.'}
              {activeTab === 'hunting' && 'Inspect raw web events stored inside SQLite database.'}
              {activeTab === 'offline' && 'Forensic log parsing, threat scoring, and mitigation checklists.'}
              {activeTab === 'incidents' && 'Track case logs, resolution notes, and analyst assignments.'}
              {activeTab === 'reports' && 'Generate CSV feeds and PDF sheets of threat parameters.'}
            </p>
          </div>

          <div className="flex items-center space-x-3 text-xs bg-slate-900/60 px-4 py-2 border border-slate-800/80 rounded-xl">
            <Radio className="w-3.5 h-3.5 text-blue-500 animate-pulse" />
            <span className="font-semibold text-slate-400">Stream Status:</span>
            <span className="text-emerald-400 font-bold flex items-center font-mono">
              <ShieldCheck className="w-3.5 h-3.5 mr-1" /> LIVE CONNECTED
            </span>
          </div>
        </header>

        {/* Tab view switching logic */}
        <div className="transition-all duration-300">
          {activeTab === 'dashboard' && (
            <Dashboard 
              metrics={metrics}
              alerts={alerts}
              latestAlert={latestAlert}
              epsHistory={epsHistory}
              onBlock={handleBlock}
              onDismiss={handleDismiss}
              onConfigChange={handleConfigChange}
              logs={logs}
              setActiveTab={setActiveTab}
              incidents={incidents}
            />
          )}

          {activeTab === 'alerts' && (
            <div className="glass-panel p-6 rounded-2xl border border-slate-800/80">
              <AlertFeed 
                alerts={alerts} 
                onBlock={handleBlock} 
                onDismiss={handleDismiss} 
                onEscalate={handleCreateIncident}
              />
            </div>
          )}

          {activeTab === 'hunting' && (
            <ThreatHunting 
              onCreateIncident={handleCreateIncident} 
            />
          )}

          {activeTab === 'incidents' && (
            <IncidentManager 
              incidents={incidents} 
              onUpdateIncident={handleUpdateIncident}
              triggerRefresh={fetchIncidents}
            />
          )}

          {activeTab === 'reports' && (
            <ReportDownload />
          )}

          {activeTab === 'offline' && (
            <LogUpload />
          )}

          {activeTab === 'mitre' && (
            <MitreMatrix alerts={alerts} />
          )}

          {activeTab === 'killchain' && (
            <KillChainDetail alerts={alerts} latestAlert={latestAlert} />
          )}

          {activeTab === 'threatintel' && (
            <ThreatIntelManager alerts={alerts} />
          )}

          {activeTab === 'blockedips' && (
            <BlockedIpsManager blockedIpsList={metrics.blocked_ips_list} triggerRefresh={fetchMetrics} />
          )}

          {activeTab === 'settings' && (
            <SettingsManager metrics={metrics} onConfigChange={handleConfigChange} triggerRefresh={fetchMetrics} />
          )}
        </div>
      </main>
    </div>
  );
}
