import React, { useState, useEffect } from 'react';
import { 
  UploadCloud, CheckCircle, ShieldAlert, AlertTriangle, Play, 
  FileText, Trash2, Loader2, AlertCircle, Shield, FileDown, 
  ExternalLink, BarChart3, HelpCircle 
} from 'lucide-react';
import { 
  PieChart, Pie, Cell, ResponsiveContainer, 
  LineChart, Line, XAxis, YAxis, Tooltip, Legend 
} from 'recharts';

export default function LogUpload() {
  const [file, setFile] = useState(null);
  const [format, setFormat] = useState('auto');
  const [columnMapping, setColumnMapping] = useState({
    timestamp: '0',
    source_ip: '1',
    method: '2',
    uri: '3',
    status_code: '4',
    user_agent: '5'
  });
  
  const [jobId, setJobId] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [jobStatus, setJobStatus] = useState(null);
  const [history, setHistory] = useState([]);
  
  // Results details
  const [selectedJob, setSelectedJob] = useState(null);
  const [resultsData, setResultsData] = useState(null); // { job, summary, alerts }
  const [loadingResults, setLoadingResults] = useState(false);
  
  // Fetch upload history
  const fetchHistory = async () => {
    try {
      const res = await fetch('/api/upload/history');
      if (res.ok) {
        const data = await res.json();
        setHistory(data);
      }
    } catch (err) {
      console.error("Failed to fetch upload history", err);
    }
  };

  useEffect(() => {
    fetchHistory();
    const interval = setInterval(fetchHistory, 10000);
    return () => clearInterval(interval);
  }, []);

  // Poll status when a job is active
  useEffect(() => {
    if (!jobId) return;

    let intervalId;
    const checkStatus = async () => {
      try {
        const res = await fetch(`/api/upload/${jobId}/status`);
        if (!res.ok) return;
        const data = await res.json();
        setJobStatus(data);
        
        if (data.status === 'complete') {
          clearInterval(intervalId);
          setUploading(false);
          setJobId(null);
          loadResults(jobId);
          fetchHistory();
        } else if (data.status === 'failed') {
          clearInterval(intervalId);
          setUploading(false);
          setJobId(null);
          alert("Log file analysis failed. Please verify the log format.");
          fetchHistory();
        }
      } catch (err) {
        console.error("Error polling status", err);
      }
    };

    intervalId = setInterval(checkStatus, 2000);
    return () => clearInterval(intervalId);
  }, [jobId]);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleUploadSubmit = async (e) => {
    e.preventDefault();
    if (!file) return;

    setUploading(true);
    setResultsData(null);
    setJobStatus({ status: 'uploading' });

    const formData = new FormData();
    formData.append('file', file);
    formData.append('format', format);
    if (format === 'csv') {
      formData.append('column_mapping', JSON.stringify(columnMapping));
    }

    try {
      const res = await fetch('/api/upload/logs', {
        method: 'POST',
        body: formData,
      });
      
      if (!res.ok) {
        throw new Error(await res.text() || "Upload failed");
      }
      
      const data = await res.json();
      setJobId(data.job_id);
    } catch (err) {
      console.error(err);
      alert("Upload failed: " + err.message);
      setUploading(false);
      setJobStatus(null);
    }
  };

  const loadResults = async (jId) => {
    setLoadingResults(true);
    setSelectedJob(jId);
    try {
      const res = await fetch(`/api/upload/${jId}/results`);
      if (res.ok) {
        const data = await res.json();
        setResultsData(data);
      } else {
        alert("Failed to load results.");
      }
    } catch (err) {
      console.error("Error loading results", err);
    } finally {
      setLoadingResults(false);
    }
  };

  const handleDeleteJob = async (jId, e) => {
    e.stopPropagation();
    if (!confirm("Are you sure you want to delete this job and its analytics data?")) return;

    try {
      const res = await fetch(`/api/upload/${jId}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        if (selectedJob === jId) {
          setResultsData(null);
          setSelectedJob(null);
        }
        fetchHistory();
      }
    } catch (err) {
      console.error("Failed to delete job", err);
    }
  };

  const handleBlockIP = async (alertId, ip) => {
    try {
      const res = await fetch(`/api/alerts/${alertId}/block`, {
        method: 'POST',
      });
      if (res.ok) {
        // Refresh results
        if (selectedJob) {
          loadResults(selectedJob);
        }
      } else {
        alert("Failed to block IP");
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleDismissAlert = async (alertId) => {
    try {
      const res = await fetch(`/api/alerts/${alertId}/dismiss`, {
        method: 'POST',
      });
      if (res.ok) {
        // Refresh results
        if (selectedJob) {
          loadResults(selectedJob);
        }
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleExportReport = async (expFormat) => {
    if (!selectedJob) return;
    try {
      const response = await fetch(`/api/export?format=${expFormat}&job_id=${selectedJob}`);
      if (!response.ok) throw new Error("Export failed");
      const blob = await response.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      const fileExts = { pdf: 'pdf', csv: 'csv', json: 'json' };
      link.setAttribute('download', `offline_report_${selectedJob}.${fileExts[expFormat]}`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      alert("Failed to export: " + err.message);
    }
  };

  const COLORS = ['#ef4444', '#f97316', '#3b82f6', '#10b981', '#a855f7', '#ec4899'];
  const SEV_COLORS = {
    Critical: '#ef4444',
    High: '#f97316',
    Medium: '#eab308',
    Low: '#10b981'
  };

  // Convert summary.attack_distribution to format usable by Recharts
  const getPieData = () => {
    if (!resultsData || !resultsData.summary || !resultsData.summary.attack_distribution) return [];
    return Object.entries(resultsData.summary.attack_distribution).map(([name, value]) => ({
      name,
      value
    }));
  };

  return (
    <div className="space-y-6 text-xs text-slate-300">
      
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Offline Log Analytics</h1>
          <p className="text-slate-500 mt-1">
            Ingest external or historical log dumps to analyze, score, maps MITRE vectors, and generate reports.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Ingestion Panel */}
        <div className="lg:col-span-1 space-y-6">
          <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 space-y-4">
            <h2 className="text-sm font-semibold text-slate-100 flex items-center">
              <UploadCloud className="w-4 h-4 mr-2 text-blue-500" />
              Upload Log Archive
            </h2>
            
            <form onSubmit={handleUploadSubmit} className="space-y-4">
              {/* Drag n Drop picker */}
              <div className="border border-dashed border-slate-800 hover:border-slate-700 bg-slate-950/50 rounded-xl p-6 text-center cursor-pointer transition-colors relative">
                <input 
                  type="file" 
                  accept=".log,.txt,.csv,.json,.jsonl,.gz"
                  onChange={handleFileChange}
                  className="absolute inset-0 opacity-0 cursor-pointer"
                  disabled={uploading}
                />
                <UploadCloud className="w-8 h-8 mx-auto text-slate-500 mb-2" />
                {file ? (
                  <div>
                    <p className="font-semibold text-slate-200 truncate">{file.name}</p>
                    <p className="text-[10px] text-slate-500 mt-0.5">{(file.size / 1024).toFixed(1)} KB</p>
                  </div>
                ) : (
                  <div>
                    <p className="font-semibold text-slate-300">Choose file or drag here</p>
                    <p className="text-[10px] text-slate-500 mt-0.5">Accepts .log, .txt, .csv, .json, .jsonl, .gz</p>
                  </div>
                )}
              </div>

              {/* Format dropdown */}
              <div className="space-y-1.5">
                <label className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider block">Log Format</label>
                <select
                  value={format}
                  onChange={(e) => setFormat(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 outline-none focus:border-slate-700"
                  disabled={uploading}
                >
                  <option value="auto">Auto-Detect Format</option>
                  <option value="apache">Apache CLF / Combined</option>
                  <option value="iis">IIS W3C Extended</option>
                  <option value="syslog">Syslog RFC 3164/5424</option>
                  <option value="json">JSON / JSONL Dumps</option>
                  <option value="csv">CSV (Comma-Separated)</option>
                </select>
              </div>

              {/* CSV column mapping */}
              {format === 'csv' && (
                <div className="p-3 bg-slate-950/40 border border-slate-900/60 rounded-xl space-y-2 text-[10px]">
                  <p className="font-bold text-slate-400 mb-1">CSV Header Mapping</p>
                  {Object.keys(columnMapping).map((field) => (
                    <div key={field} className="flex items-center justify-between gap-2">
                      <span className="capitalize text-slate-500">{field.replace('_', ' ')}:</span>
                      <input 
                        type="text" 
                        value={columnMapping[field]}
                        onChange={(e) => setColumnMapping({ ...columnMapping, [field]: e.target.value })}
                        className="bg-slate-900 border border-slate-800 rounded px-2 py-0.5 w-24 text-right text-slate-200 outline-none"
                        placeholder="Index or Name"
                        disabled={uploading}
                      />
                    </div>
                  ))}
                </div>
              )}

              {/* Submit button */}
              <button
                type="submit"
                disabled={!file || uploading}
                className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white font-bold rounded-lg transition-colors flex items-center justify-center space-x-1.5 shadow-[0_0_12px_rgba(37,99,235,0.3)]"
              >
                {uploading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span className="capitalize">{jobStatus?.status || 'Analyzing'}...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    <span>Run Offline Analysis</span>
                  </>
                )}
              </button>
            </form>

            {/* In-progress progress bars */}
            {uploading && jobStatus && (
              <div className="pt-3 border-t border-slate-800/60 space-y-2">
                <div className="flex items-center justify-between text-[10px] text-slate-500">
                  <span className="capitalize">Stage: {jobStatus.status}</span>
                  <span>{jobStatus.total_lines || 0} lines parsed</span>
                </div>
                <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-blue-500 animate-pulse transition-all duration-300"
                    style={{ 
                      width: jobStatus.status === 'uploading' ? '30%' : 
                             jobStatus.status === 'detecting' ? '60%' : 
                             jobStatus.status === 'parsing' ? '85%' : '100%' 
                    }}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Historical Uploads */}
          <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 space-y-4">
            <h2 className="text-sm font-semibold text-slate-100 flex items-center">
              <FileText className="w-4 h-4 mr-2 text-slate-400" />
              Analysis History
            </h2>
            
            <div className="space-y-2.5 max-h-[300px] overflow-y-auto pr-1">
              {history.length === 0 ? (
                <div className="text-center py-6 text-slate-500">No past uploads found.</div>
              ) : (
                history.map((h) => (
                  <div
                    key={h.job_id}
                    onClick={() => loadResults(h.job_id)}
                    className={`p-3 rounded-xl border cursor-pointer transition-colors flex items-center justify-between gap-2 ${
                      selectedJob === h.job_id
                        ? 'bg-slate-900 border-blue-600/60 text-slate-200'
                        : 'bg-slate-950/60 border-slate-900 text-slate-400 hover:border-slate-800 hover:bg-slate-900/30'
                    }`}
                  >
                    <div className="min-w-0 flex-1 space-y-1">
                      <div className="flex items-center justify-between gap-1.5">
                        <span className="font-semibold text-slate-200 truncate pr-2">{h.filename}</span>
                        <span className="text-[9px] uppercase bg-slate-900/80 text-slate-500 font-bold px-1.5 py-0.5 rounded border border-slate-800">{h.format}</span>
                      </div>
                      <div className="flex items-center justify-between text-[9px] text-slate-500">
                        <span>{new Date(h.uploaded_at).toLocaleDateString()}</span>
                        <span>{h.total_alerts} alerts / {h.total_lines} lines</span>
                      </div>
                    </div>
                    
                    <button 
                      onClick={(e) => handleDeleteJob(h.job_id, e)}
                      className="p-1.5 hover:text-red-400 text-slate-600 transition-colors shrink-0"
                      title="Delete Analytics Job"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Results Panel */}
        <div className="lg:col-span-2 space-y-6">
          
          {loadingResults ? (
            <div className="glass-panel p-16 rounded-2xl border border-slate-800/80 flex flex-col items-center justify-center space-y-3">
              <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
              <p className="text-sm font-semibold text-slate-400">Retrieving forensic analytics report...</p>
            </div>
          ) : resultsData ? (
            <div className="space-y-6">
              
              {/* Export and Action Header */}
              <div className="glass-panel p-4 rounded-xl border border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-4">
                <div className="flex items-center space-x-2">
                  <BarChart3 className="w-5 h-5 text-blue-500" />
                  <span className="font-bold text-slate-200 text-sm truncate max-w-xs">{resultsData.job.filename}</span>
                </div>
                <div className="flex items-center space-x-2">
                  {['pdf', 'csv', 'json'].map((expFmt) => (
                    <button
                      key={expFmt}
                      onClick={() => handleExportReport(expFmt)}
                      className="px-2.5 py-1 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 rounded font-semibold transition-all flex items-center space-x-1 uppercase text-[10px]"
                    >
                      <FileDown className="w-3 h-3" />
                      <span>{expFmt}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* KPI metrics */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                <div className="bg-slate-900/50 border border-slate-800/70 p-4 rounded-xl space-y-1">
                  <p className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider">Total Alerts</p>
                  <p className="text-xl font-bold text-red-500">{resultsData.summary.total_alerts}</p>
                  <p className="text-[9px] text-slate-500">out of {resultsData.summary.total_lines} logs</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-800/70 p-4 rounded-xl space-y-1">
                  <p className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider">Detection Rate</p>
                  <p className="text-xl font-bold text-blue-400">{resultsData.summary.detection_rate}%</p>
                  <p className="text-[9px] text-slate-500">attacks / total events</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-800/70 p-4 rounded-xl space-y-1">
                  <p className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider">Unique Attackers</p>
                  <p className="text-xl font-bold text-slate-200">{resultsData.summary.unique_attackers}</p>
                  <p className="text-[9px] text-slate-500">distinct source IPs</p>
                </div>
                <div className="bg-slate-900/50 border border-slate-800/70 p-4 rounded-xl space-y-1">
                  <p className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider">Avg Threat Score</p>
                  <p className={`text-xl font-bold ${
                    resultsData.summary.avg_threat_score >= 70 ? 'text-red-500' :
                    resultsData.summary.avg_threat_score >= 40 ? 'text-orange-400' : 'text-emerald-500'
                  }`}>{resultsData.summary.avg_threat_score}/100</p>
                  <p className="text-[9px] text-slate-500">average hazard weight</p>
                </div>
              </div>

              {/* Aggregation Charts */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* Attack Distribution Pie */}
                <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 space-y-4">
                  <h3 className="text-xs font-semibold text-slate-200 tracking-wide uppercase">Attack Type Distribution</h3>
                  <div className="h-48 w-full flex items-center justify-center">
                    {getPieData().length === 0 ? (
                      <div className="text-slate-500 text-center">No alerts to display</div>
                    ) : (
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={getPieData()}
                            cx="50%"
                            cy="50%"
                            innerRadius={50}
                            outerRadius={70}
                            paddingAngle={3}
                            dataKey="value"
                          >
                            {getPieData().map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip 
                            contentStyle={{ backgroundColor: '#090d16', border: '1px solid #1e293b' }}
                            itemStyle={{ color: '#cbd5e1', fontSize: 10 }}
                          />
                          <Legend 
                            verticalAlign="bottom" 
                            height={36} 
                            iconSize={8}
                            iconType="circle"
                            wrapperStyle={{ fontSize: 9, color: '#64748b' }}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                    )}
                  </div>
                </div>

                {/* Timeline Chart */}
                <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 space-y-4">
                  <h3 className="text-xs font-semibold text-slate-200 tracking-wide uppercase">Alert Activity Timeline</h3>
                  <div className="h-48 w-full">
                    {resultsData.summary.timeline.length === 0 ? (
                      <div className="text-slate-500 text-center pt-20">No data points</div>
                    ) : (
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={resultsData.summary.timeline}>
                          <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 8 }} />
                          <YAxis stroke="#64748b" tick={{ fontSize: 8 }} />
                          <Tooltip 
                            contentStyle={{ backgroundColor: '#090d16', border: '1px solid #1e293b' }}
                            itemStyle={{ color: '#ef4444', fontSize: 10 }}
                          />
                          <Line type="monotone" dataKey="count" name="Alerts Count" stroke="#ef4444" strokeWidth={2} dot={false} />
                        </LineChart>
                      </ResponsiveContainer>
                    )}
                  </div>
                </div>
              </div>

              {/* MITRE Kill Chain Coverage */}
              <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 space-y-3">
                <h3 className="text-xs font-semibold text-slate-200 tracking-wide uppercase">MITRE Cyber Kill Chain Coverage</h3>
                <div className="grid grid-cols-2 sm:grid-cols-7 gap-2.5">
                  {Object.entries(resultsData.summary.kill_chain_coverage).map(([stage, hit]) => (
                    <div 
                      key={stage}
                      className={`p-3 rounded-lg border text-center transition-all ${
                        hit 
                          ? 'bg-red-500/10 border-red-500 text-red-400 font-bold shadow-[0_0_10px_rgba(239,68,68,0.2)]'
                          : 'bg-slate-950/40 border-slate-900 text-slate-600'
                      }`}
                    >
                      <p className="text-[9px] font-semibold truncate leading-tight" title={stage}>{stage}</p>
                      <span className="text-[8px] block mt-1 font-bold">
                        {hit ? 'DETECTED' : 'CLEAN'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Top Attacking IPs & Recommended Mitigation */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* Top IPs Table */}
                <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 space-y-3">
                  <h3 className="text-xs font-semibold text-slate-200 tracking-wide uppercase">Top Attacking IP Addresses</h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-[10px] text-left">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-500 font-semibold">
                          <th className="pb-2">Source IP</th>
                          <th className="pb-2 text-right">Alert Count</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-900">
                        {resultsData.summary.top_ips.map((row, idx) => (
                          <tr key={idx} className="hover:bg-slate-900/30">
                            <td className="py-2.5 font-mono text-slate-300">{row.ip}</td>
                            <td className="py-2.5 text-right font-semibold text-red-400">{row.count}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Recommended actions */}
                <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 space-y-3">
                  <h3 className="text-xs font-semibold text-slate-200 tracking-wide uppercase">Actionable Remediation Checklist</h3>
                  <div className="space-y-3 max-h-[160px] overflow-y-auto pr-1">
                    {resultsData.summary.recommended_actions.length === 0 ? (
                      <div className="text-slate-500 py-4 text-center">No actions generated</div>
                    ) : (
                      resultsData.summary.recommended_actions.map((act, idx) => (
                        <div key={idx} className="flex gap-2.5 p-2.5 bg-slate-950/40 border border-slate-900 rounded-lg">
                          <Shield className="w-4 h-4 text-blue-500 shrink-0 mt-0.5" />
                          <div className="space-y-0.5">
                            <p className="font-bold text-slate-200">{act.attack_type}</p>
                            <p className="text-[9px] text-slate-500 leading-normal">{act.mitigation}</p>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>

              {/* Forensic Log / Offline Alerts Feed */}
              <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 space-y-4">
                <h3 className="text-xs font-semibold text-slate-200 tracking-wide uppercase">Forensic Incident logs ({resultsData.alerts.length})</h3>
                
                <div className="space-y-3.5 max-h-[400px] overflow-y-auto pr-1">
                  {resultsData.alerts.length === 0 ? (
                    <div className="text-slate-500 py-10 text-center">No alerts found in this log dump.</div>
                  ) : (
                    resultsData.alerts.map((al) => (
                      <div 
                        key={al.id} 
                        className={`p-4 rounded-xl border space-y-3 transition-colors bg-slate-950/30 ${
                          al.status === 'Escalated' ? 'border-red-600/40 bg-red-950/5' : 
                          al.status === 'Dismissed' ? 'border-slate-900 bg-slate-950/20 opacity-55' : 'border-slate-800'
                        }`}
                      >
                        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
                          <div className="flex items-center space-x-2">
                            <span 
                              className="px-2 py-0.5 rounded font-bold text-[9px]"
                              style={{ backgroundColor: `${SEV_COLORS[al.severity]}20`, color: SEV_COLORS[al.severity] }}
                            >
                              {al.severity}
                            </span>
                            <span className="font-bold text-slate-200 text-[11px]">{al.attack_type}</span>
                            <span className="text-[10px] text-slate-500">[{al.mitre_technique}]</span>
                          </div>
                          
                          <div className="flex items-center space-x-1.5">
                            {al.status === 'Active' && !al.auto_blocked && (
                              <>
                                <button 
                                  onClick={() => handleBlockIP(al.id, al.source_ip)}
                                  className="px-2 py-1 bg-red-950/40 hover:bg-red-900/40 text-red-400 hover:text-red-300 font-semibold rounded border border-red-900/60 transition-colors"
                                >
                                  Block Attacker
                                </button>
                                <button 
                                  onClick={() => handleDismissAlert(al.id)}
                                  className="px-2 py-1 bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-300 font-semibold rounded border border-slate-800 transition-colors"
                                >
                                  Dismiss
                                </button>
                              </>
                            )}
                            {al.auto_blocked && (
                              <span className="px-2 py-1 bg-emerald-950/50 text-emerald-400 font-bold border border-emerald-900/60 rounded text-[9px]">
                                Attacker Blocked
                              </span>
                            )}
                            {al.status === 'Escalated' && !al.auto_blocked && (
                              <span className="px-2 py-1 bg-blue-950/50 text-blue-400 font-bold border border-blue-900/60 rounded text-[9px]">
                                Escalated (Blocked)
                              </span>
                            )}
                            {al.status === 'Dismissed' && (
                              <span className="px-2 py-1 bg-slate-900 text-slate-600 font-semibold rounded text-[9px]">
                                Dismissed
                              </span>
                            )}
                          </div>
                        </div>

                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[10px] text-slate-400 pt-1 border-t border-slate-900">
                          <div>
                            <span className="text-[9px] text-slate-600 block">Attacking IP</span>
                            <span className="font-mono font-bold text-slate-300">{al.source_ip}</span>
                          </div>
                          <div>
                            <span className="text-[9px] text-slate-600 block">HTTP Request</span>
                            <span className="font-semibold text-slate-300">{al.method} {al.uri}</span>
                          </div>
                          <div>
                            <span className="text-[9px] text-slate-600 block">HTTP Status</span>
                            <span className="font-bold text-slate-300">{al.status_code}</span>
                          </div>
                          <div>
                            <span className="text-[9px] text-slate-600 block">Threat Score</span>
                            <span className="font-bold text-red-400">{al.threat_score}/100</span>
                          </div>
                        </div>

                        <div className="bg-slate-950/80 p-2.5 rounded-lg border border-slate-900/60 font-mono text-[9px] text-slate-500 select-all leading-normal overflow-x-auto whitespace-pre-wrap">
                          {al.raw_log}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="glass-panel p-16 rounded-2xl border border-slate-800/80 text-center flex flex-col items-center justify-center space-y-2.5">
              <ShieldAlert className="w-10 h-10 text-slate-600 mb-1" />
              <p className="text-sm font-semibold text-slate-300">No active report loaded</p>
              <p className="text-xs text-slate-500 max-w-sm leading-relaxed">
                Upload a log file or select a completed report from the Analysis History panel to load detailed findings.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
