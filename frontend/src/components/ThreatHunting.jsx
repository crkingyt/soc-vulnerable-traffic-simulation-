import React, { useState, useEffect } from 'react';
import { Search, FolderPlus, Compass } from 'lucide-react';

export default function ThreatHunting({ onCreateIncident }) {
  const [ip, setIp] = useState('');
  const [uri, setUri] = useState('');
  const [ua, setUa] = useState('');
  const [attackType, setAttackType] = useState('');
  const [severity, setSeverity] = useState('');
  
  const [results, setResults] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [limit] = useState(15);
  const [page, setPage] = useState(1);

  const fetchResults = async (overrideParams = {}) => {
    setLoading(true);
    try {
      const currentPage = overrideParams.hasOwnProperty('page') ? overrideParams.page : page;
      const currentIp = overrideParams.hasOwnProperty('ip') ? overrideParams.ip : ip;
      const currentUri = overrideParams.hasOwnProperty('uri') ? overrideParams.uri : uri;
      const currentUa = overrideParams.hasOwnProperty('ua') ? overrideParams.ua : ua;
      const currentAttackType = overrideParams.hasOwnProperty('attackType') ? overrideParams.attackType : attackType;
      const currentSeverity = overrideParams.hasOwnProperty('severity') ? overrideParams.severity : severity;

      const offset = (currentPage - 1) * limit;
      let query = `/api/hunt?limit=${limit}&offset=${offset}`;
      if (currentIp) query += `&source_ip=${encodeURIComponent(currentIp)}`;
      if (currentUri) query += `&uri=${encodeURIComponent(currentUri)}`;
      if (currentUa) query += `&user_agent=${encodeURIComponent(currentUa)}`;
      if (currentAttackType) query += `&attack_type=${encodeURIComponent(currentAttackType)}`;
      if (currentSeverity) query += `&severity=${encodeURIComponent(currentSeverity)}`;

      const res = await fetch(query);
      if (res.ok) {
        const data = await res.json();
        setResults(data.results);
        setTotal(data.total);
      }
    } catch (e) {
      console.error("Forensic lookup search failed", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchResults();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page]);

  const handleSearch = (e) => {
    e.preventDefault();
    setPage(1);
    fetchResults({ page: 1 });
  };

  const clearFilters = () => {
    setIp('');
    setUri('');
    setUa('');
    setAttackType('');
    setSeverity('');
    setPage(1);
    fetchResults({
      ip: '',
      uri: '',
      ua: '',
      attackType: '',
      severity: '',
      page: 1
    });
  };

  return (
    <div className="space-y-6">
      {/* Search Filter Form */}
      <form onSubmit={handleSearch} className="glass-panel p-5 rounded-2xl border border-slate-800/80 space-y-4">
        <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-widest flex items-center">
          <Search className="w-4 h-4 mr-2 text-blue-500" />
          Forensic Threat Hunting Search
        </h3>

        <div className="grid grid-cols-5 gap-3.5">
          <div className="flex flex-col">
            <label className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider mb-1.5">Source IP</label>
            <input 
              type="text" 
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="e.g. 192.168.1.10"
              className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 outline-none focus:border-slate-700 font-mono"
            />
          </div>

          <div className="flex flex-col">
            <label className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider mb-1.5">URI Pattern</label>
            <input 
              type="text" 
              value={uri}
              onChange={(e) => setUri(e.target.value)}
              placeholder="e.g. /login"
              className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 outline-none focus:border-slate-700 font-mono"
            />
          </div>

          <div className="flex flex-col">
            <label className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider mb-1.5">User Agent</label>
            <input 
              type="text" 
              value={ua}
              onChange={(e) => setUa(e.target.value)}
              placeholder="e.g. sqlmap"
              className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 outline-none focus:border-slate-700"
            />
          </div>

          <div className="flex flex-col">
            <label className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider mb-1.5">Attack Type</label>
            <select
              value={attackType}
              onChange={(e) => setAttackType(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 outline-none focus:border-slate-700"
            >
              <option value="">All Attacks</option>
              <option value="SQL Injection">SQL Injection</option>
              <option value="XSS">XSS Attack</option>
              <option value="Directory Traversal">Directory Traversal</option>
              <option value="Brute Force">Brute Force</option>
              <option value="Command Injection">Command Injection</option>
              <option value="Web Scanning">Web Scanning</option>
            </select>
          </div>

          <div className="flex flex-col">
            <label className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider mb-1.5">Severity</label>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 outline-none focus:border-slate-700"
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
        </div>

        <div className="flex justify-end space-x-2 pt-2">
          <button
            type="button"
            onClick={clearFilters}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-750 text-xs font-semibold text-slate-400 hover:text-slate-300 rounded-lg transition-colors"
          >
            Clear Filters
          </button>
          <button
            type="submit"
            className="flex items-center space-x-1.5 px-5 py-2 bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white rounded-lg transition-colors shadow-[0_0_10px_rgba(37,99,235,0.3)]"
          >
            <Search className="w-3.5 h-3.5" />
            <span>Search Logs</span>
          </button>
        </div>
      </form>

      {/* Results Log Table */}
      <div className="glass-panel rounded-2xl border border-slate-800/80 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-2">Target</th>
                <th className="py-3 px-2">Method</th>
                <th className="py-3 px-4">URI Path</th>
                <th className="py-3 px-2">Status</th>
                <th className="py-3 px-4">Attack Type</th>
                <th className="py-3 px-4 text-center">Severity</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {loading ? (
                <tr>
                  <td colSpan={9} className="text-center py-16 text-slate-500">
                    Executing dynamic query on SQLite soc.db...
                  </td>
                </tr>
              ) : results.length === 0 ? (
                <tr>
                  <td colSpan={9} className="text-center py-16 text-slate-500">
                    No results match selection criteria.
                  </td>
                </tr>
              ) : (
                results.map((row) => (
                  <tr 
                    key={row.id} 
                    className={`hover:bg-slate-900/30 transition-colors ${
                      row.attack_type ? 'bg-red-500/[0.02]' : ''
                    }`}
                  >
                    <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">
                      {row.timestamp.replace('T', ' ').slice(0, 19)}
                    </td>
                    <td className="py-3.5 px-4 text-slate-200">{row.source_ip}</td>
                    <td className="py-3.5 px-2">
                      <span className="text-slate-400">{row.server.toUpperCase()}</span>
                    </td>
                    <td className="py-3.5 px-2">
                      <span className="bg-slate-850 px-1.5 py-0.5 rounded text-[10px] font-bold text-slate-300">
                        {row.method}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-300 max-w-[200px] truncate" title={row.uri}>
                      {row.uri}
                    </td>
                    <td className={`py-3.5 px-2 font-bold ${row.status_code >= 400 ? 'text-red-400' : 'text-emerald-400'}`}>
                      {row.status_code}
                    </td>
                    <td className="py-3.5 px-4 font-sans text-slate-200">
                      {row.attack_type || <span className="text-slate-600 italic">Benign Traffic</span>}
                    </td>
                    <td className="py-3.5 px-4 text-center">
                      {row.severity ? (
                        <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold uppercase ${
                          row.severity === 'Critical' ? 'bg-red-500/10 text-red-500 border border-red-500/20' :
                          row.severity === 'High' ? 'bg-orange-500/10 text-orange-500 border border-orange-500/20' :
                          row.severity === 'Medium' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                          'bg-slate-500/10 text-slate-400 border border-slate-500/20'
                        }`}>
                          {row.severity}
                        </span>
                      ) : '-'}
                    </td>
                    <td className="py-3.5 px-4 text-right font-sans">
                      {row.attack_type && row.alert_status !== 'Escalated' ? (
                        <button
                          onClick={() => onCreateIncident({
                            attack_type: row.attack_type,
                            severity: row.severity,
                            alert_ids: [row.alert_id],
                            analyst_notes: `Escalated alert detected from IP ${row.source_ip} querying ${row.uri}`
                          })}
                          className="flex items-center space-x-1 ml-auto px-2.5 py-1 bg-blue-600/10 hover:bg-blue-600 text-[10px] font-semibold text-blue-400 hover:text-white border border-blue-500/20 rounded-md transition-all"
                        >
                          <FolderPlus className="w-3 h-3" />
                          <span>Escalate</span>
                        </button>
                      ) : row.alert_status === 'Escalated' ? (
                        <span className="text-[10px] text-emerald-400 flex items-center justify-end font-semibold">
                          <Compass className="w-3 h-3 mr-1" /> Escalated
                        </span>
                      ) : '-'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        {total > limit && (
          <div className="bg-slate-900/40 border-t border-slate-800/80 px-4 py-3 flex items-center justify-between text-slate-500 text-xs">
            <span>
              Showing {(page - 1) * limit + 1} to {Math.min(page * limit, total)} of {total} records
            </span>
            <div className="flex space-x-1.5 font-sans">
              <button
                disabled={page === 1}
                onClick={() => setPage(p => Math.max(1, p - 1))}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 rounded transition-colors text-slate-300 font-semibold"
              >
                Previous
              </button>
              <button
                disabled={page * limit >= total}
                onClick={() => setPage(p => p + 1)}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 rounded transition-colors text-slate-300 font-semibold"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
