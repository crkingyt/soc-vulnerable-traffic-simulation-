import React, { useState } from 'react';
import { FileDown, Calendar, AlertCircle } from 'lucide-react';

export default function ReportDownload() {
  const [format, setFormat] = useState('pdf');
  const [startTime, setStartTime] = useState('');
  const [endTime, setEndTime] = useState('');
  const [downloading, setDownloading] = useState(false);

  const handleDownload = async (e) => {
    e.preventDefault();
    setDownloading(true);
    try {
      let url = `/api/export?format=${format}`;
      if (startTime) url += `&start_time=${new Date(startTime).toISOString()}`;
      if (endTime) url += `&end_time=${new Date(endTime).toISOString()}`;
      
      const response = await fetch(url);
      if (!response.ok) throw new Error("Download request failed");
      
      const blob = await response.blob();
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.setAttribute('download', `soc_report_${format === 'pdf' ? 'summary.pdf' : format === 'csv' ? 'alerts.csv' : 'state.json'}`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      console.error("Error downloading report", err);
      alert("Failed to export report: " + err.message);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="glass-panel p-6 rounded-2xl border border-slate-800/80 max-w-xl mx-auto space-y-5">
      <div>
        <h2 className="text-base font-semibold text-slate-100 flex items-center">
          <FileDown className="w-5 h-5 mr-2 text-blue-500" />
          Export Platform Reports
        </h2>
        <p className="text-xs text-slate-500 mt-1">
          Compile logs, active incident logs, MITRE mappings, and defensive blocks into audit-ready report sheets.
        </p>
      </div>

      <form onSubmit={handleDownload} className="space-y-4 text-xs">
        {/* Format Select */}
        <div className="flex flex-col">
          <label className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider block mb-1.5">Export Format</label>
          <div className="grid grid-cols-3 gap-2.5">
            {['pdf', 'csv', 'json'].map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => setFormat(f)}
                className={`py-2.5 rounded-lg border text-center font-semibold transition-all ${
                  format === f
                    ? 'bg-blue-600/10 border-blue-500 text-blue-400 font-bold'
                    : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                {f.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {/* Date Ranges */}
        <div className="grid grid-cols-2 gap-4">
          <div className="flex flex-col">
            <label className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider block mb-1.5">Start Date (Optional)</label>
            <div className="relative">
              <input
                type="datetime-local"
                value={startTime}
                onChange={(e) => setStartTime(e.target.value)}
                className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2.5 text-slate-200 outline-none focus:border-slate-700 w-full font-sans"
              />
            </div>
          </div>
          <div className="flex flex-col">
            <label className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider block mb-1.5">End Date (Optional)</label>
            <input
              type="datetime-local"
              value={endTime}
              onChange={(e) => setEndTime(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2.5 text-slate-200 outline-none focus:border-slate-700 w-full font-sans"
            />
          </div>
        </div>

        {/* Format Explanation Warning */}
        <div className="bg-slate-950/40 p-3 rounded-lg border border-slate-900/60 flex items-start space-x-2 text-slate-500 text-[11px] leading-relaxed">
          <AlertCircle className="w-4 h-4 text-blue-500/80 shrink-0 mt-0.5" />
          <span>
            {format === 'pdf' && 'Generates a fully stylized PDF including summary charts, MITRE top techniques tables, and active defensive block summaries.'}
            {format === 'csv' && 'Compiles a flat, importable CSV sheet listing all security alerts with full raw payloads for import into Splunk or ELK.'}
            {format === 'json' && 'Generates a JSON dump matching standard SOC ingestion schemas, containing nested lists of alerts, blocks, and incidents.'}
          </span>
        </div>

        {/* Action Button */}
        <button
          type="submit"
          disabled={downloading}
          className="w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold rounded-lg transition-colors flex items-center justify-center space-x-1.5 shadow-[0_0_15px_rgba(37,99,235,0.4)]"
        >
          <FileDown className="w-4 h-4" />
          <span>{downloading ? 'Compiling Report Data...' : 'Download Report'}</span>
        </button>
      </form>
    </div>
  );
}
