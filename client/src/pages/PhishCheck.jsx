import React, { useState } from 'react';
import { securityApi } from '../api';
import { StatusBadge } from '../components/StatusBadge';
import { ResultTable } from '../components/ResultTable';
import { Alert } from '../components/Alert';

export default function PhishCheck() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleCheck = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    setResult(null);

    try {
      const res = await securityApi.checkPhish(url);
      setResult(res.data);
    } catch (err) {
      setError(err.message || 'Check failed');
    } finally {
      setLoading(false);
    }
  };

  const columns = [
    { header: 'Rule Triggered', accessor: 'rule', render: (r) => <span className="font-mono text-xs font-semibold">{r.rule}</span> },
    {
      header: 'Severity',
      accessor: 'severity',
      render: (r) => (
        <span className={`px-2 py-0.5 rounded text-xs font-bold ${
          r.severity === 'HIGH' ? 'bg-rose-100 text-rose-800' :
          r.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-800' : 'bg-slate-100 text-slate-800'
        }`}>
          {r.severity}
        </span>
      )
    },
    { header: 'Finding Description', accessor: 'message' }
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">PhishCheck</h1>
        <p className="text-sm text-slate-500">Heuristic threat scoring and deceptive pattern analysis for URLs.</p>
      </div>

      <Alert type="error" message={error} onClose={() => setError('')} />

      <form onSubmit={handleCheck} className="flex gap-3 bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://secure-login.suspicious-domain.xyz"
          required
          className="flex-1 px-4 py-2 border border-slate-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500 text-sm"
        />
        <button
          type="submit"
          disabled={loading}
          className="px-6 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-medium rounded-lg shadow-sm transition disabled:opacity-50 text-sm"
        >
          {loading ? 'Evaluating...' : 'Check URL'}
        </button>
      </form>

      {result && (
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-100 pb-4">
            <div>
              <p className="text-xs uppercase font-bold text-slate-400">Target URL</p>
              <p className="font-mono text-sm font-semibold text-slate-800 break-all">{result.url}</p>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <p className="text-xs uppercase font-bold text-slate-400">Risk Score</p>
                <p className={`text-2xl font-black ${result.riskScore > 50 ? 'text-rose-600' : 'text-emerald-600'}`}>
                  {result.riskScore}/100
                </p>
              </div>
              <StatusBadge status={result.classification} />
            </div>
          </div>

          <h3 className="font-semibold text-slate-800">Triggered Heuristics</h3>
          {result.findings.length > 0 ? (
            <ResultTable columns={columns} data={result.findings} />
          ) : (
            <div className="p-4 bg-emerald-50 text-emerald-800 rounded-lg text-sm">
              ✅ No high-risk phishing patterns or suspicious deceptive indicators detected in this URL.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

