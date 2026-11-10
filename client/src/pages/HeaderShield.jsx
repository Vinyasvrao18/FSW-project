import React, { useState } from 'react';
import { securityApi } from '../api';
import { ResultTable } from '../components/ResultTable';
import { StatusBadge } from '../components/StatusBadge';
import { Alert } from '../components/Alert';

export default function HeaderShield() {
  const [targetUrl, setTargetUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleScan = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    setResult(null);

    try {
      const res = await securityApi.scanHeaders(targetUrl);
      setResult(res.data);
    } catch (err) {
      setError(err.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const columns = [
    { header: 'Security Header', accessor: 'header', render: (r) => <span className="font-mono text-xs font-semibold">{r.header}</span> },
    {
      header: 'Status',
      accessor: 'present',
      render: (r) => (
        <span className={`px-2 py-0.5 rounded text-xs font-bold ${r.present ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'}`}>
          {r.present ? 'FOUND' : 'MISSING'}
        </span>
      )
    },
    { header: 'Weight', accessor: 'weight', render: (r) => <span>{r.weight} pts</span> },
    { header: 'Description', accessor: 'description' },
    {
      header: 'Observed Value',
      accessor: 'value',
      render: (r) => (
        <span className="font-mono text-xs text-slate-600 truncate max-w-xs block" title={r.value || ''}>
          {r.value || '-'}
        </span>
      )
    }
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">HeaderShield</h1>
        <p className="text-sm text-slate-500">Analyze HTTP response headers and ensure defense-in-depth compliance.</p>
      </div>

      <Alert type="error" message={error} onClose={() => setError('')} />

      <form onSubmit={handleScan} className="flex gap-3 bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
        <input
          type="url"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          placeholder="https://example.com"
          required
          className="flex-1 px-4 py-2 border border-slate-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500 text-sm"
        />
        <button
          type="submit"
          disabled={loading}
          className="px-6 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-medium rounded-lg shadow-sm transition disabled:opacity-50 text-sm"
        >
          {loading ? 'Scanning...' : 'Inspect Headers'}
        </button>
      </form>

      {result && (
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-100 pb-4">
            <div>
              <p className="text-xs uppercase font-bold text-slate-400">Target Analyzed</p>
              <p className="font-mono text-base font-semibold text-slate-800">{result.targetUrl}</p>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <p className="text-xs uppercase font-bold text-slate-400">Security Score</p>
                <p className="text-2xl font-black text-indigo-600">{result.score}/100</p>
              </div>
              <StatusBadge status={result.status} />
            </div>
          </div>

          <h3 className="font-semibold text-slate-800">Evaluated Headers</h3>
          <ResultTable columns={columns} data={result.checks} />
        </div>
      )}
    </div>
  );
}

