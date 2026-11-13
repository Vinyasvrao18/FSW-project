import React, { useEffect, useState } from 'react';
import { securityApi } from '../api';
import { ResultTable } from '../components/ResultTable';
import { Alert } from '../components/Alert';

export default function HeaderShield() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);   // null = not scanned yet
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [approvedHosts, setApprovedHosts] = useState([]);

  useEffect(() => {
    let active = true;
    securityApi.getApprovedHeaderHosts()
      .then(response => { if (active) setApprovedHosts(response.data); })
      .catch(error => { if (active) setError(error.message); });
    return () => { active = false; };
  }, []);

  async function handleScan(event) {
    event.preventDefault();
    setError('');
    setResult(null);
    setLoading(true);

    try {
      const response = await securityApi.scanHeaders(url);
      setResult(response.data);
    } catch (error) {
      setError(error.message || 'Scan failed. Please try again.');
    } finally {
      setLoading(false);
    }
  }

  function handleReset() {
    setResult(null);
    setError('');
    setUrl('');
  }

  const columns = [
    {
      header: 'Header',
      accessor: 'header',
      render: (row) => (
        // Show header names in monospace so they are easy to read
        <span className="font-mono text-xs font-semibold text-slate-700">
          {row.header}
        </span>
      )
    },
    {
      header: 'Status',
      accessor: 'status',
      render: (row) => {
        // Status is shown as a text label AND colour — never colour alone
        const isPresent = row.status === 'present';
        return (
          <span
            className={
              isPresent
                ? 'inline-block px-2 py-0.5 rounded text-xs font-semibold bg-emerald-100 text-emerald-800'
                : 'inline-block px-2 py-0.5 rounded text-xs font-semibold bg-rose-100 text-rose-800'
            }
          >
            {isPresent ? 'Present' : 'Missing'}
          </span>
        );
      }
    },
    {
      header: 'Purpose',
      accessor: 'purpose',
      render: (row) => (
        <span className="text-sm text-slate-600">{row.purpose}</span>
      )
    },
    {
      header: 'Recommendation',
      accessor: 'recommendation',
      render: (row) => (
        // Show a dash when present and no recommendation is needed
        <span className="text-sm text-slate-600">
          {row.recommendation || '—'}
        </span>
      )
    }
  ];

  return (
    <div className="space-y-6 max-w-4xl">

      <div>
        <h1 className="text-2xl font-bold text-slate-900">HeaderShield</h1>
        <p className="text-sm text-slate-500 mt-1">
          Check which browser security headers a website sends.
        </p>
      </div>

      <div className="bg-amber-50 border border-amber-200 text-amber-800 text-sm rounded-lg px-4 py-3">
        This reviews response headers only. It is not a full security audit.
      </div>

      <Alert message={error} onClose={() => setError('')} />

      {!result && (
        <form onSubmit={handleScan} className="bg-white border border-slate-200 rounded-xl p-5 space-y-4">
          <div>
            <label
              htmlFor="website-url"
              className="block text-sm font-medium text-slate-700 mb-1"
            >
              Website URL
            </label>
            <input
              id="website-url"
              type="url"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://example.com"
              required
              disabled={loading}
              className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-slate-50"
            />
            <p className="mt-1.5 text-xs text-slate-500">
              Choose an approved hostname or enter a full URL on that host.
            </p>
            <div className="mt-2 flex flex-wrap gap-2">
              {approvedHosts.map(hostname => (
                <button type="button" key={hostname} disabled={loading}
                  className="rounded border px-2 py-1 text-sm text-indigo-700"
                  onClick={() => { setUrl('https://' + hostname); setError(''); }}>
                  {hostname}
                </button>
              ))}
            </div>
          </div>

          <button
            type="submit"
            disabled={loading || !url}
            className="px-5 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-sm font-semibold rounded-lg transition-colors"
          >
            {loading ? 'Checking response headers…' : 'Scan headers'}
          </button>
        </form>
      )}

      {result && (
        <div className="bg-white border border-slate-200 rounded-xl p-5 space-y-5">

          <div className="pb-4 border-b border-slate-100 space-y-1">
            <p className="text-xs uppercase font-semibold text-slate-400 tracking-wide">
              Target scanned
            </p>
            <p className="font-mono text-sm font-semibold text-slate-800 break-all">
              {result.target}
            </p>
            <p className="text-sm text-slate-500">
              HTTP status: <span className="font-mono font-semibold text-slate-700">{result.httpStatus}</span>
            </p>
          </div>

          <div>
            <h2 className="font-semibold">Weighted header score</h2>
            <p>{result.score}/100 · {result.status}</p>
            <p className="text-sm text-slate-500">Based on six headers, including X-Frame-Options.</p>
          </div>

          <div>
            <p className="text-sm font-semibold text-slate-700 mb-2">Policy checks</p>
            <div className="flex flex-wrap gap-4 text-sm">
              <span className="text-slate-600">
                Checked: <strong>{result.summary.checked}</strong>
              </span>
              <span className="text-emerald-700">
                Present: <strong>{result.summary.present}</strong>
              </span>
              <span className="text-rose-700">
                Missing: <strong>{result.summary.missing}</strong>
              </span>
            </div>
          </div>

          <div>
            <p className="text-sm font-semibold text-slate-700 mb-2">Header findings</p>
            <ResultTable columns={columns} data={result.findings} />
          </div>

          <p className="text-xs text-slate-500 italic border-t border-slate-100 pt-3">
            {result.limitations}
          </p>

          <button
            type="button"
            onClick={handleReset}
            className="px-4 py-2 border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 text-sm font-medium rounded-lg transition-colors"
          >
            Run another scan
          </button>
        </div>
      )}
    </div>
  );
}
