import React, { useState, useEffect } from 'react';
import { securityApi } from '../api';
import { StatusBadge } from '../components/StatusBadge';
import { ResultTable } from '../components/ResultTable';
import { EmptyState } from '../components/EmptyState';

export default function History() {
  const [history, setHistory] = useState([]);
  const [filterModule, setFilterModule] = useState('');
  const [loading, setLoading] = useState(true);

  const fetchHistory = (module = '') => {
    setLoading(true);
    const query = module ? `?module=${module}` : '';
    securityApi.getHistory(query)
      .then(res => setHistory(res.data))
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchHistory(filterModule);
  }, [filterModule]);

  const columns = [
    {
      header: 'Module',
      accessor: 'module',
      render: (r) => <span className="font-bold text-xs uppercase text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded">{r.module}</span>
    },
    {
      header: 'Target',
      accessor: 'target',
      render: (r) => <span className="font-mono text-xs text-slate-800 truncate max-w-xs block" title={r.target}>{r.target}</span>
    },
    {
      header: 'Status',
      accessor: 'status',
      render: (r) => <StatusBadge status={r.status} />
    },
    {
      header: 'Score',
      accessor: 'score',
      render: (r) => <span>{r.score !== null ? `${r.score}/100` : '-'}</span>
    },
    {
      header: 'Timestamp',
      accessor: 'created_at',
      render: (r) => <span className="text-xs text-slate-500">{new Date(r.created_at).toLocaleString()}</span>
    }
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Audit & Scan History</h1>
          <p className="text-sm text-slate-500">Historical records of all triggered security scans and checks.</p>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-xs font-semibold text-slate-500">Filter by:</span>
          <select
            value={filterModule}
            onChange={(e) => setFilterModule(e.target.value)}
            className="text-sm px-3 py-1.5 border border-slate-300 rounded-md bg-white focus:ring-indigo-500"
          >
            <option value="">All Modules</option>
            <option value="HeaderShield">HeaderShield</option>
            <option value="PhishCheck">PhishCheck</option>
            <option value="FileIntegrity">FileIntegrity</option>
          </select>
        </div>
      </div>

      <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
        {loading ? (
          <div className="p-8 text-center text-slate-500">Loading history logs...</div>
        ) : history.length > 0 ? (
          <ResultTable columns={columns} data={history} />
        ) : (
          <EmptyState title="No history found" description="No scan events recorded matching your filter." />
        )}
      </div>
    </div>
  );
}

