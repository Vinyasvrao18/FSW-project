import React, { useState, useEffect } from 'react';
import { securityApi } from '../api';
import { StatusBadge } from '../components/StatusBadge';
import { ResultTable } from '../components/ResultTable';
import { EmptyState } from '../components/EmptyState';

const PAGE_SIZE = 10;

export default function History() {
  const [history, setHistory] = useState([]);
  const [filterModule, setFilterModule] = useState('');
  const [loading, setLoading] = useState(true);

  const [page, setPage] = useState(1);
  const [errorMessage, setErrorMessage] = useState('');

  useEffect(() => {
    let active = true;
    async function loadPage() {
      setLoading(true);
      setErrorMessage('');
      const parameters = new URLSearchParams({
        limit: PAGE_SIZE + 1,
        offset: (page - 1) * PAGE_SIZE
      });
      if (filterModule) parameters.set('module', filterModule);
      try {
        const response = await securityApi.getHistory('?' + parameters);
        if (active) setHistory(response.data);
      } catch (error) {
        if (active) setErrorMessage(error.message);
      } finally {
        if (active) setLoading(false);
      }
    }

    loadPage();
    return () => { active = false; };
  }, [filterModule, page]);

  const columns = [
    {
      header: 'Module',
      accessor: 'module',
      render: (record) => <span className="font-bold text-xs uppercase text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded">{record.module}</span>
    },
    {
      header: 'Target',
      accessor: 'target',
      render: (record) => <span className="font-mono text-xs text-slate-800 truncate max-w-xs block" title={record.target}>{record.target}</span>
    },
    {
      header: 'Status',
      accessor: 'status',
      render: (record) => <StatusBadge status={record.status} />
    },
    {
      header: 'Score',
      accessor: 'score',
      render: (record) => <span>{record.score !== null ? `${record.score}/100` : '-'}</span>
    },
    {
      header: 'Timestamp',
      accessor: 'created_at',
      render: (record) => <span className="text-xs text-slate-500">{new Date(record.created_at).toLocaleString()}</span>
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
          <label htmlFor="module-filter" className="text-xs font-semibold text-slate-500">Filter by module</label>
          <select id="module-filter"
            value={filterModule}
            onChange={(event) => {
              setFilterModule(event.target.value);
              setPage(1);
            }}
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
        ) : errorMessage ? (
          <p role="alert">{errorMessage}</p>
        ) : history.length > 0 ? (
          <ResultTable columns={columns} data={history.slice(0, PAGE_SIZE)} />
        ) : (
          <EmptyState title="No history found" description="No scan events recorded matching your filter." />
        )}
        {!loading && !errorMessage && (page > 1 || history.length > PAGE_SIZE) && (
          <nav aria-label="History pages" className="pagination">
            <button disabled={page === 1} onClick={() => setPage(page - 1)}>Previous</button>
            <span>Page {page}</span>
            <button disabled={history.length <= PAGE_SIZE} onClick={() => setPage(page + 1)}>Next</button>
          </nav>
        )}
      </div>
    </div>
  );
}
