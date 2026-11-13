import React, { useState, useEffect } from 'react';
import { securityApi } from '../api';
import { StatusBadge } from '../components/StatusBadge';
import { ResultTable } from '../components/ResultTable';
import { Alert } from '../components/Alert';

export default function FileIntegrity() {
  const [file, setFile] = useState(null);
  const [expectedHash, setExpectedHash] = useState('');
  const [result, setResult] = useState(null);
  const [baselines, setBaselines] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const loadBaselines = () => {
    securityApi.getFileBaselines()
      .then(response => setBaselines(response.data))
      .catch(console.error);
  };

  useEffect(() => {
    loadBaselines();
  }, []);

  const handleUpload = async (event) => {
    event.preventDefault();
    if (!file) return;

    setError('');
    setLoading(true);
    setResult(null);

    const formData = new FormData();
    formData.append('file', file);
    if (expectedHash) formData.append('expectedHash', expectedHash);

    try {
      const response = await securityApi.checkFileIntegrity(formData);
      setResult(response.data);
      loadBaselines();
    } catch (error) {
      setError(error.message || 'Integrity check failed');
    } finally {
      setLoading(false);
    }
  };

  const baselineColumns = [
    { header: 'Filename', accessor: 'filename', render: (record) => <span className="font-semibold">{record.filename}</span> },
    { header: 'SHA-256 Checksum', accessor: 'sha256', render: (record) => <span className="font-mono text-xs">{record.sha256}</span> },
    { header: 'Size', accessor: 'file_size', render: (record) => <span>{(record.file_size / 1024).toFixed(1)} KB</span> },
    { header: 'Recorded At', accessor: 'created_at', render: (record) => <span className="text-xs text-slate-500">{new Date(record.created_at).toLocaleString()}</span> }
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">FileIntegrity</h1>
        <p className="text-sm text-slate-500">Calculate cryptographic SHA-256 hashes, compare baselines and detect tampering.</p>
      </div>

      <Alert message={error} onClose={() => setError('')} />

      <form onSubmit={handleUpload} className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label htmlFor="upload-file" className="block text-sm font-medium text-slate-700 mb-1">Upload Target File</label>
            <input
              id="upload-file"
              disabled={loading}
              type="file"
              onChange={(event) => {
                setFile(event.target.files[0] || null);
                setResult(null);
                setError('');
              }}
              required
              className="w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-indigo-50 file:text-indigo-700 hover:file:bg-indigo-100"
            />
            {file && (
              <p className="mt-3 break-all text-sm text-slate-600" aria-live="polite">
                {file.name} · {(file.size / 1024).toFixed(2)} KB
              </p>
            )}
          </div>
          <div>
            <label htmlFor="expected-hash" className="block text-sm font-medium text-slate-700 mb-1">Expected SHA-256 (Optional comparison)</label>
            <input
              id="expected-hash"
              type="text"
              value={expectedHash}
              onChange={(event) => setExpectedHash(event.target.value)}
              placeholder="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
              className="w-full px-3 py-2 border border-slate-300 rounded-md font-mono text-xs focus:ring-indigo-500 focus:border-indigo-500"
            />
          </div>
        </div>

        <button
          type="submit"
          disabled={loading || !file}
          className="px-6 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-medium rounded-lg shadow-sm transition disabled:opacity-50 text-sm"
        >
          {loading ? 'Computing SHA-256...' : 'Analyze File'}
        </button>
      </form>

      {result && (
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-3">
          <div className="flex justify-between items-center">
            <h3 className="font-semibold text-slate-800">Analysis Output</h3>
            <StatusBadge status={result.status} />
          </div>
          <div className="bg-slate-50 p-4 rounded-lg break-all font-mono text-xs space-y-2 text-slate-700">
            <div><span className="font-bold text-slate-500">File:</span> {result.filename} ({(result.fileSize / 1024).toFixed(1)} KB)</div>
            <div><span className="font-bold text-slate-500">Computed SHA-256:</span> {result.calculatedHash}</div>
            {result.expectedHash && (
              <div><span className="font-bold text-slate-500">Expected SHA-256:</span> {result.expectedHash}</div>
            )}
            {result.match !== null && (
              <div className={`font-bold mt-2 ${result.match ? 'text-emerald-600' : 'text-rose-600'}`}>
                {result.match ? '✅ Checksum matches baseline exactly!' : '❌ HASH MISMATCH: Possible tampering detected!'}
              </div>
            )}
          </div>
        </div>
      )}

      <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
        <h3 className="font-semibold text-slate-800">Recorded File Baselines</h3>
        <ResultTable columns={baselineColumns} data={baselines} />
      </div>
    </div>
  );
}
