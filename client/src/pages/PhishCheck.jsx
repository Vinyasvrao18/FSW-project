import React, { useState } from 'react';
import { securityApi } from '../api';
import { Alert } from '../components/Alert';

export default function PhishCheck() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);   // null = not analysed yet
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleAnalyse(event) {
    event.preventDefault();
    setError('');
    setResult(null);
    setLoading(true);

    try {
      // checkPhishingUrl calls /phishcheck/check which the server maps to /analyze
      const response = await securityApi.checkPhishingUrl(url);
      setResult(response.data);
    } catch (error) {
      setError(error.message || 'Analysis failed. Please try again.');
    } finally {
      setLoading(false);
    }
  }

  function handleReset() {
    setResult(null);
    setError('');
    setUrl('');
  }

  // Status is ALWAYS shown as text. Colour is support only.
  function riskColour(level) {
    switch ((level || '').toLowerCase()) {
      case 'low':       return 'bg-emerald-100 text-emerald-800';
      case 'medium':    return 'bg-amber-100 text-amber-800';
      case 'high':      return 'bg-rose-100 text-rose-800';
      case 'very high': return 'bg-rose-200 text-rose-900';
      default:          return 'bg-slate-100 text-slate-700';
    }
  }

  function riskLabel(level) {
    switch ((level || '').toLowerCase()) {
      case 'low':       return 'Low';
      case 'medium':    return 'Medium';
      case 'high':      return 'High';
      case 'very high': return 'Very high';
      default:          return level || 'Unknown';
    }
  }

  return (
    <div className="space-y-6 max-w-4xl">

      <div>
        <h1 className="text-2xl font-bold text-slate-900">PhishCheck</h1>
        <p className="text-sm text-slate-500 mt-1">
          Inspect a URL for patterns commonly associated with phishing.
        </p>
      </div>

      <div className="bg-amber-50 border border-amber-200 text-amber-800 text-sm rounded-lg px-4 py-3">
        PhishCheck reads the URL without visiting it. A word like “login” contributes to the score even on a legitimate site.
        The link is never opened.
      </div>

      <Alert message={error} onClose={() => setError('')} />

      {!result && (
        <form onSubmit={handleAnalyse} className="bg-white border border-slate-200 rounded-xl p-5 space-y-4">
          <div>
            <label
              htmlFor="url-to-analyse"
              className="block text-sm font-medium text-slate-700 mb-1"
            >
              URL to analyse
            </label>
            <input
              id="url-to-analyse"
              type="text"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://example.com/login"
              required
              disabled={loading}
              className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-slate-50"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !url}
            className="px-5 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-sm font-semibold rounded-lg transition-colors"
          >
            {loading ? 'Analysing URL…' : 'Analyse URL'}
          </button>
        </form>
      )}

      {result && (
        <div className="bg-white border border-slate-200 rounded-xl p-5 space-y-5">

          <div className="pb-4 border-b border-slate-100 space-y-3">

            <div className="flex items-center gap-3 flex-wrap">
              <span
                className={`inline-block px-3 py-1 rounded-full text-sm font-semibold ${riskColour(result.riskLevel)}`}
              >
                {riskLabel(result.riskLevel)}
              </span>
              <span className="text-sm text-slate-600">
                Score: <strong className="text-slate-800">{result.score} / 100</strong>
              </span>
            </div>

            <div>
              <span className="text-xs uppercase font-semibold text-slate-400 tracking-wide">
                Host
              </span>
              <p className="font-mono text-sm text-slate-800 mt-0.5 break-all">
                {result.hostname}
              </p>
            </div>
          </div>

          <div>
            <p className="text-sm font-semibold text-slate-700 mb-3">Triggered rules</p>

            {result.findings && result.findings.length > 0 ? (
              <ul className="space-y-2">
                {result.findings.map((finding) => (
                  <li
                    key={finding.ruleId}
                    className="border border-slate-200 rounded-lg px-4 py-3 text-sm space-y-1"
                  >
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <span className="font-semibold text-slate-800">
                        {finding.label}
                      </span>
                      <span className="text-xs font-mono text-slate-500">
                        +{finding.weight} pts
                      </span>
                    </div>
                    <p className="text-slate-600">{finding.explanation}</p>
                  </li>
                ))}
              </ul>
            ) : (
              // No rules triggered — still show the disclaimer
              <div className="border border-slate-200 rounded-lg px-4 py-4 text-sm text-slate-600">
                No suspicious patterns found.
              </div>
            )}
          </div>

          <p className="text-xs text-slate-500 italic border-t border-slate-100 pt-3">
            {result.disclaimer}
          </p>

          <button
            type="button"
            onClick={handleReset}
            className="px-4 py-2 border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 text-sm font-medium rounded-lg transition-colors"
          >
            Analyse another URL
          </button>
        </div>
      )}
    </div>
  );
}
