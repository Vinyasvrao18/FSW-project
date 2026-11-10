import React, { useEffect, useState } from 'react';
import { securityApi } from '../api';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState } from '../components/EmptyState';
import { Link } from 'react-router-dom';

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    securityApi.getDashboardSummary()
      .then(res => setSummary(res.data))
      .catch(err => console.error(err))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div className="p-8 text-center text-slate-500">Loading security metrics...</div>;
  }

  const statCards = [
    { title: 'Total Scans', value: summary?.totalScans || 0, icon: '📊', color: 'text-indigo-600' },
    { title: 'Average Score', value: `${summary?.averageScore || 0}%`, icon: '🛡️', color: 'text-emerald-600' },
    { title: 'High Alerts', value: summary?.highAlertsCount || 0, icon: '⚠️', color: 'text-rose-600' },
    { title: 'Headers Evaluated', value: summary?.headerShieldCount || 0, icon: '🌐', color: 'text-blue-600' }
  ];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Security Dashboard</h1>
          <p className="text-sm text-slate-500">Real-time posture and threat overview</p>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((card, idx) => (
          <div key={idx} className="p-5 bg-white rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
            <div>
              <p className="text-xs uppercase font-bold tracking-wider text-slate-400">{card.title}</p>
              <p className={`text-2xl font-black mt-1 ${card.color}`}>{card.value}</p>
            </div>
            <div className="text-3xl">{card.icon}</div>
          </div>
        ))}
      </div>

      {/* Quick Launch Buttons */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link to="/headershield" className="p-4 bg-white hover:border-indigo-400 border border-slate-200 rounded-xl transition shadow-sm block">
          <h3 className="font-semibold text-slate-800">HeaderShield</h3>
          <p className="text-xs text-slate-500 mt-1">Audit HTTP security response headers and identify missing policies.</p>
        </Link>
        <Link to="/phishcheck" className="p-4 bg-white hover:border-indigo-400 border border-slate-200 rounded-xl transition shadow-sm block">
          <h3 className="font-semibold text-slate-800">PhishCheck</h3>
          <p className="text-xs text-slate-500 mt-1">Evaluate URLs against heuristic indicators and known risk vectors.</p>
        </Link>
        <Link to="/fileintegrity" className="p-4 bg-white hover:border-indigo-400 border border-slate-200 rounded-xl transition shadow-sm block">
          <h3 className="font-semibold text-slate-800">FileIntegrity</h3>
          <p className="text-xs text-slate-500 mt-1">Calculate SHA-256 hashes, set baselines and detect tampering.</p>
        </Link>
      </div>

      {/* Recent Activity */}
      <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
        <h2 className="text-lg font-bold text-slate-900 mb-4">Recent Scans</h2>
        {summary?.recentScans?.length > 0 ? (
          <div className="divide-y divide-slate-100">
            {summary.recentScans.map((scan) => (
              <div key={scan.id} className="py-3 flex items-center justify-between">
                <div>
                  <span className="text-xs font-semibold uppercase text-slate-400 mr-2">{scan.module}</span>
                  <span className="font-mono text-sm text-slate-800">{scan.target}</span>
                </div>
                <div className="flex items-center space-x-3">
                  <StatusBadge status={scan.status} />
                  <span className="text-xs text-slate-400">{new Date(scan.created_at).toLocaleDateString()}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState title="No recent activity" description="Launch a scanner above to begin monitoring." />
        )}
      </div>
    </div>
  );
}

