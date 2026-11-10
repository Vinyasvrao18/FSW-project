import React from 'react';

export function StatusBadge({ status }) {
  const getStyle = () => {
    switch (status?.toUpperCase()) {
      case 'STRONG':
      case 'VERIFIED':
      case 'SAFE':
        return 'bg-emerald-100 text-emerald-800 border-emerald-300';
      case 'MODERATE':
      case 'SUSPICIOUS':
      case 'RECORDED':
        return 'bg-amber-100 text-amber-800 border-amber-300';
      case 'WEAK':
      case 'HIGH_RISK':
      case 'TAMPERED':
        return 'bg-rose-100 text-rose-800 border-rose-300';
      default:
        return 'bg-slate-100 text-slate-800 border-slate-300';
    }
  };

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${getStyle()}`}>
      {status || 'UNKNOWN'}
    </span>
  );
}

