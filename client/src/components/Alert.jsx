import React from 'react';

export function Alert({ type = 'info', message, onClose }) {
  if (!message) return null;

  const styles = {
    info: 'bg-blue-50 border-blue-200 text-blue-800',
    success: 'bg-emerald-50 border-emerald-200 text-emerald-800',
    warning: 'bg-amber-50 border-amber-200 text-amber-800',
    error: 'bg-rose-50 border-rose-200 text-rose-800'
  }[type] || 'bg-slate-50 border-slate-200 text-slate-800';

  return (
    <div className={`flex items-center justify-between p-3.5 mb-4 rounded-lg border text-sm ${styles}`}>
      <span>{message}</span>
      {onClose && (
        <button
          onClick={onClose}
          className="ml-3 font-bold opacity-60 hover:opacity-100 transition-opacity"
        >
          ✕
        </button>
      )}
    </div>
  );
}
