import React from 'react';

export function EmptyState({ title = 'No data found', description = 'Try performing an action to see data here.', action }) {
  return (
    <div className="flex flex-col items-center justify-center p-8 text-center bg-slate-50 border border-dashed border-slate-300 rounded-xl">
      <div className="w-12 h-12 rounded-full bg-slate-200 flex items-center justify-center text-slate-500 mb-3">
        🔍
      </div>
      <h3 className="text-base font-semibold text-slate-800">{title}</h3>
      <p className="text-sm text-slate-500 max-w-sm mt-1 mb-4">{description}</p>
      {action && <div>{action}</div>}
    </div>
  );
}
