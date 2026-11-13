import React from 'react';

export function Alert({ message, onClose }) {
  if (!message) return null;

  return (
    <div role="alert" className="flex items-center justify-between p-3.5 mb-4 rounded-lg border text-sm bg-rose-50 border-rose-200 text-rose-800">
      <span>{message}</span>
      {onClose && (
        <button
          aria-label="Dismiss error"
          onClick={onClose}
          className="ml-3 font-bold opacity-60 hover:opacity-100 transition-opacity"
        >
          ✕
        </button>
      )}
    </div>
  );
}
