import React from 'react';

export function ResultTable({ columns, data }) {
  if (!data || data.length === 0) {
    return <div className="text-center py-4 text-slate-500 text-sm">No results to display.</div>;
  }

  return (
    <div className="overflow-x-auto w-full border border-slate-200 rounded-lg shadow-sm">
      <table className="min-w-full divide-y divide-slate-200 text-sm text-left">
        <thead className="bg-slate-50">
          <tr>
            {columns.map((col, idx) => (
              <th key={idx} className="px-4 py-3 font-medium text-slate-600">
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-200 bg-white">
          {data.map((row, rowIdx) => (
            <tr key={rowIdx} className="hover:bg-slate-50 transition-colors">
              {columns.map((col, colIdx) => (
                <td key={colIdx} className="px-4 py-3 text-slate-700">
                  {col.render ? col.render(row) : row[col.accessor]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

