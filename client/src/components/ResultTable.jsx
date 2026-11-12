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
            {columns.map((column, index) => (
              <th key={index} className="px-4 py-3 font-medium text-slate-600">
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-200 bg-white">
          {data.map((row, rowIndex) => (
            <tr key={rowIndex} className="hover:bg-slate-50 transition-colors">
              {columns.map((column, columnIndex) => (
                <td key={columnIndex} className="px-4 py-3 text-slate-700">
                  {column.render ? column.render(row) : row[column.accessor]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
