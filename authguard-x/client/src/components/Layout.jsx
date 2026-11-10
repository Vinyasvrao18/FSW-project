import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { authApi } from '../api';

export function Layout({ children, user, setUser }) {
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      await authApi.logout();
      setUser(null);
      navigate('/login');
    } catch (e) {
      console.error('Logout error', e);
    }
  };

  const navItems = [
    { label: 'Dashboard', path: '/dashboard' },
    { label: 'HeaderShield', path: '/headershield' },
    { label: 'PhishCheck', path: '/phishcheck' },
    { label: 'FileIntegrity', path: '/fileintegrity' },
    { label: 'History', path: '/history' }
  ];

  return (
    <div className="min-h-screen bg-slate-100 flex flex-col font-sans">
      {/* Top Navbar */}
      <header className="bg-slate-900 text-white shadow-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <span className="text-xl font-black tracking-wide text-indigo-400">🛡️ AuthGuard-X</span>
          </div>

          <nav className="flex space-x-1 sm:space-x-4">
            {navItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                    isActive ? 'bg-indigo-600 text-white' : 'text-slate-300 hover:bg-slate-800'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>

          <div className="flex items-center space-x-4">
            {user ? (
              <div className="flex items-center space-x-3">
                <span className="text-sm text-slate-300 hidden md:inline">{user.username}</span>
                <button
                  onClick={handleLogout}
                  className="text-xs bg-slate-800 hover:bg-rose-700 text-white px-3 py-1.5 rounded transition"
                >
                  Logout
                </button>
              </div>
            ) : (
              <NavLink
                to="/login"
                className="text-sm bg-indigo-600 hover:bg-indigo-700 text-white px-3 py-1.5 rounded"
              >
                Sign In
              </NavLink>
            )}
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
        {children}
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-slate-200 py-4 text-center text-xs text-slate-500">
        AuthGuard-X Security Suite &copy; {new Date().getFullYear()}
      </footer>
    </div>
  );
}

