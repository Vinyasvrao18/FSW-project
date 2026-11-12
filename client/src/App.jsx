import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { authenticationApi } from './api';
import { Layout } from './components/Layout';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import HeaderShield from './pages/HeaderShield';
import PhishCheck from './pages/PhishCheck';
import FileIntegrity from './pages/FileIntegrity';
import History from './pages/History';

export default function App() {
  const [user, setUser] = useState(null);
  const [checkingAuthentication, setCheckingAuthentication] = useState(true);

  useEffect(() => {
    authenticationApi.me()
      .then(response => setUser(response.data))
      .catch(() => setUser(null))
      .finally(() => setCheckingAuthentication(false));
  }, []);

  if (checkingAuthentication) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-100 text-slate-500">
        Loading AuthGuard-X...
      </div>
    );
  }

  return (
    <BrowserRouter>
      <Layout user={user} setUser={setUser}>
        <Routes>
          <Route path="/login" element={!user ? <Login setUser={setUser} /> : <Navigate to="/dashboard" />} />
          <Route path="/register" element={!user ? <Register setUser={setUser} /> : <Navigate to="/dashboard" />} />
          <Route path="/dashboard" element={user ? <Dashboard /> : <Navigate to="/login" />} />
          <Route path="/headershield" element={user ? <HeaderShield /> : <Navigate to="/login" />} />
          <Route path="/phishcheck" element={user ? <PhishCheck /> : <Navigate to="/login" />} />
          <Route path="/fileintegrity" element={user ? <FileIntegrity /> : <Navigate to="/login" />} />
          <Route path="/history" element={user ? <History /> : <Navigate to="/login" />} />
          <Route path="*" element={<Navigate to={user ? "/dashboard" : "/login"} />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}
