import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { authenticationApi } from '../api';
import { Alert } from '../components/Alert';

export default function Register({ setUser }) {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setLoading(true);
    try {
      const response = await authenticationApi.register({ username, email, password });
      setUser(response.data);
      navigate('/dashboard');
    } catch (error) {
      setError(error.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="account-panel">
      <h1 className="account-title">Create an Account</h1>
      <Alert type="error" message={error} onClose={() => setError('')} />
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="text" className="block text-sm font-medium text-slate-700">Username</label>
          <input
            id="text"
            autoComplete="username"
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            required
            className="mt-1 block w-full px-3 py-2 border border-slate-300 rounded-md focus:ring-indigo-500 focus:border-indigo-500"
          />
        </div>
        <div>
          <label htmlFor="email" className="block text-sm font-medium text-slate-700">Email Address</label>
          <input
            id="email"
            autoComplete="email"
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
            className="mt-1 block w-full px-3 py-2 border border-slate-300 rounded-md focus:ring-indigo-500 focus:border-indigo-500"
          />
        </div>
        <div>
          <label htmlFor="password" className="block text-sm font-medium text-slate-700">Password (min 8 characters)</label>
          <input
            id="password"
            autoComplete="new-password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
            minLength={8}
            className="mt-1 block w-full px-3 py-2 border border-slate-300 rounded-md focus:ring-indigo-500 focus:border-indigo-500"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="w-full py-2.5 px-4 bg-indigo-600 hover:bg-indigo-700 text-white font-medium rounded-md shadow-sm transition disabled:opacity-50"
        >
          {loading ? 'Creating account...' : 'Register'}
        </button>
      </form>
      <div className="text-center text-sm text-slate-500 mt-4">
        Already have an account? <Link to="/login" className="text-indigo-600 font-semibold hover:underline">Sign In</Link>
      </div>
    </div>
  );
}
