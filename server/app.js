const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const cors = require('cors');

const authRoutes = require('./auth');
const headerShieldRoutes = require('./headershield');
const phishCheckRoutes = require('./phishcheck');
const fileIntegrityRoutes = require('./fileintegrity');
const historyRoutes = require('./history');
const { ok, fail } = require('./helpers');

const app = express();

const SESSION_SECRET = process.env.SESSION_SECRET || 'authguard_dev_secret_key_1234567890';
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173';

// 1. Security Headers via Helmet
app.use(helmet());

// 2. CORS setup
app.use(cors({
  origin: CLIENT_ORIGIN,
  credentials: true
}));

// 3. Body & Cookie Parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(SESSION_SECRET));

// 4. Rate Limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { success: false, message: 'Too many requests from this IP, please try again later.' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  message: { success: false, message: 'Too many authentication attempts, please try again later.' }
});

app.use('/api/', generalLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// 5. Session Setup
app.use(session({
  name: 'authguard.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// 6. Built-in Session-based CSRF Protection
// Issues and validates random cryptographic tokens per user session
app.get('/api/csrf-token', (req, res) => {
  if (!req.session.csrfSecret) {
    req.session.csrfSecret = crypto.randomBytes(32).toString('hex');
  }
  return ok(res, { csrfToken: req.session.csrfSecret }, 'CSRF token issued');
});

// CSRF validation middleware for mutating requests
const csrfProtection = (req, res, next) => {
  // Safe HTTP methods do not mutate state
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const clientToken = req.headers['csrf-token'] || req.headers['x-csrf-token'] || req.body?._csrf;
  const sessionToken = req.session?.csrfSecret;

  if (!clientToken || !sessionToken || clientToken !== sessionToken) {
    return fail(res, 'Invalid or missing CSRF token', 403);
  }

  next();
};

app.use('/api', csrfProtection);

// 7. Route Handlers
app.use('/api/auth', authRoutes);
app.use('/api/headershield', headerShieldRoutes);
app.use('/api/phishcheck', phishCheckRoutes);
app.use('/api/fileintegrity', fileIntegrityRoutes);
app.use('/api/history', historyRoutes);

// Health check
app.get('/api/health', (req, res) => ok(res, { status: 'healthy', time: new Date() }, 'API online'));

// 8. 404 Handler
app.use((req, res) => {
  return fail(res, 'Endpoint not found', 404);
});

// 9. Centralized Error Handler
app.use((err, req, res, next) => {
  console.error('[Error]', err);
  return fail(res, err.message || 'Internal server error', err.status || 500);
});

// Start server if executed directly
if (process.env.NODE_ENV !== 'test') {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`🛡️  AuthGuard-X Server listening on port ${PORT}`);
  });
}

module.exports = app;
