const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('./db');
const { ok, fail, isValidEmail } = require('./helpers');

const router = express.Router();

// Register
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return fail(res, 'Username, email, and password are required', 422);
  }

  if (!isValidEmail(email)) {
    return fail(res, 'Invalid email format', 422);
  }

  if (password.length < 8) {
    return fail(res, 'Password must be at least 8 characters long', 422);
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    db.run(
      `INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)`,
      [username.trim(), email.trim().toLowerCase(), passwordHash],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return fail(res, 'Username or email already exists', 409);
          }
          return fail(res, 'Failed to create user', 500);
        }

        req.session.userId = this.lastID;
        return ok(res, { id: this.lastID, username, email }, 'Registered successfully', 201);
      }
    );
  } catch (error) {
    return fail(res, 'Internal registration error', 500);
  }
});

// Login
router.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return fail(res, 'Email and password are required', 422);
  }

  db.get(
    `SELECT * FROM users WHERE email = ?`,
    [email.trim().toLowerCase()],
    async (err, user) => {
      if (err) return fail(res, 'Database error', 500);
      if (!user) return fail(res, 'Invalid email or password', 401);

      const isMatch = await bcrypt.compare(password, user.password_hash);
      if (!isMatch) return fail(res, 'Invalid email or password', 401);

      req.session.userId = user.id;
      return ok(res, { id: user.id, username: user.username, email: user.email }, 'Logged in successfully');
    }
  );
});

// Logout
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return fail(res, 'Logout failed', 500);
    res.clearCookie('connect.sid');
    return ok(res, {}, 'Logged out successfully');
  });
});

// Current user profile
router.get('/me', (req, res) => {
  if (!req.session || !req.session.userId) {
    return fail(res, 'Not authenticated', 401);
  }

  db.get(
    `SELECT id, username, email, created_at FROM users WHERE id = ?`,
    [req.session.userId],
    (err, user) => {
      if (err || !user) return fail(res, 'User not found', 404);
      return ok(res, user, 'User profile fetched');
    }
  );
});

module.exports = router;

