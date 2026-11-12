const express = require('express');
const bcrypt = require('bcryptjs');
const database = require('./db');
const { ok, fail, isValidEmail } = require('./helpers');

const router = express.Router();

// Register
router.post('/register', async (request, response) => {
  const { username, email, password } = request.body;

  if (!username || !email || !password) {
    return fail(response, 'Username, email, and password are required', 422);
  }

  if (!isValidEmail(email)) {
    return fail(response, 'Invalid email format', 422);
  }

  if (password.length < 8) {
    return fail(response, 'Password must be at least 8 characters long', 422);
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    database.run(
      `INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)`,
      [username.trim(), email.trim().toLowerCase(), passwordHash],
      function (error) {
        if (error) {
          if (error.message.includes('UNIQUE constraint failed')) {
            return fail(response, 'Username or email already exists', 409);
          }
          return fail(response, 'Failed to create user', 500);
        }

        request.session.userId = this.lastID;
        return ok(response, { id: this.lastID, username, email }, 'Registered successfully', 201);
      }
    );
  } catch (error) {
    return fail(response, 'Internal registration error', 500);
  }
});

// Login
router.post('/login', (request, response) => {
  const { email, password } = request.body;

  if (!email || !password) {
    return fail(response, 'Email and password are required', 422);
  }

  database.get(
    `SELECT * FROM users WHERE email = ?`,
    [email.trim().toLowerCase()],
    async (error, user) => {
      if (error) return fail(response, 'Database error', 500);
      if (!user) return fail(response, 'Invalid email or password', 401);

      const isMatch = await bcrypt.compare(password, user.password_hash);
      if (!isMatch) return fail(response, 'Invalid email or password', 401);

      request.session.userId = user.id;
      return ok(response, { id: user.id, username: user.username, email: user.email }, 'Logged in successfully');
    }
  );
});

// Logout
router.post('/logout', (request, response) => {
  request.session.destroy((error) => {
    if (error) return fail(response, 'Logout failed', 500);
    response.clearCookie('authguard.sid');
    return ok(response, {}, 'Logged out successfully');
  });
});

// Current user profile
router.get('/me', (request, response) => {
  if (!request.session || !request.session.userId) {
    return fail(response, 'Not authenticated', 401);
  }

  database.get(
    `SELECT id, username, email, created_at FROM users WHERE id = ?`,
    [request.session.userId],
    (error, user) => {
      if (error || !user) return fail(response, 'User not found', 404);
      return ok(response, user, 'User profile fetched');
    }
  );
});

module.exports = router;
