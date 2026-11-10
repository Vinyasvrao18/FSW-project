/**
 * Standardized API response envelopes & input validators
 */

function ok(res, data = {}, message = 'Success', statusCode = 200) {
  return res.status(statusCode).json({
    success: true,
    message,
    data
  });
}

function fail(res, message = 'An error occurred', statusCode = 400, errors = null) {
  return res.status(statusCode).json({
    success: false,
    message,
    errors
  });
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidUrl(urlStr) {
  try {
    const parsed = new URL(urlStr);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  return fail(res, 'Unauthorized access. Please log in.', 401);
}

module.exports = {
  ok,
  fail,
  isValidEmail,
  isValidUrl,
  isAuthenticated
};

