/**
 * Standardized API response envelopes & input validators
 */

function ok(response, data = {}, message = 'Success', statusCode = 200) {
  return response.status(statusCode).json({
    success: true,
    message,
    data
  });
}

function fail(response, message = 'An error occurred', statusCode = 400, errors = null) {
  return response.status(statusCode).json({
    success: false,
    message,
    errors
  });
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidUrl(urlString) {
  try {
    const parsed = new URL(urlString);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function isAuthenticated(request, response, next) {
  if (request.session && request.session.userId) {
    return next();
  }
  return fail(response, 'Unauthorized access. Please log in.', 401);
}

module.exports = {
  ok,
  fail,
  isValidEmail,
  isValidUrl,
  isAuthenticated
};
