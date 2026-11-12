/**
 * headershield.js
 * Scans a website's HTTP response headers for key security headers.
 *
 * Security controls used:
 *  - isAuthenticated: only logged-in users can scan
 *  - SSRF host allowlist: only pre-approved hostnames can be scanned
 *  - No redirect following: maxRedirects: 0 stops server-side redirect chains
 *  - HEAD-first: avoids downloading page bodies
 *  - Parameterised SQL: prevents SQL injection when saving history
 *  - Safe error messages: real errors logged server-side, safe text sent to client
 */

const express = require('express');
const axios = require('axios');
const database = require('./db');
const { ok, fail, isAuthenticated } = require('./helpers');

const router = express.Router();

// Only hostnames listed here may be scanned. Everything else is blocked.
// Add "example.com" (or more) to the ALLOWED_SCAN_HOSTS env var.
const RECOMMENDED_HEADERS = [
  { name: 'content-security-policy', weight: 25, description: 'Mitigates XSS and data injection attacks' },
  { name: 'strict-transport-security', weight: 20, description: 'Forces secure HTTPS connections' },
  { name: 'x-frame-options', weight: 15, description: 'Protects against clickjacking' },
  { name: 'x-content-type-options', weight: 15, description: 'Prevents MIME-sniffing' },
  { name: 'referrer-policy', weight: 15, description: 'Controls referrer data sent in requests' },
  { name: 'permissions-policy', weight: 10, description: 'Restricts browser features and APIs' }
];

const RAW_ALLOWED = process.env.ALLOWED_SCAN_HOSTS || 'example.com';
const ALLOWED_HOSTS = RAW_ALLOWED
  .split(',')
  .map(hostname => hostname.trim().toLowerCase())
  .filter(Boolean);

// Exactly the five headers the spec requires. No weights, no x-frame-options.
const HEADERS_TO_CHECK = [
  {
    header: 'content-security-policy',
    purpose: 'Tells the browser which sources of scripts, styles and images are allowed. Reduces XSS risk.',
    recommendation: 'Add a Content-Security-Policy header with a strict policy, e.g. default-src \'self\'.'
  },
  {
    header: 'strict-transport-security',
    purpose: 'Forces the browser to use HTTPS instead of HTTP for future visits. Prevents protocol downgrade attacks.',
    recommendation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains (only meaningful over HTTPS).'
  },
  {
    header: 'x-content-type-options',
    purpose: 'Stops the browser from guessing the file type (MIME sniffing), which can be exploited for XSS.',
    recommendation: 'Add X-Content-Type-Options: nosniff exactly.'
  },
  {
    header: 'referrer-policy',
    purpose: 'Controls how much of the current URL is sent to other sites when a user clicks a link.',
    recommendation: 'Add Referrer-Policy: no-referrer or strict-origin-when-cross-origin.'
  },
  {
    header: 'permissions-policy',
    purpose: 'Restricts which browser features (camera, microphone, geolocation) the page can use.',
    recommendation: 'Add Permissions-Policy listing only the features your site actually needs.'
  }
];

function validateUrl(raw) {
  // Must be a non-empty string
  if (typeof raw !== 'string' || raw.length === 0) {
    return { error: 'Please enter a URL.' };
  }
  // Hard cap to prevent memory abuse
  if (raw.length > 2048) {
    return { error: 'URL is too long (max 2048 characters).' };
  }

  let parsed;
  try {
    parsed = new URL(raw); // throws if not a valid URL
  } catch {
    return { error: 'Invalid URL. Please include http:// or https://.' };
  }

  // Only allow http and https — block javascript:, ftp:, data:, etc.
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { error: 'Only http:// and https:// URLs are accepted.' };
  }

  // Block URLs with embedded credentials (e.g. http://user:pass@evil.com)
  if (parsed.username || parsed.password) {
    return { error: 'URLs with a username or password are not allowed.' };
  }

  return { parsed };
}

function isHostAllowed(hostname) {
  // Compare in lowercase so casing tricks cannot bypass the check
  const lower = hostname.toLowerCase();
  return ALLOWED_HOSTS.includes(lower);
}

function safeAxiosError(error) {
  if (error.code === 'ECONNABORTED') return 'The request timed out. The site did not respond in time.';
  if (error.code === 'ENOTFOUND')    return 'Could not reach the site (DNS lookup failed).';
  if (error.code === 'ECONNREFUSED') return 'The site refused the connection.';
  return 'Could not reach the site.';
}

function checkOneHeader(headerDefinition, receivedHeaders, isHttps) {
  const rawValue = receivedHeaders[headerDefinition.header] || null;
  let status = rawValue ? 'present' : 'missing';

  // x-content-type-options is only "correct" when the value is exactly "nosniff"
  if (headerDefinition.header === 'x-content-type-options' && rawValue) {
    if (rawValue.trim().toLowerCase() !== 'nosniff') {
      status = 'missing'; // present but wrong value → treat as missing
    }
  }

  // HSTS is only meaningful over HTTPS; note this in the recommendation
  let recommendation = status === 'missing' ? headerDefinition.recommendation : '';
  if (headerDefinition.header === 'strict-transport-security' && !isHttps && status === 'missing') {
    recommendation = 'HSTS only works over HTTPS. Switch the site to HTTPS first, then add this header.';
  }

  // valueSummary: a short (≤120 char) display of the actual value
  let valueSummary = '';
  if (rawValue) {
    valueSummary = rawValue.length > 120 ? rawValue.substring(0, 117) + '...' : rawValue;
  }

  return {
    header: headerDefinition.header,
    status,            // 'present' or 'missing'
    valueSummary,      // what the site actually sent (blank when missing)
    purpose: headerDefinition.purpose,
    recommendation     // plain-English advice (blank when present and correct)
  };
}

router.post('/scan', isAuthenticated, async (request, response) => {
  const rawUrl = request.body.url ?? request.body.targetUrl;

  // 1. Validate the URL shape
  const validation = validateUrl(rawUrl);
  if (validation.error) {
    return fail(response, validation.error, 422);
  }
  const parsed = validation.parsed;

  // 2. SSRF defence: reject any host not on the allowlist
  if (!isHostAllowed(parsed.hostname)) {
    return fail(response, 'This site is not allowed in this demo.', 403);
  }

  // Normalised URL = href produced by the URL parser (strips extra whitespace etc.)
  const normalisedUrl = parsed.href;
  const isHttps = parsed.protocol === 'https:';

  let httpStatus;
  let receivedHeaders;

  try {
    // 3. Try HEAD first (avoids downloading the page body)
    const requestOptions = {
      maxRedirects: 0,
      timeout: 6000,
      maxContentLength: 1024,
      validateStatus: () => true
    };
    let upstreamResponse = await axios.head(normalisedUrl, requestOptions);
    if ([405, 501].includes(upstreamResponse.status)) {
      upstreamResponse = await axios.get(normalisedUrl, { ...requestOptions, maxContentLength: 512 });
    }

    httpStatus = upstreamResponse.status;
    receivedHeaders = upstreamResponse.headers || {};

    // If the server redirected (3xx), tell the client where it wanted to go (hostname only)
    if (httpStatus >= 300 && httpStatus < 400) {
      const locationHeader = receivedHeaders['location'] || '';
      let redirectHost = '';
      try {
        redirectHost = new URL(locationHeader).hostname;
      } catch { /* location header is not a full URL */ }
      console.log('[HeaderShield] Redirect detected → Location host:', redirectHost);
    }

  } catch (error) {
    // Catch-all for unexpected errors
    console.error('[HeaderShield] Unexpected error:', error.message);
    return fail(response, safeAxiosError(error), 502);
  }

  // 4. Check each of the five required headers
  const findings = HEADERS_TO_CHECK.map(definition =>
    checkOneHeader(definition, receivedHeaders, isHttps)
  );

  // 5. Count the detailed policy findings
  const present = findings.filter(finding => finding.status === 'present').length;
  const missing = findings.filter(finding => finding.status === 'missing').length;
  const summary = {
    checked: findings.length,
    present,
    missing
  };

  let score = 0;
  const checks = RECOMMENDED_HEADERS.map(headerDefinition => {
    const present = Boolean(receivedHeaders[headerDefinition.name.toLowerCase()]);
    if (present) score += headerDefinition.weight;
    return {
      header: headerDefinition.name,
      present,
      value: receivedHeaders[headerDefinition.name.toLowerCase()] || null,
      description: headerDefinition.description,
      weight: headerDefinition.weight
    };
  });

  const status = score >= 80 ? 'STRONG' : score >= 50 ? 'MODERATE' : 'WEAK';

  // 6. Save to scan_history using parameterised SQL
  //    user_id comes from the session only — never from the request body
  database.run(
    `INSERT INTO scan_history (user_id, module, target, status, score, details)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [
      request.session.userId,          // from server session, not from client
      'HeaderShield',              // exact module name the dashboard counts on
      normalisedUrl,               // normalised URL, not raw user input
      status,
      score,
      JSON.stringify({ httpStatus, findings, summary, checks })
    ],
    (databaseError) => {
      if (databaseError) {
        // Log DB errors but do not fail the HTTP response
        console.error('[HeaderShield] DB insert error:', databaseError.message);
      }
    }
  );

  // 7. Return the result — never include raw errors, paths, or internal details
  return ok(response, {
    targetUrl: rawUrl,
    checks,
    score,
    status,
    statusCode: httpStatus,
    target: normalisedUrl,
    httpStatus,
    findings,
    summary,
    limitations: 'Presence of a header does not prove it is well configured.'
  }, 'Headers checked');
});

module.exports = router;
