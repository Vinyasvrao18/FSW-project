/**
 * headershield.js
 * Scans a website's HTTP response headers for key security headers.
 *
 * Security controls used:
 *  - isAuthenticated: only logged-in users can scan
 *  - Resolve public destinations once and reuse the checked IP addresses
 *  - No redirect following: maxRedirects: 0 stops server-side redirect chains
 *  - HEAD-first: avoids downloading page bodies
 *  - Parameterised SQL: prevents SQL injection when saving history
 *  - Safe error messages: real errors logged server-side, safe text sent to client
 */

const express = require('express');
const axios = require('axios');
const dns = require('node:dns').promises;
const net = require('node:net');
const ipaddr = require('ipaddr.js');
const database = require('./db');
const { ok, fail, isAuthenticated } = require('./helpers');

const router = express.Router();

const HEADER_POLICIES = [
  {
    header: 'content-security-policy',
    weight: 25,
    purpose: 'Tells the browser which sources of scripts, styles and images are allowed. Reduces XSS risk.',
    recommendation: 'Add a Content-Security-Policy header with a strict policy, e.g. default-src \'self\'.'
  },
  {
    header: 'strict-transport-security',
    weight: 20,
    purpose: 'Forces the browser to use HTTPS instead of HTTP for future visits. Prevents protocol downgrade attacks.',
    recommendation: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains (only meaningful over HTTPS).'
  },
  {
    header: 'x-frame-options',
    weight: 15,
    purpose: 'Controls whether other pages can embed this page in a frame.',
    recommendation: 'Set X-Frame-Options to DENY or SAMEORIGIN.',
    acceptedValues: ['deny', 'sameorigin']
  },
  {
    header: 'x-content-type-options',
    weight: 15,
    acceptedValues: ['nosniff'],
    purpose: 'Stops the browser from guessing the file type (MIME sniffing), which can be exploited for XSS.',
    recommendation: 'Add X-Content-Type-Options: nosniff exactly.'
  },
  {
    header: 'referrer-policy',
    weight: 15,
    purpose: 'Controls how much of the current URL is sent to other sites when a user clicks a link.',
    recommendation: 'Add Referrer-Policy: no-referrer or strict-origin-when-cross-origin.'
  },
  {
    header: 'permissions-policy',
    weight: 10,
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

function isPublicAddress({ address }) {
  const parsed = ipaddr.process(address);
  if (parsed.range() !== 'unicast') return false;
  return parsed.kind() === 'ipv4' || parsed.match(ipaddr.parse('2000::'), 3);
}

function safeAxiosError(error) {
  if (error.code === 'ECONNABORTED') return 'The request timed out. The site did not respond in time.';
  if (error.code === 'ENOTFOUND')    return 'Could not reach the site (DNS lookup failed).';
  if (error.code === 'ECONNREFUSED') return 'The site refused the connection.';
  return 'Could not reach the site.';
}

function checkOneHeader(headerDefinition, receivedHeaders, isHttps) {
  const value = String(receivedHeaders[headerDefinition.header] ?? '').trim();
  let status = value ? 'present' : 'missing';
  let recommendation = headerDefinition.recommendation;
  if (value && headerDefinition.acceptedValues && !headerDefinition.acceptedValues.includes(value.toLowerCase())) {
    status = 'invalid';
  }
  if (headerDefinition.header === 'strict-transport-security' && !isHttps) {
    if (value) status = 'invalid';
    recommendation = 'Serve the site over HTTPS, then send Strict-Transport-Security.';
  }

  return {
    header: headerDefinition.header,
    weight: headerDefinition.weight,
    points: status === 'present' ? headerDefinition.weight : 0,
    status,
    valueSummary: value.length > 120 ? value.slice(0, 117) + '...' : value,
    purpose: headerDefinition.purpose,
    recommendation: status === 'present' ? '' : recommendation
  };
}

router.get('/hosts', isAuthenticated, (request, response) => {
  // Compatibility with older clients that displayed example hosts.
  return ok(response, []);
});

router.post('/scan', isAuthenticated, async (request, response) => {
  const rawUrl = request.body.url ?? request.body.targetUrl;

  // 1. Validate the URL shape
  const validation = validateUrl(rawUrl);
  if (validation.error) {
    return fail(response, validation.error, 422);
  }
  const parsed = validation.parsed;

  // Normalised URL = href produced by the URL parser (strips extra whitespace etc.)
  const normalisedUrl = parsed.href;
  const isHttps = parsed.protocol === 'https:';

  let httpStatus;
  let receivedHeaders;

  try {
    const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
    const family = net.isIP(hostname);
    const addresses = family ? [{ address: hostname, family }] : await dns.lookup(hostname, { all: true });
    if (!addresses.length || !addresses.every(isPublicAddress)) {
      return fail(response, 'Private and reserved network addresses are not allowed.', 403);
    }

    // 3. Try HEAD first (avoids downloading the page body)
    const requestOptions = {
      // Connect only to the addresses we checked, including on the GET fallback.
      proxy: false,
      lookup: (_hostname, options, callback) => {
        if (options.all) return callback(null, addresses);
        callback(null, addresses[0].address, addresses[0].family);
      },
      maxRedirects: 0,
      timeout: 6000,
      maxContentLength: 1024,
      validateStatus: () => true
    };
    let upstreamResponse = await axios.head(normalisedUrl, requestOptions);
    if ([405, 501].includes(upstreamResponse.status)) {
      // The headers are available immediately. Close the stream before reading the page body.
      upstreamResponse = await axios.get(normalisedUrl, { ...requestOptions, responseType: 'stream' });
      upstreamResponse.data.destroy();
    }

    httpStatus = upstreamResponse.status;
    receivedHeaders = upstreamResponse.headers || {};

  } catch (error) {
    // Catch-all for unexpected errors
    console.error('[HeaderShield] Unexpected error:', error.message);
    return fail(response, safeAxiosError(error), 502);
  }

  const findings = HEADER_POLICIES.map(policy => checkOneHeader(policy, receivedHeaders, isHttps));
  const score = findings.reduce((total, finding) => total + finding.points, 0);
  const summary = {
    checked: findings.length,
    present: findings.filter(finding => finding.status === 'present').length,
    missing: findings.filter(finding => finding.status === 'missing').length,
    invalid: findings.filter(finding => finding.status === 'invalid').length
  };

  // Keep the original API fields for clients that read the checks array.
  const checks = findings.map(finding => ({
    header: finding.header,
    present: finding.status !== 'missing',
    value: receivedHeaders[finding.header] || null,
    description: finding.purpose,
    weight: finding.weight
  }));

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
