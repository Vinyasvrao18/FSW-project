/**
 * phishcheck.js
 * Scores a URL for phishing patterns using simple text-based rules.
 *
 * IMPORTANT: This file NEVER fetches, opens, or resolves the URL.
 * No axios, no DNS lookup, no network calls of any kind.
 *
 * Security idea: heuristic pattern matching on the URL text alone.
 * Same input → same output every time (deterministic).
 */

const analyzeOriginalPhishingRules = require('./originalPhishingRules');
const express = require('express');
const database = require('./db');
const { ok, fail, isAuthenticated } = require('./helpers');

const router = express.Router();

// All rules, weights, keywords, shortener hosts and score bands live here.
// A teacher can read this one object and understand the whole scoring system.
const CONFIG = {

  // Each rule has: id, label, weight, and a plain-English explanation.
  rules: [
    {
      id: 'URL_SCHEME',
      label: 'Plain HTTP (not HTTPS)',
      weight: 10,
      explanation: 'The URL uses plain HTTP, which does not encrypt traffic between your browser and the server.'
    },
    {
      id: 'IP_HOST',
      label: 'IP address used as host',
      weight: 25,
      explanation: 'The host is a raw IP address. Legitimate sites almost always use a domain name, not an IP.'
    },
    {
      id: 'AT_SYMBOL',
      label: 'Credentials before the @ symbol',
      weight: 20,
      explanation: 'The URL contains user information before an @ sign, which is a classic trick to hide the real host.'
    },
    {
      id: 'EXCESSIVE_SUBDOMAINS',
      label: 'Too many subdomains',
      weight: 10,
      explanation: 'The host has more than 3 labels (e.g. a.b.c.d.example.com). Phishing sites often pad subdomains.'
    },
    {
      id: 'PUNYCODE',
      label: 'Punycode label (possible lookalike domain)',
      weight: 15,
      explanation: 'A label in the host starts with xn--, which is used to encode non-ASCII letters that can look like common letters.'
    },
    {
      id: 'SUSPICIOUS_KEYWORDS',
      label: 'Suspicious keywords in URL',
      weight: 10,
      explanation: 'The URL contains words like "login" or "verify" that are common in phishing pages designed to steal credentials.'
    },
    {
      id: 'LONG_URL',
      label: 'Unusually long URL',
      weight: 5,
      explanation: 'The URL is longer than 75 characters. Phishing URLs are often padded to hide the real destination.'
    },
    {
      id: 'UNUSUAL_PORT',
      label: 'Unusual port number',
      weight: 10,
      explanation: 'The URL uses a port other than 80 (HTTP) or 443 (HTTPS), which is uncommon for legitimate public sites.'
    },
    {
      id: 'SHORTENER',
      label: 'URL shortener service',
      weight: 15,
      explanation: 'The host is a known URL-shortening service. These hide the final destination until you click.'
    }
  ],

  // Keywords that are common in phishing pages
  suspiciousKeywords: ['login', 'verify', 'wallet', 'update', 'secure', 'signin'],

  // Known URL shortener hostnames
  shorteners: ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd'],

  // Score bands (project document values)
  bands: [
    { max: 24,  level: 'low' },
    { max: 49,  level: 'medium' },
    { max: 74,  level: 'high' },
    { max: 100, level: 'very high' }
  ],

  maxScore: 100,
  longUrlThreshold: 75,
  excessiveSubdomainLabels: 3  // more than this many labels triggers the rule
};

function isIpAddress(hostname) {
  // IPv4: four groups of digits separated by dots
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  // IPv6: surrounded by square brackets (the URL parser leaves the brackets)
  const ipv6 = hostname.startsWith('[');
  return ipv4 || ipv6;
}

function scoreToBand(score) {
  for (const band of CONFIG.bands) {
    if (score <= band.max) return band.level;
  }
  return 'very high'; // fallback (score already capped at 100)
}

// Exported so unit tests can call it directly without HTTP.
function analyzeUrl(urlString, parsed = new URL(urlString)) {

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl  = parsed.href; // the normalised URL from the parser

  const triggeredFindings = []; // rules that matched
  let totalScore = 0;

  // Build a lookup map from rule id to rule definition (for easy access below)
  const ruleMap = {};
  CONFIG.rules.forEach(rule => { ruleMap[rule.id] = rule; });

  // Helper to trigger a rule: add it to findings and add its weight to score
  function trigger(ruleId) {
    const rule = ruleMap[ruleId];
    totalScore += rule.weight;
    triggeredFindings.push({
      ruleId:      rule.id,
      label:       rule.label,
      weight:      rule.weight,
      explanation: rule.explanation
    });
  }

  // Rule 1: plain HTTP (not HTTPS)
  if (parsed.protocol === 'http:') {
    trigger('URL_SCHEME');
  }

  // Rule 2: IP address used as host
  if (isIpAddress(hostname)) {
    trigger('IP_HOST');
  }

  // Rule 3: credentials embedded before an @ (the URL parser extracts these)
  if (parsed.username || parsed.password) {
    trigger('AT_SYMBOL');
  }

  // Rule 4: too many subdomain labels
  // e.g. "a.b.c.example.com" has 5 labels; > 3 triggers the rule
  const labels = hostname.split('.');
  if (labels.length > CONFIG.excessiveSubdomainLabels) {
    trigger('EXCESSIVE_SUBDOMAINS');
  }

  // Rule 5: punycode label (xn-- prefix means an IDN — international domain name)
  const hasPunycode = labels.some(label => label.startsWith('xn--'));
  if (hasPunycode) {
    trigger('PUNYCODE');
  }

  // Rule 6: suspicious keywords in hostname or path
  const lowerPath = parsed.pathname.toLowerCase();
  const lowerQuery = parsed.search.toLowerCase();
  const hasKeyword = CONFIG.suspiciousKeywords.some(keyword =>
    hostname.includes(keyword) || lowerPath.includes(keyword) || lowerQuery.includes(keyword)
  );
  if (hasKeyword) {
    trigger('SUSPICIOUS_KEYWORDS');
  }

  // Rule 7: URL is longer than the threshold
  if (urlString.length > CONFIG.longUrlThreshold) {
    trigger('LONG_URL');
  }

  // Rule 8: unusual port (the URL parser sets port to '' when it is the default)
  if (parsed.port !== '') {
    const port = Number(parsed.port);
    if (port !== 80 && port !== 443) {
      trigger('UNUSUAL_PORT');
    }
  }

  // Rule 9: known URL shortener
  if (CONFIG.shorteners.includes(hostname)) {
    trigger('SHORTENER');
  }

  // Cap the score at 100
  const score = Math.min(totalScore, CONFIG.maxScore);
  const riskLevel = scoreToBand(score);

  return {
    normalisedUrl: fullUrl,
    hostname,
    score,
    riskLevel,
    findings: triggeredFindings,
    disclaimer: 'Heuristic result; not a reputation verdict.'
  };
}

// Used by both /analyze and /check routes so there is no duplicated code.
function handleAnalyze(request, response) {
  const rawUrl = request.body.url;

  // 1. Reject too-long or missing input before even trying to parse
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
    return fail(response, 'Please enter a URL.', 422);
  }
  if (rawUrl.length > 2048) {
    return fail(response, 'URL is too long (max 2048 characters).', 422);
  }

  // 2. Try to parse the URL — this rejects javascript:, data:, file:, ftp: etc.
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return fail(response, 'Invalid URL. Please include http:// or https://.', 422);
  }

  // 3. Only http and https are accepted
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return fail(response, 'Only http:// and https:// URLs are accepted.', 422);
  }

  // 4. Run the heuristic analysis (pure function, no network)
  const usesOriginalRules = request.path === '/check';
  let report;
  try {
    report = usesOriginalRules ? analyzeOriginalPhishingRules(rawUrl, parsed) : analyzeUrl(rawUrl, parsed);
  } catch (error) {
    // Should not happen after the checks above, but be safe
    console.error('[PhishCheck] analyzeUrl error:', error.message);
    return fail(response, 'Could not analyse this URL.', 422);
  }

  const status = usesOriginalRules ? report.classification : report.riskLevel;
  const score = usesOriginalRules ? report.riskScore : report.score;

  // 5. Save to scan_history with parameterised SQL
  //    user_id from session only — never from the request body
  database.run(
    `INSERT INTO scan_history (user_id, module, target, status, score, details)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [
      request.session.userId,          // from server session
      'PhishCheck',                // exact module name the dashboard counts on
      parsed.href,        // normalised URL from the parser
      status,
      score,
      JSON.stringify({ riskLevel: status, findings: report.findings })
    ],
    (databaseError) => {
      if (databaseError) {
        // Log DB errors but do not fail the HTTP response
        console.error('[PhishCheck] DB insert error:', databaseError.message);
      }
    }
  );

  // 6. Return the result — no internal error details exposed
  return ok(response, report, 'URL analysed');
}

// The original /check endpoint retains its own scoring rules and response format.
router.post('/analyze', isAuthenticated, handleAnalyze);
router.post('/check', isAuthenticated, handleAnalyze);

module.exports = router;
module.exports.analyzeUrl = analyzeUrl; // exported for unit tests
