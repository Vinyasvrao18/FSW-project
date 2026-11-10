const express = require('express');
const axios = require('axios');
const db = require('./db');
const { ok, fail, isValidUrl, isAuthenticated } = require('./helpers');

const router = express.Router();

const RECOMMENDED_HEADERS = [
  { name: 'content-security-policy', weight: 25, description: 'Mitigates XSS and data injection attacks' },
  { name: 'strict-transport-security', weight: 20, description: 'Forces secure HTTPS connections' },
  { name: 'x-frame-options', weight: 15, description: 'Protects against clickjacking' },
  { name: 'x-content-type-options', weight: 15, description: 'Prevents MIME-sniffing' },
  { name: 'referrer-policy', weight: 15, description: 'Controls referrer data sent in requests' },
  { name: 'permissions-policy', weight: 10, description: 'Restricts browser features and APIs' }
];

// Scan URL for security headers
router.post('/scan', isAuthenticated, async (req, res) => {
  const { targetUrl } = req.body;

  if (!targetUrl || !isValidUrl(targetUrl)) {
    return fail(res, 'A valid HTTP/HTTPS URL is required', 422);
  }

  try {
    const response = await axios.get(targetUrl, {
      timeout: 6000,
      maxRedirects: 5,
      validateStatus: () => true
    });

    const receivedHeaders = response.headers;
    let score = 0;
    const checks = RECOMMENDED_HEADERS.map(item => {
      const present = Boolean(receivedHeaders[item.name.toLowerCase()]);
      if (present) score += item.weight;
      return {
        header: item.name,
        present,
        value: receivedHeaders[item.name.toLowerCase()] || null,
        description: item.description,
        weight: item.weight
      };
    });

    const status = score >= 80 ? 'STRONG' : score >= 50 ? 'MODERATE' : 'WEAK';

    // Log to scan_history
    db.run(
      `INSERT INTO scan_history (user_id, module, target, status, score, details) VALUES (?, ?, ?, ?, ?, ?)`,
      [
        req.session.userId,
        'HeaderShield',
        targetUrl,
        status,
        score,
        JSON.stringify({ checks, statusCode: response.status })
      ]
    );

    return ok(res, {
      targetUrl,
      score,
      status,
      statusCode: response.status,
      checks
    }, 'Security headers evaluated');
  } catch (err) {
    return fail(res, `Failed to analyze target: ${err.message}`, 502);
  }
});

module.exports = router;

