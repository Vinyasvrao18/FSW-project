const express = require('express');
const db = require('./db');
const { ok, fail, isAuthenticated } = require('./helpers');

const router = express.Router();

// Get scan history list with optional module filter and pagination
router.get('/', isAuthenticated, (req, res) => {
  const { module, limit = 50, offset = 0 } = req.query;

  let query = `SELECT id, module, target, status, score, details, created_at FROM scan_history WHERE user_id = ?`;
  const params = [req.session.userId];

  if (module) {
    query += ` AND module = ?`;
    params.push(module);
  }

  query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
  params.push(Number(limit), Number(offset));

  db.all(query, params, (err, rows) => {
    if (err) return fail(res, 'Failed to fetch history', 500);

    const parsedRows = rows.map(r => ({
      ...r,
      details: r.details ? JSON.parse(r.details) : null
    }));

    return ok(res, parsedRows, 'History retrieved');
  });
});

// Single history detail
router.get('/:id', isAuthenticated, (req, res) => {
  db.get(
    `SELECT * FROM scan_history WHERE id = ? AND user_id = ?`,
    [req.params.id, req.session.userId],
    (err, row) => {
      if (err || !row) return fail(res, 'Record not found', 404);
      return ok(res, {
        ...row,
        details: row.details ? JSON.parse(row.details) : null
      }, 'Record details retrieved');
    }
  );
});

// Dashboard summary metrics
router.get('/summary/dashboard', isAuthenticated, (req, res) => {
  const userId = req.session.userId;

  const summaryQuery = `
    SELECT 
      COUNT(*) as totalScans,
      SUM(CASE WHEN module = 'HeaderShield' THEN 1 ELSE 0 END) as headerShieldCount,
      SUM(CASE WHEN module = 'PhishCheck' THEN 1 ELSE 0 END) as phishCheckCount,
      SUM(CASE WHEN module = 'FileIntegrity' THEN 1 ELSE 0 END) as fileIntegrityCount,
      SUM(CASE WHEN status IN ('WEAK', 'HIGH_RISK', 'TAMPERED') THEN 1 ELSE 0 END) as highAlertsCount,
      AVG(score) as averageScore
    FROM scan_history
    WHERE user_id = ?
  `;

  db.get(summaryQuery, [userId], (err, summary) => {
    if (err) return fail(res, 'Failed to compute dashboard metrics', 500);

    db.all(
      `SELECT id, module, target, status, score, created_at FROM scan_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 5`,
      [userId],
      (recentErr, recentScans) => {
        if (recentErr) return fail(res, 'Failed to load recent scans', 500);

        return ok(res, {
          totalScans: summary.totalScans || 0,
          headerShieldCount: summary.headerShieldCount || 0,
          phishCheckCount: summary.phishCheckCount || 0,
          fileIntegrityCount: summary.fileIntegrityCount || 0,
          highAlertsCount: summary.highAlertsCount || 0,
          averageScore: Math.round(summary.averageScore || 0),
          recentScans: recentScans || []
        }, 'Dashboard summary metrics fetched');
      }
    );
  });
});

module.exports = router;

