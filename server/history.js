const express = require('express');
const database = require('./db');
const { ok, fail, isAuthenticated } = require('./helpers');

const router = express.Router();

// Get scan history list with optional module filter and pagination
router.get('/', isAuthenticated, (request, response) => {
  const { module, limit = 50, offset = 0 } = request.query;

  let query = `SELECT id, module, target, status, score, details, created_at FROM scan_history WHERE user_id = ?`;
  const queryParameters = [request.session.userId];

  if (module) {
    query += ` AND module = ?`;
    queryParameters.push(module);
  }

  query += ` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`;
  queryParameters.push(Number(limit), Number(offset));

  database.all(query, queryParameters, (error, rows) => {
    if (error) return fail(response, 'Failed to fetch history', 500);

    const parsedRows = rows.map(record => ({
      ...record,
      details: record.details ? JSON.parse(record.details) : null
    }));

    return ok(response, parsedRows, 'History retrieved');
  });
});

// Single history detail
router.get('/:id', isAuthenticated, (request, response) => {
  database.get(
    `SELECT * FROM scan_history WHERE id = ? AND user_id = ?`,
    [request.params.id, request.session.userId],
    (error, row) => {
      if (error || !row) return fail(response, 'Record not found', 404);
      return ok(response, {
        ...row,
        details: row.details ? JSON.parse(row.details) : null
      }, 'Record details retrieved');
    }
  );
});

// Dashboard summary metrics
router.get('/summary/dashboard', isAuthenticated, (request, response) => {
  const userId = request.session.userId;

  const summaryQuery = `
    SELECT 
      COUNT(*) as totalScans,
      SUM(CASE WHEN module = 'HeaderShield' THEN 1 ELSE 0 END) as headerShieldCount,
      SUM(CASE WHEN module = 'PhishCheck' THEN 1 ELSE 0 END) as phishCheckCount,
      SUM(CASE WHEN module = 'FileIntegrity' THEN 1 ELSE 0 END) as fileIntegrityCount,
      SUM(CASE WHEN status IN ('WEAK', 'HIGH_RISK', 'TAMPERED', 'high', 'very high') THEN 1 ELSE 0 END) as highAlertsCount,
      AVG(score) as averageScore
    FROM scan_history
    WHERE user_id = ?
  `;

  database.get(summaryQuery, [userId], (error, summary) => {
    if (error) return fail(response, 'Failed to compute dashboard metrics', 500);

    database.all(
      `SELECT id, module, target, status, score, created_at FROM scan_history WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 5`,
      [userId],
      (recentScansError, recentScans) => {
        if (recentScansError) return fail(response, 'Failed to load recent scans', 500);

        return ok(response, {
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
