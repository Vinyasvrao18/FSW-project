const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const db = require('./db');
const { ok, fail, isAuthenticated } = require('./helpers');

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

const router = express.Router();

// Upload file, calculate SHA-256 and store baseline or compare
router.post('/check', isAuthenticated, upload.single('file'), (req, res) => {
  if (!req.file) {
    return fail(res, 'No file uploaded', 422);
  }

  const { expectedHash } = req.body;
  const hash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
  const filename = req.file.originalname;
  const fileSize = req.file.size;

  let match = null;
  let status = 'RECORDED';

  if (expectedHash) {
    match = hash.toLowerCase() === expectedHash.trim().toLowerCase();
    status = match ? 'VERIFIED' : 'TAMPERED';
  }

  // Record baseline if not comparing or if user chose to register
  db.run(
    `INSERT INTO file_hashes (user_id, filename, sha256, file_size) VALUES (?, ?, ?, ?)`,
    [req.session.userId, filename, hash, fileSize]
  );

  // Record into audit log
  db.run(
    `INSERT INTO scan_history (user_id, module, target, status, score, details) VALUES (?, ?, ?, ?, ?, ?)`,
    [
      req.session.userId,
      'FileIntegrity',
      filename,
      status,
      match === false ? 0 : 100,
      JSON.stringify({ calculatedHash: hash, expectedHash: expectedHash || null, fileSize })
    ]
  );

  return ok(res, {
    filename,
    fileSize,
    calculatedHash: hash,
    expectedHash: expectedHash || null,
    match,
    status
  }, 'File integrity analyzed');
});

// List saved baselines
router.get('/baselines', isAuthenticated, (req, res) => {
  db.all(
    `SELECT id, filename, sha256, file_size, created_at FROM file_hashes WHERE user_id = ? ORDER BY created_at DESC`,
    [req.session.userId],
    (err, rows) => {
      if (err) return fail(res, 'Failed to fetch baselines', 500);
      return ok(res, rows, 'Baselines fetched');
    }
  );
});

module.exports = router;

