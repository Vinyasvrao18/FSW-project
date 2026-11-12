const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const database = require('./db');
const { ok, fail, isAuthenticated } = require('./helpers');

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

const router = express.Router();

// Upload file, calculate SHA-256 and store baseline or compare
router.post('/check', isAuthenticated, upload.single('file'), (request, response) => {
  if (!request.file) {
    return fail(response, 'No file uploaded', 422);
  }

  const { expectedHash } = request.body;
  const hash = crypto.createHash('sha256').update(request.file.buffer).digest('hex');
  const filename = request.file.originalname;
  const fileSize = request.file.size;

  let match = null;
  let status = 'RECORDED';

  if (expectedHash) {
    match = hash.toLowerCase() === expectedHash.trim().toLowerCase();
    status = match ? 'VERIFIED' : 'TAMPERED';
  }

  // Record baseline if not comparing or if user chose to register
  database.run(
    `INSERT INTO file_hashes (user_id, filename, sha256, file_size) VALUES (?, ?, ?, ?)`,
    [request.session.userId, filename, hash, fileSize]
  );

  // Record into audit log
  database.run(
    `INSERT INTO scan_history (user_id, module, target, status, score, details) VALUES (?, ?, ?, ?, ?, ?)`,
    [
      request.session.userId,
      'FileIntegrity',
      filename,
      status,
      match === false ? 0 : 100,
      JSON.stringify({ calculatedHash: hash, expectedHash: expectedHash || null, fileSize })
    ]
  );

  return ok(response, {
    filename,
    fileSize,
    calculatedHash: hash,
    expectedHash: expectedHash || null,
    match,
    status
  }, 'File integrity analyzed');
});

// List saved baselines
router.get('/baselines', isAuthenticated, (request, response) => {
  database.all(
    `SELECT id, filename, sha256, file_size, created_at FROM file_hashes WHERE user_id = ? ORDER BY created_at DESC`,
    [request.session.userId],
    (error, rows) => {
      if (error) return fail(response, 'Failed to fetch baselines', 500);
      return ok(response, rows, 'Baselines fetched');
    }
  );
});

module.exports = router;
