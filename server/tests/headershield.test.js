/**
 * headershield.test.js
 * Tests for the HeaderShield backend.
 *
 * Key testing ideas:
 *  - We mock axios so no real network requests are made.
 *  - We use supertest to make HTTP requests against the Express app.
 *  - We use ONE shared auth agent (beforeAll) to avoid hitting rate limits.
 *  - We check that security controls (allowlist, CSRF, auth) work.
 */

const dns = require('node:dns').promises;
const request = require('supertest');
const app = require('../app');

// ── Mock axios before the module under test loads it ─────────────────────────
// This stops any real HTTP calls from going out during tests.
jest.mock('axios');
const axios = require('axios');

// ── Shared test state — set up once for the whole suite ──────────────────────
// Using beforeAll means we only call register+login once, avoiding rate limits.
let sharedAgent;      // authenticated supertest agent (holds session cookie)
let sharedCsrfToken;  // CSRF token for the authenticated session

beforeAll(async () => {
  sharedAgent = request.agent(app);

  // Get a CSRF token (GET is safe — no CSRF check needed)
  const csrfResponse = await sharedAgent.get('/api/csrf-token');
  sharedCsrfToken = csrfResponse.body.data.csrfToken;

  // Register one test user for the whole suite
  const unique = 'hs_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
  const email = `${unique}@test.com`;

  await sharedAgent
    .post('/api/auth/register')
    .set('CSRF-Token', sharedCsrfToken)
    .send({ username: unique, email, password: 'Password1!' });

  // Log in — the agent stores the session cookie automatically
  await sharedAgent
    .post('/api/auth/login')
    .set('CSRF-Token', sharedCsrfToken)
    .send({ email, password: 'Password1!' });
});

beforeEach(() => {
  // Reset mock state between tests (call counts and queued return values)
  // but we do NOT recreate the agent — the session stays alive.
  jest.resetAllMocks();
  jest.spyOn(dns, 'lookup').mockImplementation(async hostname => [
    { address: hostname === 'localhost' ? '127.0.0.1' : '8.8.8.8', family: 4 }
  ]);
});

// ── TESTS ─────────────────────────────────────────────────────────────────────

describe('HeaderShield — POST /api/headershield/scan', () => {

  // ── Authentication guard ───────────────────────────────────────────────────

  test('returns 401 when not logged in', async () => {
    // Use a fresh agent with NO session (not sharedAgent)
    const anonymousAgent = request.agent(app);
    const csrfResponse = await anonymousAgent.get('/api/csrf-token');
    const anonCsrf = csrfResponse.body.data.csrfToken;

    const response = await anonymousAgent
      .post('/api/headershield/scan')
      .set('CSRF-Token', anonCsrf)
      .send({ url: 'https://example.com' });

    expect(response.statusCode).toBe(401);
    expect(response.body.success).toBe(false);
  });

  // ── CSRF guard ─────────────────────────────────────────────────────────────

  test('returns 403 when CSRF token is missing', async () => {
    const response = await sharedAgent
      .post('/api/headershield/scan')
      // deliberately NOT setting CSRF-Token header
      .send({ url: 'https://example.com' });

    expect(response.statusCode).toBe(403);
  });

  // ── URL validation ─────────────────────────────────────────────────────────

  test('rejects a malformed URL', async () => {
    const response = await sharedAgent
      .post('/api/headershield/scan')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'not-a-url' });

    expect(response.statusCode).toBe(422);
    expect(response.body.success).toBe(false);
  });

  test('rejects ftp:// URLs', async () => {
    const response = await sharedAgent
      .post('/api/headershield/scan')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'ftp://example.com/file.txt' });

    expect(response.statusCode).toBe(422);
  });

  test('rejects URLs with embedded credentials', async () => {
    const response = await sharedAgent
      .post('/api/headershield/scan')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'https://admin:secret@example.com' });

    expect(response.statusCode).toBe(422);
  });

  // ── SSRF allowlist ─────────────────────────────────────────────────────────

  test('rejects localhost', async () => {
    const response = await sharedAgent
      .post('/api/headershield/scan')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'http://localhost' });

    expect(response.statusCode).toBe(403);
    expect(response.body.message).toMatch(/not allowed/i);
  });

  test('rejects 127.0.0.1', async () => {
    const response = await sharedAgent
      .post('/api/headershield/scan')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'http://127.0.0.1' });

    expect(response.statusCode).toBe(403);
    expect(response.body.message).toMatch(/not allowed/i);
  });

  test('rejects 192.168.1.1 (private IP)', async () => {
    const response = await sharedAgent
      .post('/api/headershield/scan')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'http://192.168.1.1' });

    expect(response.statusCode).toBe(403);
    expect(response.body.message).toMatch(/not allowed/i);
  });

  test('rejects 169.254.169.254 (AWS metadata endpoint)', async () => {
    const response = await sharedAgent
      .post('/api/headershield/scan')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'http://169.254.169.254/latest/meta-data/' });

    expect(response.statusCode).toBe(403);
    expect(response.body.message).toMatch(/not allowed/i);
  });

  test('scans an arbitrary public host using the validated DNS records', async () => {
    axios.head.mockResolvedValueOnce({ status: 200, headers: {} });
    const response = await sharedAgent
      .post('/api/headershield/scan')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'https://google.com' });

    expect(response.statusCode).toBe(200);
    const options = axios.head.mock.calls[0][1];
    expect(options.proxy).toBe(false);
    const callback = jest.fn();
    options.lookup('google.com', { all: true }, callback);
    expect(callback).toHaveBeenCalledWith(null, [{ address: '8.8.8.8', family: 4 }]);
  });

  // ── Happy path: allowed host, all headers present ─────────────────────────

  test('scans allowed host and returns findings + saves history row', async () => {
    // Set up axios to return a response with all six security headers
    axios.head.mockResolvedValueOnce({
      status: 200,
      headers: {
        'content-security-policy': "default-src 'self'",
        'strict-transport-security': 'max-age=31536000',
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'permissions-policy': 'geolocation=()'
      }
    });

    const response = await sharedAgent
      .post('/api/headershield/scan')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'https://example.com' });

    expect(response.statusCode).toBe(200);
    expect(response.body.success).toBe(true);

    const data = response.body.data;
    // All six headers should be present
    expect(data.summary.present).toBe(6);
    expect(data.summary.missing).toBe(0);
    expect(data.summary.checked).toBe(6);
    expect(data.score).toBe(100);
    expect(data.findings.reduce((total, finding) => total + finding.points, 0)).toBe(data.score);
    expect(data.checks.map(check => check.header)).toEqual(data.findings.map(finding => finding.header));

    // Response must include the limitation note
    expect(data.limitations).toMatch(/does not prove/i);

    // Findings array must have exactly six entries
    expect(data.findings).toHaveLength(6);

    // Every finding has the required fields
    data.findings.forEach(finding => {
      expect(finding).toHaveProperty('header');
      expect(finding).toHaveProperty('status');
      expect(finding).toHaveProperty('valueSummary');
      expect(finding).toHaveProperty('purpose');
      expect(finding).toHaveProperty('recommendation');
    });

    // Check that one history row was saved (we do this via the history API)
    const historyResponse = await sharedAgent.get('/api/history?module=HeaderShield');
    expect(historyResponse.statusCode).toBe(200);
    const rows = historyResponse.body.data;
    expect(rows.some(record => record.module === 'HeaderShield' && record.target === 'https://example.com/')).toBe(true);
  });

  // ── Missing headers get recommendations ───────────────────────────────────

  test('missing headers each receive a recommendation string', async () => {
    // No security headers at all
    axios.head.mockResolvedValueOnce({ status: 200, headers: {} });

    const response = await sharedAgent
      .post('/api/headershield/scan')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'https://example.com' });

    expect(response.statusCode).toBe(200);
    const data = response.body.data;
    expect(data.summary.missing).toBe(6);

    // Every missing header must have a non-empty recommendation
    data.findings
      .filter(finding => finding.status === 'missing')
      .forEach(finding => {
        expect(finding.recommendation.length).toBeGreaterThan(0);
      });
  });

  // ── x-content-type-options must be exactly "nosniff" ─────────────────────

  test('x-content-type-options with wrong value earns zero points', async () => {
    // Value is present but wrong
    axios.head.mockResolvedValueOnce({
      status: 200,
      headers: { 'x-content-type-options': 'allow' }
    });

    const response = await sharedAgent
      .post('/api/headershield/scan')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'https://example.com' });

    expect(response.statusCode).toBe(200);
    const contentTypeOptions = response.body.data.findings.find(finding => finding.header === 'x-content-type-options');
    expect(contentTypeOptions).toMatchObject({ status: 'invalid', points: 0 });
    expect(response.body.data.score).toBe(0);
  });

  test.each([
    ['  SameOrigin  ', 'present', 15],
    ['ALLOW-FROM https://example.com', 'invalid', 0],
    ['   ', 'missing', 0]
  ])('X-Frame-Options value %j agrees with the total score', async (value, status, points) => {
    axios.head.mockResolvedValueOnce({ status: 200, headers: { 'x-frame-options': value } });
    const response = await sharedAgent.post('/api/headershield/scan').set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'https://example.com' }).expect(200);
    const report = response.body.data;
    expect(report.score).toBe(points);
    expect(report.findings).toContainEqual(expect.objectContaining({ header: 'x-frame-options', status, points }));
    expect(report.summary.present + report.summary.invalid + report.summary.missing).toBe(report.summary.checked);
  });

  test('HSTS received over HTTP receives no points', async () => {
    axios.head.mockResolvedValueOnce({ status: 200, headers: { 'strict-transport-security': 'max-age=31536000' } });
    const response = await sharedAgent.post('/api/headershield/scan').set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'http://example.com' }).expect(200);
    expect(response.body.data.score).toBe(0);
    expect(response.body.data.summary.invalid).toBe(1);
  });

  // ── Redirect is NOT followed ───────────────────────────────────────────────

  test('does not follow redirects (reports 301 status)', async () => {
    // Simulate a 301 redirect response (axios returns it because maxRedirects: 0)
    axios.head.mockResolvedValueOnce({
      status: 301,
      headers: { location: 'https://example.com/new' }
    });

    const response = await sharedAgent
      .post('/api/headershield/scan')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'https://example.com' });

    expect(response.statusCode).toBe(200);
    // The httpStatus in the data must reflect the 301, not the final destination
    expect(response.body.data.httpStatus).toBe(301);
  });

  // ── Timeout returns a safe message (no err.message leaking) ───────────────

  test('timeout returns a safe user-facing message without internal details', async () => {
    // Simulate an ECONNABORTED (timeout) error from axios
    const timeoutError = new Error('timeout of 6000ms exceeded');
    timeoutError.code = 'ECONNABORTED';
    axios.head.mockRejectedValueOnce(timeoutError);

    const response = await sharedAgent
      .post('/api/headershield/scan')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'https://example.com' });

    expect(response.statusCode).toBe(502);
    // The real error message must NOT appear in the response
    expect(JSON.stringify(response.body)).not.toMatch(/timeout of 6000ms/i);
    // A safe, human-readable message must appear instead
    expect(response.body.message).toMatch(/timed out/i);
  });

  // ── HEAD 405 falls back to GET ─────────────────────────────────────────────

  test('falls back to GET when HEAD returns 405', async () => {
    axios.head.mockResolvedValueOnce({ status: 405, headers: {} });

    // A full page can exceed the buffered response limit. Read headers and close its stream.
    const bodyStream = require('stream').Readable.from(Buffer.alloc(8192));
    axios.get.mockResolvedValueOnce({
      status: 200,
      data: bodyStream,
      headers: { 'referrer-policy': 'no-referrer' }
    });

    const response = await sharedAgent
      .post('/api/headershield/scan')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'https://example.com' });

    expect(response.statusCode).toBe(200);
    expect(axios.get).toHaveBeenCalledTimes(1);
    expect(axios.get).toHaveBeenCalledWith('https://example.com/', expect.objectContaining({
      responseType: 'stream', maxRedirects: 0
    }));
    expect(bodyStream.destroyed).toBe(true);
  });

  test('blocks mixed public and private DNS answers before making a request', async () => {
    dns.lookup.mockResolvedValueOnce([{ address: '8.8.8.8', family: 4 }, { address: '::1', family: 6 }]);
    await sharedAgent.post('/api/headershield/scan').set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'https://mixed.example' }).expect(403);
    expect(axios.head).not.toHaveBeenCalled();
  });

  test.each(['[::1]', '[::ffff:127.0.0.1]', '[fd00::1]', '[::127.0.0.1]', '0x7f000001'])(
    'blocks non-public IP literal %s', async host => {
      await sharedAgent.post('/api/headershield/scan').set('CSRF-Token', sharedCsrfToken)
        .send({ url: 'http://' + host }).expect(403);
      expect(axios.head).not.toHaveBeenCalled();
    }
  );

});
