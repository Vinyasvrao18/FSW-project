/**
 * phishcheck.test.js
 * Tests for the PhishCheck backend.
 *
 * Key ideas:
 *  - We test the pure analyzeUrl() function directly for scoring logic.
 *  - We test the HTTP route with supertest for auth, CSRF, and DB saving.
 *  - We confirm axios is NEVER called (no network allowed in this module).
 *  - We use a shared auth agent in beforeAll to stay well clear of rate limits.
 */

const request = require('supertest');
const app = require('../app');
const { analyzeUrl } = require('../phishcheck');

// Make sure axios is never called from phishcheck.js
jest.mock('axios');
const axios = require('axios');

// ═══════════════════════════════════════════════════════════════════════════════
// UNIT TESTS: analyzeUrl() pure function
// These do NOT need supertest or HTTP — they just call the function directly.
// ═══════════════════════════════════════════════════════════════════════════════

describe('analyzeUrl() – pure function unit tests', () => {

  test('clean HTTPS URL scores 0', () => {
    const result = analyzeUrl('https://example.com/page');
    expect(result.score).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.riskLevel).toBe('low');
  });

  // ── Individual rule tests ──────────────────────────────────────────────────

  test('URL_SCHEME: http adds +10', () => {
    const result = analyzeUrl('http://example.com');
    const rule = result.findings.find(finding => finding.ruleId === 'URL_SCHEME');
    expect(rule).toBeDefined();
    expect(rule.weight).toBe(10);
    expect(result.score).toBe(10);
  });

  test('IP_HOST: IPv4 literal adds +25', () => {
    const result = analyzeUrl('https://192.168.1.1/page');
    const rule = result.findings.find(finding => finding.ruleId === 'IP_HOST');
    expect(rule).toBeDefined();
    expect(rule.weight).toBe(25);
  });

  test('AT_SYMBOL: credentials in URL add +20', () => {
    const result = analyzeUrl('https://admin:pw@example.com');
    const rule = result.findings.find(finding => finding.ruleId === 'AT_SYMBOL');
    expect(rule).toBeDefined();
    expect(rule.weight).toBe(20);
  });

  test('EXCESSIVE_SUBDOMAINS: >3 labels adds +10', () => {
    const result = analyzeUrl('https://a.b.c.d.example.com');
    const rule = result.findings.find(finding => finding.ruleId === 'EXCESSIVE_SUBDOMAINS');
    expect(rule).toBeDefined();
    expect(rule.weight).toBe(10);
  });

  test('EXCESSIVE_SUBDOMAINS: 3 labels (sub.example.com) does NOT trigger', () => {
    const result = analyzeUrl('https://sub.example.com');
    const rule = result.findings.find(finding => finding.ruleId === 'EXCESSIVE_SUBDOMAINS');
    expect(rule).toBeUndefined();
  });

  test('PUNYCODE: xn-- label adds +15', () => {
    const result = analyzeUrl('https://xn--e1awd7f.com/page');
    const rule = result.findings.find(finding => finding.ruleId === 'PUNYCODE');
    expect(rule).toBeDefined();
    expect(rule.weight).toBe(15);
  });

  test('SUSPICIOUS_KEYWORDS: "login" in path adds +10', () => {
    const result = analyzeUrl('https://example.com/login');
    const rule = result.findings.find(finding => finding.ruleId === 'SUSPICIOUS_KEYWORDS');
    expect(rule).toBeDefined();
    expect(rule.weight).toBe(10);
  });

  test('SUSPICIOUS_KEYWORDS: "verify" in hostname adds +10', () => {
    const result = analyzeUrl('https://verify-account.com');
    const rule = result.findings.find(finding => finding.ruleId === 'SUSPICIOUS_KEYWORDS');
    expect(rule).toBeDefined();
  });

  test('SUSPICIOUS_KEYWORDS: "signin" in URL adds +10', () => {
    const result = analyzeUrl('https://example.com/signin');
    const rule = result.findings.find(finding => finding.ruleId === 'SUSPICIOUS_KEYWORDS');
    expect(rule).toBeDefined();
  });

  test('LONG_URL: >75 chars adds +5', () => {
    const longUrl = 'https://example.com/' + 'a'.repeat(60);
    expect(longUrl.length).toBeGreaterThan(75);
    const result = analyzeUrl(longUrl);
    const rule = result.findings.find(finding => finding.ruleId === 'LONG_URL');
    expect(rule).toBeDefined();
    expect(rule.weight).toBe(5);
  });

  test('LONG_URL: exactly 75 chars does NOT trigger', () => {
    const base = 'https://example.com/';
    const url = base + 'a'.repeat(75 - base.length);
    expect(url.length).toBe(75);
    const result = analyzeUrl(url);
    const rule = result.findings.find(finding => finding.ruleId === 'LONG_URL');
    expect(rule).toBeUndefined();
  });

  test('UNUSUAL_PORT: port 8080 adds +10', () => {
    const result = analyzeUrl('https://example.com:8080/path');
    const rule = result.findings.find(finding => finding.ruleId === 'UNUSUAL_PORT');
    expect(rule).toBeDefined();
    expect(rule.weight).toBe(10);
  });

  test('UNUSUAL_PORT: port 443 does NOT trigger', () => {
    const result = analyzeUrl('https://example.com:443/path');
    const rule = result.findings.find(finding => finding.ruleId === 'UNUSUAL_PORT');
    expect(rule).toBeUndefined();
  });

  test('UNUSUAL_PORT: port 80 does NOT trigger', () => {
    const result = analyzeUrl('http://example.com:80/path');
    const rule = result.findings.find(finding => finding.ruleId === 'UNUSUAL_PORT');
    expect(rule).toBeUndefined();
  });

  test('SHORTENER: bit.ly adds +15', () => {
    const result = analyzeUrl('https://bit.ly/abc123');
    const rule = result.findings.find(finding => finding.ruleId === 'SHORTENER');
    expect(rule).toBeDefined();
    expect(rule.weight).toBe(15);
  });

  test('SHORTENER: tinyurl.com adds +15', () => {
    const result = analyzeUrl('https://tinyurl.com/xyz');
    const rule = result.findings.find(finding => finding.ruleId === 'SHORTENER');
    expect(rule).toBeDefined();
  });

  test('IPv4 octets do not trigger the excessive subdomains rule', () => {
    const report = analyzeUrl('https://192.0.2.1');
    expect(report.findings.map(finding => finding.ruleId)).toEqual(['IP_HOST']);
    expect(report.score).toBe(25);
  });

  test('multiple occurrences of login contribute the keyword weight once', () => {
    const report = analyzeUrl('https://login.example.com/login?next=login');
    expect(report.score).toBe(10);
    expect(report.findings).toHaveLength(1);
  });

  // ── Combined case ──────────────────────────────────────────────────────────

  test('combined case: http + IP + AT triggers multiple rules, score >= 55 and <= 100', () => {
    const result = analyzeUrl('http://user:pw@192.168.0.1/login');
    expect(result.score).toBeGreaterThanOrEqual(55);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(['low', 'medium', 'high', 'very high']).toContain(result.riskLevel);

    const ruleIds = result.findings.map(finding => finding.ruleId);
    expect(ruleIds).toContain('URL_SCHEME');
    expect(ruleIds).toContain('IP_HOST');
    expect(ruleIds).toContain('AT_SYMBOL');
    expect(ruleIds).toContain('SUSPICIOUS_KEYWORDS');
  });

  test('score is capped at 100 — does not exceed the maximum', () => {
    const result = analyzeUrl(
      'http://admin:pw@a.b.c.d.xn--e1awd7f.com:8080/login-verify?update=wallet&' + 'x'.repeat(60)
    );
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
    expect(result.score).toBeGreaterThanOrEqual(70);
  });

  // ── Deterministic output ───────────────────────────────────────────────────

  test('same input gives the same output every time (deterministic)', () => {
    const url = 'http://bit.ly/fake-login-verify';
    const result1 = analyzeUrl(url);
    const result2 = analyzeUrl(url);
    expect(result1.score).toBe(result2.score);
    expect(result1.riskLevel).toBe(result2.riskLevel);
    expect(result1.findings.map(finding => finding.ruleId)).toEqual(result2.findings.map(finding => finding.ruleId));
  });

  // ── Risk bands ────────────────────────────────────────────────────────────

  test('score 0 → "low"',       () => { expect(analyzeUrl('https://example.com').riskLevel).toBe('low'); });
  test('score 10 → "low"',      () => { expect(analyzeUrl('http://example.com').riskLevel).toBe('low'); });
  test('score 25 → "medium"',   () => { expect(analyzeUrl('https://192.168.1.1').riskLevel).toBe('medium'); });

  // ── Result structure ──────────────────────────────────────────────────────

  test('result always has normalisedUrl, hostname, score, riskLevel, findings, disclaimer', () => {
    const result = analyzeUrl('https://example.com');
    expect(result).toHaveProperty('normalisedUrl');
    expect(result).toHaveProperty('hostname');
    expect(result).toHaveProperty('score');
    expect(result).toHaveProperty('riskLevel');
    expect(result).toHaveProperty('findings');
    expect(result).toHaveProperty('disclaimer');
    expect(result.disclaimer).toMatch(/heuristic/i);
  });

  // ── Never says safe/malicious ─────────────────────────────────────────────

  test('disclaimer does not contain "safe" or "malicious"', () => {
    const result = analyzeUrl('https://example.com');
    expect(result.disclaimer.toLowerCase()).not.toMatch(/\bsafe\b/);
    expect(result.disclaimer.toLowerCase()).not.toMatch(/malicious/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// INTEGRATION TESTS: HTTP route via supertest
// ═══════════════════════════════════════════════════════════════════════════════

describe('POST /api/phishcheck/analyze – HTTP route', () => {

  let sharedAgent;
  let sharedCsrfToken;

  beforeAll(async () => {
    sharedAgent = request.agent(app);

    const csrfResponse = await sharedAgent.get('/api/csrf-token');
    sharedCsrfToken = csrfResponse.body.data.csrfToken;

    const unique = 'pc_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    const email = `${unique}@test.com`;

    await sharedAgent
      .post('/api/auth/register')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ username: unique, email, password: 'Password1!' });

    await sharedAgent
      .post('/api/auth/login')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ email, password: 'Password1!' });
  });

  beforeEach(() => {
    jest.resetAllMocks();
  });

  // ── Authentication guard ───────────────────────────────────────────────────

  test('returns 401 when not logged in', async () => {
    const anonymousAgent = request.agent(app);
    const csrfToken = (await anonymousAgent.get('/api/csrf-token')).body.data.csrfToken;

    const response = await anonymousAgent
      .post('/api/phishcheck/analyze')
      .set('CSRF-Token', csrfToken)
      .send({ url: 'https://example.com' });

    expect(response.statusCode).toBe(401);
  });

  // ── Validation ─────────────────────────────────────────────────────────────

  test('rejects javascript: URL', async () => {
    const response = await sharedAgent
      .post('/api/phishcheck/analyze')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'javascript:alert(1)' });

    expect(response.statusCode).toBe(422);
    expect(response.body.success).toBe(false);
  });

  test('rejects data: URL', async () => {
    const response = await sharedAgent
      .post('/api/phishcheck/analyze')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'data:text/html,<h1>hi</h1>' });

    expect(response.statusCode).toBe(422);
  });

  test('rejects file: URL', async () => {
    const response = await sharedAgent
      .post('/api/phishcheck/analyze')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'file:///etc/passwd' });

    expect(response.statusCode).toBe(422);
  });

  test('rejects input longer than 2048 characters', async () => {
    const response = await sharedAgent
      .post('/api/phishcheck/analyze')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'https://example.com/' + 'x'.repeat(2048) });

    expect(response.statusCode).toBe(422);
  });

  // ── Axios is NEVER called ─────────────────────────────────────────────────

  test('axios is never called — no network requests made', async () => {
    await sharedAgent
      .post('/api/phishcheck/analyze')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'https://example.com' });

    expect(axios.get).not.toHaveBeenCalled();
    expect(axios.head).not.toHaveBeenCalled();
    expect(axios.post).not.toHaveBeenCalled();
  });

  // ── Successful analysis ────────────────────────────────────────────────────

  test('returns expected fields for a valid URL', async () => {
    const response = await sharedAgent
      .post('/api/phishcheck/analyze')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'https://example.com' });

    expect(response.statusCode).toBe(200);
    expect(response.body.success).toBe(true);

    const data = response.body.data;
    expect(data).toHaveProperty('normalisedUrl');
    expect(data).toHaveProperty('hostname');
    expect(data).toHaveProperty('score');
    expect(data).toHaveProperty('riskLevel');
    expect(data).toHaveProperty('findings');
    expect(data).toHaveProperty('disclaimer');
  });

  // ── History row is saved under the logged-in user ─────────────────────────

  test('saves a row to scan_history for the logged-in user', async () => {
    await sharedAgent
      .post('/api/phishcheck/analyze')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url: 'https://bit.ly/test123' });

    const historyResponse = await sharedAgent.get('/api/history?module=PhishCheck');
    expect(historyResponse.statusCode).toBe(200);
    const rows = historyResponse.body.data;
    expect(rows.some(record => record.module === 'PhishCheck')).toBe(true);
  });

  // ── /check alias also works ────────────────────────────────────────────────

  test.each([
    ['https://example.com/parity', 0, 'low', 'SAFE'],
    ['http://bit.ly/login-verify', 35, 'medium', 'SUSPICIOUS'],
    ['http://user@[2001:db8::1]/verify', 65, 'high', 'HIGH_RISK'],
    ['http://user@[2001:db8::1]:8888/verify', 75, 'very high', 'HIGH_RISK']
  ])('both routes score %s identically and save the same findings', async (url, score, riskLevel, classification) => {
    const reports = [];
    for (const route of ['analyze', 'check']) {
      const response = await sharedAgent.post('/api/phishcheck/' + route)
        .set('CSRF-Token', sharedCsrfToken).send({ url }).expect(200);
      reports.push(response.body.data);
    }

    const [current, legacy] = reports;
    expect(current).toMatchObject({ score, riskLevel });
    expect(legacy).toEqual({
      url, riskScore: score, classification,
      findings: current.findings.map(finding => ({
        rule: finding.ruleId, severity: finding.severity, message: finding.explanation
      }))
    });
    const history = await sharedAgent.get('/api/history?module=PhishCheck').expect(200);
    expect(history.body.data.length).toBeGreaterThanOrEqual(2);
    for (const record of history.body.data.slice(0, 2)) {
      expect(record).toMatchObject({ target: current.normalisedUrl, score, status: riskLevel,
        details: { riskLevel, findings: current.findings } });
    }
  });

  // ── Deterministic via HTTP ─────────────────────────────────────────────────

  test('same URL gives same score on two consecutive requests', async () => {
    const url = 'http://bit.ly/login-secure';

    const res1 = await sharedAgent
      .post('/api/phishcheck/analyze')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url });

    const res2 = await sharedAgent
      .post('/api/phishcheck/analyze')
      .set('CSRF-Token', sharedCsrfToken)
      .send({ url });

    expect(res1.body.data.score).toBe(res2.body.data.score);
    expect(res1.body.data.riskLevel).toBe(res2.body.data.riskLevel);
  });
});
