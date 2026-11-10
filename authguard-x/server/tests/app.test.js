const request = require('supertest');
const app = require('../app');

describe('AuthGuard-X Core API', () => {
  it('GET /api/health should return status 200', async () => {
    const res = await request(app).get('/api/health');
    expect(res.statusCode).toEqual(200);
    expect(res.body.success).toBe(true);
  });

  it('GET /api/csrf-token should provide a CSRF token', async () => {
    const res = await request(app).get('/api/csrf-token');
    expect(res.statusCode).toEqual(200);
    expect(res.body.data.csrfToken).toBeDefined();
  });
});

