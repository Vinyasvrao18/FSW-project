const request = require('supertest');
const app = require('../app');

describe('AuthGuard-X Core API', () => {
  it('GET /api/health should return status 200', async () => {
    const response = await request(app).get('/api/health');
    expect(response.statusCode).toEqual(200);
    expect(response.body.success).toBe(true);
  });

  it('GET /api/csrf-token should provide a CSRF token', async () => {
    const response = await request(app).get('/api/csrf-token');
    expect(response.statusCode).toEqual(200);
    expect(response.body.data.csrfToken).toBeDefined();
  });
});
