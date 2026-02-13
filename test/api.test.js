const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'phase5-session-secret';
process.env.TOKEN_SECRET = 'phase5-token-secret';
process.env.ADMIN_USERNAME = 'phase5-admin';
process.env.ADMIN_PASSWORD = 'phase5-password';

const app = require('../server');

test('GET /api/health responds with service status', async () => {
  const response = await request(app).get('/api/health');
  assert.equal(response.status, 200);
  assert.equal(response.body.status, 'ok');
  assert.ok(response.body.timestamp);
});

test('POST /api/login rejects malformed payloads', async () => {
  const response = await request(app).post('/api/login').send({ username: 123, password: true });
  assert.equal(response.status, 400);
  assert.equal(response.body.success, false);
});

test('POST /api/login rejects invalid credentials', async () => {
  const response = await request(app)
    .post('/api/login')
    .send({ username: 'wrong-user', password: 'wrong-password' });

  assert.equal(response.status, 401);
  assert.equal(response.body.success, false);
});

test('POST /api/login accepts valid credentials', async () => {
  const response = await request(app)
    .post('/api/login')
    .send({ username: 'phase5-admin', password: 'phase5-password' });

  assert.equal(response.status, 200);
  assert.equal(response.body.success, true);
  assert.ok(response.body.token);
  assert.ok(response.body.sessionID);
});
