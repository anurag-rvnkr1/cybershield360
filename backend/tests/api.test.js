// tests/api.test.js
const request = require('supertest');
process.env.NODE_ENV = 'test';
process.env.PORT = '3002';
const app = require('../src/server');

describe('GET /api/health', () => {
  it('returns healthy', async () => {
    const r = await request(app).get('/api/health');
    expect(r.status).toBe(200);
    expect(r.body.status).toBe('healthy');
    expect(r.body.services.hibp).toBe('k-anonymity-free');
  });
});

describe('POST /api/breach/email', () => {
  it('rejects bad email', async () => {
    const r = await request(app).post('/api/breach/email').send({ email: 'bad' });
    expect(r.status).toBe(400);
  });
  it('returns result for valid email', async () => {
    const r = await request(app).post('/api/breach/email').send({ email: 'test@gmail.com' });
    expect(r.status).toBe(200);
    expect(typeof r.body.breached).toBe('boolean');
    expect(r.body.riskScore).toBeDefined();
  });
});

describe('POST /api/password/analyze', () => {
  it('scores weak password low', async () => {
    const r = await request(app).post('/api/password/analyze').send({ password: '123456' });
    expect(r.status).toBe(200);
    expect(r.body.score).toBeLessThanOrEqual(1);
    expect(r.body.checks.minLength).toBe(false);
  });
  it('scores strong password high', async () => {
    const r = await request(app).post('/api/password/analyze').send({ password: 'V@lidP@ssw0rd!2024Secure#' });
    expect(r.status).toBe(200);
    expect(r.body.score).toBeGreaterThanOrEqual(3);
  });
});

describe('GET /api/password/generate', () => {
  it('generates password of correct length', async () => {
    const r = await request(app).get('/api/password/generate').query({ length: 32 });
    expect(r.status).toBe(200);
    expect(r.body.password).toHaveLength(32);
    expect(r.body.entropy).toBeGreaterThan(150);
  });
});

describe('POST /api/phishing/analyze-url', () => {
  it('flags phishing URL', async () => {
    const r = await request(app).post('/api/phishing/analyze-url').send({ url: 'http://paypal-secure-login.xyz/verify' });
    expect(r.status).toBe(200);
    expect(r.body.riskScore).toBeGreaterThan(50);
    expect(r.body.safe).toBe(false);
  });
  it('passes legitimate URL', async () => {
    const r = await request(app).post('/api/phishing/analyze-url').send({ url: 'https://github.com/user/repo' });
    expect(r.status).toBe(200);
    expect(r.body.riskScore).toBeLessThan(30);
  });
});

describe('POST /api/phishing/analyze-email', () => {
  it('detects phishing email', async () => {
    const r = await request(app).post('/api/phishing/analyze-email').send({
      content: 'Dear Customer, URGENT: account suspended! Click here, enter password and send bitcoin within 24 hours.'
    });
    expect(r.status).toBe(200);
    expect(r.body.riskScore).toBeGreaterThan(60);
  });
  it('passes clean email', async () => {
    const r = await request(app).post('/api/phishing/analyze-email').send({
      content: 'Hi Sarah, following up on our 3pm meeting tomorrow. Let me know if you need to reschedule.'
    });
    expect(r.status).toBe(200);
    expect(r.body.riskScore).toBe(0);
  });
});
