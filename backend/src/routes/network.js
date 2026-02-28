// network.js
const express = require('express');
const router  = express.Router();

router.get('/info', (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  res.json({
    ip,
    userAgent:  req.headers['user-agent'] || '',
    https:      req.secure || req.headers['x-forwarded-proto'] === 'https',
    language:   req.headers['accept-language'] || '',
    dnt:        req.headers['dnt'] === '1',
    timestamp:  new Date().toISOString(),
  });
});

router.get('/score', (req, res) => {
  const https = req.secure || req.headers['x-forwarded-proto'] === 'https';
  res.json({
    score: https ? 75 : 40,
    checks: { https: { pass: https, label: 'HTTPS Connection', impact: 'CRITICAL' } },
    checkedAt: new Date().toISOString(),
  });
});

module.exports = router;
