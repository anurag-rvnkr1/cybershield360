// health.js — used by Railway's health checker
const express = require('express');
const cache   = require('../utils/cache');
const router  = express.Router();
const START   = Date.now();

router.get('/', (req, res) => {
  res.json({
    status: 'healthy',
    version: '1.0.0',
    uptime: Math.floor((Date.now() - START) / 1000),
    environment: process.env.NODE_ENV || 'development',
    services: { api: 'healthy', cache: cache.type, hibp: 'k-anonymity-free' },
    timestamp: new Date().toISOString(),
  });
});

module.exports = router;
