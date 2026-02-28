// ═══════════════════════════════════════════════════════════════
//  CyberShield 360 — FREE TIER Backend
//
//  100% Free Stack:
//    Runtime   → Railway.app free tier  (no credit card needed)
//    Cache     → node-cache in-memory   (Upstash Redis free if needed)
//    Breach    → HIBP free k-Anonymity endpoint (no API key required)
//    Container → GitHub Container Registry (free)
//    CI/CD     → GitHub Actions free tier (2000 min/month)
//    HTTPS     → Railway auto-provisioned SSL (free)
//    Domain    → *.up.railway.app subdomain (free)
// ═══════════════════════════════════════════════════════════════
require('dotenv').config();

const express     = require('express');
const helmet      = require('helmet');
const cors        = require('cors');
const morgan      = require('morgan');
const compression = require('compression');
const rateLimit   = require('express-rate-limit');
const path        = require('path');

const logger = require('./utils/logger');
const cache  = require('./utils/cache');   // in-memory, no Redis needed

const breachRoutes   = require('./routes/breach');
const passwordRoutes = require('./routes/password');
const phishingRoutes = require('./routes/phishing');
const networkRoutes  = require('./routes/network');
const healthRoutes   = require('./routes/health');

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Security ──────────────────────────────────────────────────
app.set('trust proxy', 1); // Railway sits behind a proxy

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],   // needed for inline frontend
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "https://api.pwnedpasswords.com"],
      imgSrc:     ["'self'", "data:"],
    }
  },
  crossOriginEmbedderPolicy: false,
}));

// ── CORS: allow Railway domain + localhost ────────────────────
const ALLOWED = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',');
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED.some(o => origin.startsWith(o)) || origin.includes('.up.railway.app')) {
      return cb(null, true);
    }
    cb(new Error(`CORS blocked: ${origin}`));
  },
  credentials: true,
}));

app.use(compression());
app.use(express.json({ limit: '10kb' }));
app.use(morgan('tiny', { stream: { write: m => logger.http(m.trim()) } }));

// ── Rate limiting (free tier friendly) ────────────────────────
app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit reached. Try again in 15 minutes.' },
}));

// Tighter limit on breach checks (respect HIBP fair use)
app.use('/api/breach', rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Breach check limit: 10/minute. Please slow down.' },
}));

// ── API routes ────────────────────────────────────────────────
app.use('/api/health',   healthRoutes);
app.use('/api/breach',   breachRoutes);
app.use('/api/password', passwordRoutes);
app.use('/api/phishing', phishingRoutes);
app.use('/api/network',  networkRoutes);

// ── Serve frontend from /public (single deployment, no CDN needed) ─
app.use(express.static(path.join(__dirname, '..', 'public')));
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// ── Error handler ─────────────────────────────────────────────
app.use((err, req, res, _next) => {
  logger.error(`Error: ${err.message}`);
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message
  });
});

// ── Start ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  logger.info(`🛡  CyberShield 360 FREE running on :${PORT}`);
  logger.info(`📍 Env: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`💾 Cache: in-memory (${cache.type})`);
  logger.info(`🔍 HIBP: k-Anonymity endpoint (no API key needed)`);
});

module.exports = app;
