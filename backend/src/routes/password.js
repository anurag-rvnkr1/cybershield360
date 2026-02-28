// ═══════════════════════════════════════════════════════════════
//  PASSWORD ROUTE — 100% FREE
//  - k-Anonymity pwned check: HIBP /range endpoint (always free)
//  - Strength analysis: zxcvbn (open source, MIT license)
//  - Password generation: Node.js built-in crypto (no cost)
// ═══════════════════════════════════════════════════════════════
const express = require('express');
const axios   = require('axios');
const crypto  = require('crypto');
const zxcvbn  = require('zxcvbn');
const cache   = require('../utils/cache');
const logger  = require('../utils/logger');

const router = express.Router();

// ════════════════════════════════════════════════════════════
//  POST /api/password/check-pwned — TRUE FREE k-Anonymity
//  Only first 5 chars of SHA-1 sent. Password NEVER leaves server.
// ════════════════════════════════════════════════════════════
router.post('/check-pwned', async (req, res) => {
  const { password } = req.body;
  if (!password || typeof password !== 'string') return res.status(400).json({ error: 'Password required.' });
  if (password.length > 128) return res.status(400).json({ error: 'Password too long.' });

  try {
    const sha1   = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);
    const cacheKey = `pwned:prefix:${prefix}`;

    let hashList = cache.get(cacheKey);
    if (!hashList) {
      const { data } = await axios.get(
        `https://api.pwnedpasswords.com/range/${prefix}`,
        { headers: { 'Add-Padding': 'true', 'User-Agent': 'CyberShield360-Free' }, timeout: 8000 }
      );
      hashList = data;
      cache.set(cacheKey, hashList, 86400);
    }

    const match    = hashList.split('\r\n').find(l => l.startsWith(suffix));
    const pwnCount = match ? parseInt(match.split(':')[1], 10) : 0;
    const strength = zxcvbn(password.slice(0, 100));

    return res.json({
      pwned: pwnCount > 0,
      pwnedCount: pwnCount,
      pwnedSeverity: pwnCount === 0 ? 'SAFE' : pwnCount < 100 ? 'LOW' : pwnCount < 10000 ? 'MEDIUM' : 'CRITICAL',
      strength: {
        score: strength.score,
        scoreLabel: ['Terrible','Weak','Fair','Strong','Very Strong'][strength.score],
        crackTimesDisplay: strength.crack_times_display,
        guessesLog10: Math.round(strength.guesses_log10 * 10) / 10,
        feedback: strength.feedback,
      },
      checkedAt: new Date().toISOString(),
    });
  } catch (err) {
    logger.error(`Pwned check error: ${err.message}`);
    return res.status(500).json({ error: 'Password check failed.' });
  }
});

// ════════════════════════════════════════════════════════════
//  POST /api/password/analyze — real-time strength (no network)
// ════════════════════════════════════════════════════════════
router.post('/analyze', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required.' });

  const s = zxcvbn(password.slice(0, 100));
  const charsetSize = getCharsetSize(password);
  const entropy = Math.round(password.length * Math.log2(charsetSize));

  return res.json({
    score:       s.score,
    scoreLabel:  ['Terrible','Weak','Fair','Strong','Very Strong'][s.score],
    entropy,
    charsetSize,
    length:      password.length,
    crackTimes:  s.crack_times_display,
    guessesLog10: Math.round(s.guesses_log10 * 10) / 10,
    feedback:    s.feedback,
    checks: {
      minLength:    password.length >= 12,
      hasUpper:     /[A-Z]/.test(password),
      hasLower:     /[a-z]/.test(password),
      hasNumber:    /[0-9]/.test(password),
      hasSymbol:    /[^A-Za-z0-9]/.test(password),
      notCommon:    !isCommon(password),
      noRepeats:    !/(.)\1{2,}/.test(password),
      noSequential: !isSequential(password),
    },
  });
});

// ════════════════════════════════════════════════════════════
//  GET /api/password/generate — crypto.randomBytes (free, built-in)
// ════════════════════════════════════════════════════════════
router.get('/generate', (req, res) => {
  const length  = Math.min(Math.max(parseInt(req.query.length) || 24, 8), 128);
  const upper   = req.query.upper   !== 'false';
  const lower   = req.query.lower   !== 'false';
  const numbers = req.query.numbers !== 'false';
  const symbols = req.query.symbols !== 'false';

  let charset = '';
  if (upper)   charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (lower)   charset += 'abcdefghijklmnopqrstuvwxyz';
  if (numbers) charset += '0123456789';
  if (symbols) charset += '!@#$%^&*-_=+?~';
  if (!charset) charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

  // Rejection sampling — true uniform distribution, no modulo bias
  const buf = crypto.randomBytes(length * 4);
  let pwd = '', i = 0;
  const maxByte = 256 - (256 % charset.length);
  while (pwd.length < length && i < buf.length) {
    const byte = buf[i++];
    if (byte < maxByte) pwd += charset[byte % charset.length];
  }
  // Fallback if buffer exhausted (extremely rare)
  while (pwd.length < length) {
    pwd += charset[crypto.randomInt(charset.length)];
  }

  const entropy = Math.round(length * Math.log2(charset.length));
  return res.json({ password: pwd, length, entropy, charsetSize: charset.length });
});

function getCharsetSize(pwd) {
  let s = 0;
  if (/[a-z]/.test(pwd)) s += 26;
  if (/[A-Z]/.test(pwd)) s += 26;
  if (/[0-9]/.test(pwd)) s += 10;
  if (/[^A-Za-z0-9]/.test(pwd)) s += 32;
  return s || 26;
}

const COMMON = new Set(['password','123456','qwerty','admin','letmein','welcome','monkey','dragon','master','login','abc123','password1','iloveyou','sunshine','princess','football','shadow','superman','batman']);
function isCommon(p) { return COMMON.has(p.toLowerCase()); }
function isSequential(p) {
  for (let i = 0; i < p.length - 2; i++) {
    const a = p.charCodeAt(i), b = p.charCodeAt(i+1), c = p.charCodeAt(i+2);
    if ((b === a+1 && c === a+2) || (b === a-1 && c === a-2)) return true;
  }
  return false;
}

module.exports = router;
