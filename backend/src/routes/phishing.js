// ═══════════════════════════════════════════════════════════════
//  PHISHING ROUTE — pure logic, zero external API cost
// ═══════════════════════════════════════════════════════════════
const express = require('express');
const { URL }  = require('url');
const logger   = require('../utils/logger');
const router   = express.Router();

const RISKY_TLDS   = new Set(['.xyz','.tk','.ml','.cf','.gq','.ga','.top','.click','.link','.buzz','.work','.loan','.online','.site','.website','.tech']);
const MAJOR_BRANDS = ['paypal','amazon','microsoft','apple','google','facebook','instagram','netflix','spotify','twitter','linkedin','github','dropbox','icloud','chase','wellsfargo','bankofamerica','coinbase','binance'];

router.post('/analyze-url', (req, res) => {
  const { url: raw } = req.body;
  if (!raw || typeof raw !== 'string' || raw.length > 2048) return res.status(400).json({ error: 'Invalid URL.' });

  const indicators = [];
  const lower = raw.toLowerCase();
  let parsed;
  try { parsed = new URL(raw.startsWith('http') ? raw : 'https://' + raw); }
  catch { return res.json({ riskScore: 85, riskLevel: 'CRITICAL', safe: false, indicators: [{ type: 'INVALID_URL', severity: 'CRITICAL', description: 'URL is malformed — cannot be parsed.' }] }); }

  const domain  = parsed.hostname.toLowerCase();
  const tld     = '.' + domain.split('.').pop();
  const path    = parsed.pathname + parsed.search;

  if (parsed.protocol === 'http:') indicators.push({ type: 'NO_HTTPS', severity: 'HIGH', description: 'Not using HTTPS — all data transmitted in plaintext and intercept-able.' });
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) indicators.push({ type: 'IP_ADDRESS', severity: 'CRITICAL', description: 'Raw IP address used instead of domain — no legitimate site does this.' });
  if ((domain.match(/-/g)||[]).length >= 3) indicators.push({ type: 'EXCESSIVE_HYPHENS', severity: 'MEDIUM', description: 'Multiple hyphens in domain (classic typosquatting technique).' });
  if (RISKY_TLDS.has(tld)) indicators.push({ type: 'RISKY_TLD', severity: 'HIGH', description: `"${tld}" is a free TLD massively abused for phishing (>60% of phishing sites).` });
  MAJOR_BRANDS.forEach(b => {
    if (lower.includes(b) && !domain.endsWith(`${b}.com`) && !domain.endsWith(`${b}.net`) && !domain.endsWith(`${b}.org`))
      indicators.push({ type: 'BRAND_IMPERSONATION', severity: 'CRITICAL', description: `"${b}" appears in URL but doesn't match the official domain — impersonation detected.` });
  });
  if (domain.split('.').length > 5) indicators.push({ type: 'DEEP_SUBDOMAIN', severity: 'MEDIUM', description: 'Too many subdomains — common tactic to bury the real malicious domain.' });
  if (raw.length > 150) indicators.push({ type: 'LONG_URL', severity: 'LOW', description: 'Unusually long URL — often used to obscure destination via redirect chains.' });
  if ((path.match(/%[0-9a-f]{2}/gi)||[]).length > 3) indicators.push({ type: 'URL_ENCODING', severity: 'MEDIUM', description: 'Heavy URL encoding — may be hiding malicious parameters or paths.' });
  const suspKw = ['login','signin','verify','secure','account','update','confirm','authenticate','banking','wallet'];
  const found  = suspKw.filter(k => path.includes(k));
  if (found.length >= 2) indicators.push({ type: 'SUSPICIOUS_KEYWORDS', severity: 'MEDIUM', description: `Credential-harvesting keywords in path: ${found.join(', ')}` });
  if (/[0oO]{2}|1l|rn(?=[a-z])|vv/.test(domain)) indicators.push({ type: 'HOMOGRAPH', severity: 'HIGH', description: 'Possible lookalike characters in domain (0→O, rn→m) — classic visual spoofing.' });

  const W = { CRITICAL: 35, HIGH: 20, MEDIUM: 10, LOW: 5 };
  const riskScore = Math.min(indicators.reduce((s, i) => s + (W[i.severity] || 0), 0), 100);
  const riskLevel = riskScore >= 70 ? 'CRITICAL' : riskScore >= 40 ? 'HIGH' : riskScore >= 20 ? 'MEDIUM' : riskScore > 0 ? 'LOW' : 'SAFE';

  logger.info(`URL analysis: ${domain} → risk=${riskScore}`);
  return res.json({ url: raw, domain, riskScore, riskLevel, safe: riskScore < 20, indicators: indicators.sort((a,b) => W[b.severity]-W[a.severity]), checkedAt: new Date().toISOString() });
});

router.post('/analyze-email', (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'Email content required.' });

  const indicators = [];
  const rules = [
    { re: /urgent|immediately|action required|expire.*hour|expire.*24|respond.*now|limited time/i, type: 'URGENCY', sev: 'HIGH', desc: 'Urgency/fear tactics — pressures victim into bypassing critical thinking.' },
    { re: /account.*(suspended|closed|compromised|terminated)|unauthorized.*access/i, type: 'ACCOUNT_THREAT', sev: 'HIGH', desc: 'Account suspension threat — the #1 phishing hook globally.' },
    { re: /dear (customer|user|member|sir|madam|valued)/i, type: 'GENERIC_GREETING', sev: 'MEDIUM', desc: 'Generic greeting — real companies address you by name.' },
    { re: /click here|click.*link|tap here/i, type: 'CLICKBAIT', sev: 'MEDIUM', desc: 'Vague click-bait language — never click without verifying destination.' },
    { re: /password|pin|passphrase/i, type: 'PASSWORD_REQUEST', sev: 'CRITICAL', desc: 'Requesting password via email — ZERO legitimate services do this.' },
    { re: /social security|ssn|\btan\b|national id/i, type: 'GOVT_ID_REQUEST', sev: 'CRITICAL', desc: 'Requesting government ID — almost certainly fraud.' },
    { re: /credit card|card number|cvv|billing detail/i, type: 'CARD_REQUEST', sev: 'HIGH', desc: 'Requesting card details over email — do NOT provide.' },
    { re: /prize|winner|lottery|you.*won|claim.*reward|gift card/i, type: 'PRIZE_SCAM', sev: 'CRITICAL', desc: 'Lottery/prize scam — you cannot win contests you never entered.' },
    { re: /bitcoin|crypto|wire transfer|western union|moneygram/i, type: 'UNTRACEABLE_PAYMENT', sev: 'CRITICAL', desc: 'Untraceable payment method — definitive scam signature.' },
    { re: /paypa1|amaz0n|m1crosoft|g00gle|app1e|faceb00k/i, type: 'TYPOSQUATTING', sev: 'CRITICAL', desc: 'Brand name misspelled with digit substitution — phishing impersonation.' },
    { re: /\.(exe|zip|bat|vbs|js|scr|msi|dmg|ps1)\b/i, type: 'DANGEROUS_ATTACHMENT', sev: 'CRITICAL', desc: 'Dangerous file type referenced — likely malware delivery.' },
    { re: /verify.*identity|confirm.*identity/i, type: 'IDENTITY_HARVEST', sev: 'HIGH', desc: 'Identity verification request — data harvesting tactic.' },
    { re: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i, type: 'IP_IN_BODY', sev: 'HIGH', desc: 'Raw IP address in email body — legitimate links use domain names.' },
  ];

  rules.forEach(r => { if (r.re.test(content)) indicators.push({ type: r.type, severity: r.sev, description: r.desc }); });

  const W = { CRITICAL: 35, HIGH: 20, MEDIUM: 10, LOW: 5 };
  const riskScore = Math.min(indicators.reduce((s,i) => s+(W[i.severity]||0), 0), 100);
  const riskLevel = riskScore >= 70 ? 'CRITICAL' : riskScore >= 40 ? 'HIGH' : riskScore >= 20 ? 'MEDIUM' : riskScore > 0 ? 'LOW' : 'SAFE';

  return res.json({
    riskScore, riskLevel, safe: riskScore < 15, indicatorCount: indicators.length,
    indicators: indicators.sort((a,b) => W[b.severity]-W[a.severity]),
    recommendation: riskScore >= 70 ? 'DELETE IMMEDIATELY — do not click or download anything.'
      : riskScore >= 40 ? 'HIGH SUSPICION — verify sender independently.'
      : riskScore >= 20 ? 'Caution — some suspicious patterns found.'
      : 'No significant phishing indicators detected.',
    checkedAt: new Date().toISOString(),
  });
});

module.exports = router;
