// validators.js
function validateEmail(email) {
  if (typeof email !== 'string') return false;
  const t = email.trim();
  if (t.length < 3 || t.length > 254) return false;
  return /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(t);
}

function sanitise(str, max = 1000) {
  if (typeof str !== 'string') return '';
  return str.replace(/[\x00-\x08\x0B\x0E-\x1F\x7F]/g, '').slice(0, max);
}

module.exports = { validateEmail, sanitise };
