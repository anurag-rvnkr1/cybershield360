// logger.js — simple console logger, no paid logging service needed
const isProd = process.env.NODE_ENV === 'production';

function fmt(level, msg) {
  const ts = new Date().toISOString();
  return isProd ? JSON.stringify({ ts, level, msg }) : `${ts} [${level.toUpperCase().padEnd(5)}] ${msg}`;
}

const logger = {
  info:  (m) => console.log(fmt('info', m)),
  warn:  (m) => console.warn(fmt('warn', m)),
  error: (m) => console.error(fmt('error', m)),
  http:  (m) => process.env.NODE_ENV !== 'test' && console.log(fmt('http', m)),
  debug: (m) => process.env.DEBUG && console.log(fmt('debug', m)),
};

module.exports = logger;
