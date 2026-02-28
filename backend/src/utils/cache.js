// ═══════════════════════════════════════════════════════════════
//  CACHE — In-memory using node-cache (free, no Redis needed)
//
//  For Railway free tier (single instance), this is perfect.
//  If you scale to multiple instances later, swap to Upstash Redis:
//    Free plan: 10,000 req/day, 256MB — plenty for this project.
//    Add UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN to env,
//    then install @upstash/redis and swap the implementation below.
// ═══════════════════════════════════════════════════════════════
const NodeCache = require('node-cache');

const store = new NodeCache({
  stdTTL:      3600,   // default 1 hour TTL
  checkperiod: 600,    // clean up expired keys every 10 min
  useClones:   false,  // better performance for read-heavy workloads
});

module.exports = {
  type: 'in-memory',

  get(key) {
    return store.get(key) ?? null;
  },

  set(key, value, ttlSeconds = 3600) {
    store.set(key, value, ttlSeconds);
  },

  del(key) {
    store.del(key);
  },

  stats() {
    return store.getStats();
  },
};
