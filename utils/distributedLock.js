const crypto = require("crypto");

/**
 * Owner-aware mutex used to serialise work per resource (e.g. one booking at a time per creator).
 *
 * Every successful acquire returns a unique token and release only succeeds for that token.
 * Without ownership, a lock that expired (or was cleared by a stale timer) could be deleted by
 * its previous holder while a newer holder still relied on it, letting two requests into the
 * critical section at once.
 */

// Compare-and-delete: only remove the key if it still holds our token.
const RELEASE_SCRIPT =
  'if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end';

// key -> { token, timer } for the single-process fallback used when Redis is not configured.
const memoryLocks = new Map();

/**
 * @returns {Promise<string|null>} the ownership token, or null if the lock is held by someone else.
 */
async function acquireLock(redis, key, ttlSeconds) {
  const token = crypto.randomBytes(16).toString("hex");

  if (!redis) {
    if (memoryLocks.has(key)) return null;
    const timer = setTimeout(() => {
      // Expire only the lock this timer was created for, never a newer holder's lock.
      const current = memoryLocks.get(key);
      if (current && current.token === token) memoryLocks.delete(key);
    }, ttlSeconds * 1000);
    if (typeof timer.unref === "function") timer.unref();
    memoryLocks.set(key, { token, timer });
    return token;
  }

  try {
    const result = await redis.set(key, token, "EX", ttlSeconds, "NX");
    return result === "OK" ? token : null;
  } catch (err) {
    console.error("[Mutex] Redis lock error:", err);
    return null;
  }
}

/**
 * Release the lock only if `token` still owns it. Returns true if this call released it.
 */
async function releaseLock(redis, key, token) {
  if (!token) return false;

  if (!redis) {
    const current = memoryLocks.get(key);
    if (!current || current.token !== token) return false;
    clearTimeout(current.timer);
    memoryLocks.delete(key);
    return true;
  }

  try {
    if (typeof redis.eval === "function") {
      return Number(await redis.eval(RELEASE_SCRIPT, 1, key, token)) === 1;
    }
    // Client without EVAL: best-effort check-then-delete.
    if ((await redis.get(key)) === token) {
      await redis.del(key);
      return true;
    }
    return false;
  } catch (err) {
    console.error("[Mutex] Redis unlock error:", err);
    return false;
  }
}

module.exports = { acquireLock, releaseLock, RELEASE_SCRIPT };
