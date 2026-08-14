// ─────────────────────────────────────────
// tokenBucket.js  —  The Rate Limiting Logic
// ─────────────────────────────────────────

const MAX_TOKENS  = 10;  // bucket capacity
const REFILL_RATE = 0.2;   // tokens added per second

async function checkTokenBucket(redis, ip) {
  const key = `bucket:${ip}`;
  const now = Date.now();

  let bucket;

  try {
    const saved = await redis.get(key);
    bucket = saved
      ? JSON.parse(saved)
      : { tokens: MAX_TOKENS, lastTime: now };
  } catch (err) {
    // If Redis fails, fail CLOSED — block the request
    console.error('Redis error in tokenBucket:', err.message);
    return { allowed: false, tokens: 0 };
  }

  // Calculate how many tokens to add based on time passed
  const secondsPassed = (now - bucket.lastTime) / 1000;
  const tokensToAdd   = secondsPassed * REFILL_RATE;

  // Add tokens but never exceed the max
  bucket.tokens   = Math.min(MAX_TOKENS, bucket.tokens + tokensToAdd);
  bucket.lastTime = now;

  // If at least 1 token available → allow request
  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    await redis.setEx(key, 3600, JSON.stringify(bucket));
    return { allowed: true, tokens: Math.floor(bucket.tokens) };
  }

  // No tokens left → block
  await redis.setEx(key, 3600, JSON.stringify(bucket));
  return { allowed: false, tokens: 0 };
}

module.exports = { checkTokenBucket, MAX_TOKENS };
