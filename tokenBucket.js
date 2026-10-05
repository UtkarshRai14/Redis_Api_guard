// ─────────────────────────────────────────
// tokenBucket.js  —  The Rate Limiting Logic
// ─────────────────────────────────────────
//
//  Each IP has a bucket that holds up to MAX_TOKENS tokens.
//  Every request costs 1 token. Tokens refill over time
//  at REFILL_RATE tokens per second.
//
//  The whole "read → refill → consume → save" sequence runs
//  as ONE Lua script inside Redis. Redis executes a script
//  without interleaving other commands, so two concurrent
//  requests from the same IP can never spend the same token.
//  (A separate GET and SET from Node would allow exactly that.)
//
//  Redis errors are NOT caught here. They are thrown to the
//  caller, so an outage is never mistaken for a rate-limit decision.

const MAX_TOKENS  = 10;    // bucket capacity
const REFILL_RATE = 0.2;   // tokens added per second (1 token every 5 seconds)

// A bucket is full again after MAX_TOKENS / REFILL_RATE seconds of inactivity,
// so expiring an idle key loses nothing. One hour just cleans up old keys.
const BUCKET_TTL_SECONDS = 3600;

// KEYS[1] = bucket key
// ARGV    = capacity, refill rate (tokens/sec), current time (ms), key TTL (seconds)
// Returns { allowed (1 or 0), tokens left as a string }
// The token count is returned as a string because Redis would truncate a Lua number to an integer.
const TOKEN_BUCKET_SCRIPT = `
local capacity   = tonumber(ARGV[1])
local refillRate = tonumber(ARGV[2])
local now        = tonumber(ARGV[3])
local ttl        = tonumber(ARGV[4])

local saved    = redis.call('HMGET', KEYS[1], 'tokens', 'lastTime')
local tokens   = tonumber(saved[1])
local lastTime = tonumber(saved[2])

-- New IP (or unreadable state): start with a full bucket
if tokens == nil or lastTime == nil then
  tokens   = capacity
  lastTime = now
end

-- Add tokens for the time that has passed, but never exceed the capacity.
-- (max(0, ...) guards against the clock moving backwards.)
local secondsPassed = math.max(0, (now - lastTime) / 1000)
tokens = math.min(capacity, tokens + secondsPassed * refillRate)

local allowed = 0
if tokens >= 1 then
  tokens  = tokens - 1
  allowed = 1
end

redis.call('HSET', KEYS[1], 'tokens', tokens, 'lastTime', now)
redis.call('EXPIRE', KEYS[1], ttl)

return { allowed, tostring(tokens) }
`;

// Seconds until the bucket holds one whole token again (rounded up, at least 1)
function secondsUntilNextToken(tokens) {
  const seconds = (1 - tokens) / REFILL_RATE;
  // toFixed avoids floating-point noise such as 2.0000000000000004 rounding up to 3
  return Math.max(1, Math.ceil(Number(seconds.toFixed(3))));
}

async function checkTokenBucket(redis, ip) {
  const [allowed, tokensLeft] = await redis.eval(TOKEN_BUCKET_SCRIPT, {
    keys: [`guard:bucket:${ip}`],
    arguments: [
      String(MAX_TOKENS),
      String(REFILL_RATE),
      String(Date.now()),
      String(BUCKET_TTL_SECONDS),
    ],
  });

  const tokens = Number(tokensLeft);

  if (allowed === 1) {
    return { allowed: true, tokens: Math.floor(tokens), capacity: MAX_TOKENS };
  }

  return {
    allowed    : false,
    tokens     : 0,
    capacity   : MAX_TOKENS,
    retryAfter : secondsUntilNextToken(tokens),
  };
}

module.exports = { checkTokenBucket, MAX_TOKENS, REFILL_RATE };
