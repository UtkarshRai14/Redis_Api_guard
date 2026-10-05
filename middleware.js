// ─────────────────────────────────────────
// middleware.js  —  Runs on Every /api Request
// ─────────────────────────────────────────
//
//  This is the glue between the WAF, bot detection and the
//  token bucket. It runs before every /api route.
//
//  Flow:
//    Request comes in
//        ↓
//    Attack pattern?      → YES → block with 403 (WAF)
//        ↓ NO
//    Is it a bot?         → YES → block with 403
//        ↓ NO
//    Does it have tokens? → NO  → block with 429 (+ Retry-After)
//        ↓ YES
//    Allow request
//
//  The WAF runs first because it needs no Redis: it is cheap,
//  it still works during a Redis outage, and attack traffic is
//  rejected before it costs a Redis round trip.
//
//  If Redis fails during the bot / token bucket steps, the
//  request gets a 503. An outage is not reported as a rate limit.
//
//  Every decision is also sent to the dashboard as an event:
//    WAF | BOT | LIMITED | OK | REDIS_ERROR

const { checkTokenBucket } = require('./tokenBucket');
const { detectBot }        = require('./botDetector');
const { runWAF }           = require('./waf');

function createMiddleware(redis, broadcast) {

  // Send an event to the dashboard. ip, path and timestamp are added here
  // so every event has the same basic shape.
  function sendEvent(type, req, fields = {}) {
    broadcast({
      type,
      ip        : req.ip,
      path      : req.baseUrl + req.path,
      timestamp : Date.now(),
      ...fields,
    });
  }

  // This function runs on every request
  return async function (req, res, next) {
    try {
      // ── Step 0: WAF ─────────────────────────────────────────
      const wafResult = runWAF(req);

      if (wafResult.blocked) {
        sendEvent('WAF', req, { rule: wafResult.rule, detail: wafResult.detail });

        return res.status(403).json({
          error  : 'Blocked by WAF',
          rule   : wafResult.rule,
          detail : wafResult.detail,
        });
      }

      // ── Steps 1 and 2 need Redis ────────────────────────────
      let botResult;
      let bucketResult;

      try {
        // Step 1: Bot Detection
        botResult = await detectBot(redis, req);

        // Step 2: Token Bucket (only for requests that are not bots)
        if (!botResult.isBot) {
          bucketResult = await checkTokenBucket(redis, req.ip);
        }
      } catch (err) {
        // Log the real reason on the server, but never send it to the client
        console.error('Redis check failed:', err.message);
        sendEvent('REDIS_ERROR', req);

        return res.status(503).json({ error: 'Service temporarily unavailable' });
      }

      if (botResult.isBot) {
        sendEvent('BOT', req, {
          score   : botResult.score,
          reasons : botResult.reasons,
          signals : botResult.signals,
        });

        return res.status(403).json({
          error   : 'Bot detected',
          score   : botResult.score,
          reasons : botResult.reasons,
        });
      }

      if (bucketResult.allowed) {
        sendEvent('OK', req, { tokens: bucketResult.tokens, capacity: bucketResult.capacity });

        // Helpful header so the client knows how many tokens are left
        res.setHeader('X-Tokens-Remaining', bucketResult.tokens);
        return next(); // let the request through
      }

      // Out of tokens → 429 Too Many Requests
      sendEvent('LIMITED', req, {
        tokens     : bucketResult.tokens,
        capacity   : bucketResult.capacity,
        retryAfter : bucketResult.retryAfter,
      });

      res.setHeader('Retry-After', bucketResult.retryAfter);
      return res.status(429).json({
        error      : 'Too many requests',
        retryAfter : bucketResult.retryAfter, // seconds until one token is available
      });
    } catch (err) {
      // Anything unexpected goes to the error handler in server.js
      next(err);
    }
  };
}

module.exports = { createMiddleware };
