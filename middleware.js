// ─────────────────────────────────────────
// middleware.js  —  Runs on Every Request
// ─────────────────────────────────────────
//
//  This is the glue between bot detection and
//  token bucket. It runs before every /api route.
//
//  Flow:
//    Request comes in
//        ↓
//    Is it a bot?  → YES → block with 403
//        ↓ NO
//    Does it have tokens? → NO → block with 429
//        ↓ YES
//    Allow request ✅
//

const { checkTokenBucket } = require('./tokenBucket');
const { detectBot }        = require('./botDetector');
const { runWAF }           = require('./waf');

function createMiddleware(redis, broadcast) {

  // This function runs on every request
  return async function (req, res, next) {
    const ip = req.ip;

    // ── Step 0: WAF ─────────────────────────────────────────
    const wafResult = runWAF(req);

    if (wafResult.blocked) {
      broadcast({ type: 'WAF', ip, path: req.path, rule: wafResult.rule, detail: wafResult.detail });

      return res.status(403).json({
        error : '🛡️ Blocked by WAF.',
        rule  : wafResult.rule,
        detail: wafResult.detail,
      });
    }

    // ── Step 1: Bot Detection ───────────────────────────────
    const botResult = await detectBot(redis, req);

    if (botResult.isBot) {
      // Tell the dashboard about it
      broadcast({ type: 'BOT', ip, path: req.path, score: botResult.score, reasons: botResult.reasons });

      return res.status(403).json({
        error   : '🤖 Bot detected! Request blocked.',
        score   : botResult.score,
        reasons : botResult.reasons,
      });
    }

    // ── Step 2: Token Bucket ────────────────────────────────
    const bucketResult = await checkTokenBucket(redis, ip);

    // Send live update to WebSocket dashboard
    broadcast({
      type   : bucketResult.allowed ? 'OK' : 'LIMITED',
      ip,
      path   : req.path,
      tokens : bucketResult.tokens,
    });

    if (bucketResult.allowed) {
      // Add helpful headers so the client knows how many tokens are left
      res.setHeader('X-Tokens-Remaining', bucketResult.tokens);
      return next(); // ✅ let the request through
    }

    // Out of tokens → 429 Too Many Requests
    return res.status(429).json({
      error      : '🚫 Too many requests! Please slow down.',
      retryAfter : '1 second',
    });
  };
}

module.exports = { createMiddleware };
