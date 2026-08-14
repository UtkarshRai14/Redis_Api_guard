// ─────────────────────────────────────────
// botDetector.js  —  Detect Bot Requests
// ─────────────────────────────────────────
//
//  We give each request a SCORE (0 to 100).
//  Higher score = more likely a bot.
//  Score >= 60 → treat as bot → block it.
//
//  We check 3 simple things:
//
//  1. No User-Agent header        → bots often forget this  (+40)
//  2. Tool name in User-Agent     → curl/python are bot tools (+60)
//  3. Sending more than 10 req/s  → humans can't click this fast (+20)
//

// These strings in User-Agent = definitely a bot tool
const BOT_TOOLS = ['curl', 'python', 'wget', 'scrapy', 'httpie'];

async function detectBot(redis, req) {
  const ip = req.ip;
  const userAgent = req.headers['user-agent'] || ''; // what browser/tool sent the request

  let score   = 0;
  let reasons = [];

  // ── Check 1: No User-Agent header ──────────────────────────
  if (!userAgent) {
    score += 40;
    reasons.push('No User-Agent header');
  }

  // ── Check 2: Known bot tool in User-Agent ──────────────────
  // FIX: Score raised to 60 so a single tool match is enough to block
  const foundTool = BOT_TOOLS.find(tool => userAgent.toLowerCase().includes(tool));
  if (foundTool) {
    score += 60;
    reasons.push(`Bot tool detected: ${foundTool}`);
  }

  // ── Check 3: Request speed (more than 10 per second) ───────
  // FIX: expire is set only on first incr (atomic-safe pattern)
  // Old code did incr + expire as two separate ops — if connection dropped
  // between them, the key would never expire and counter would never reset.
  const speedKey = `speed:${ip}`;
  const reqCount = await redis.incr(speedKey);
  if (reqCount === 1) {
    await redis.expire(speedKey, 1); // set TTL only once, on first request
  }

  if (reqCount > 10) {
    score += 20;
    reasons.push(`Too fast: ${reqCount} requests/sec`);
  }

  // Final verdict
  const isBot = score >= 60;
  return { isBot, score, reasons };
}

module.exports = { detectBot };
