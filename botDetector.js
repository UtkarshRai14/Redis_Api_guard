// ─────────────────────────────────────────
// botDetector.js  —  Detect Bot Requests
// ─────────────────────────────────────────
//
//  We give each request a SCORE.
//  Higher score = more likely a bot.
//  Score >= 60 → treat as bot → block it.
//
//  We check 3 simple things:
//
//  1. No User-Agent header        → bots often forget this  (+40)
//  2. Tool name in User-Agent     → curl/python are bot tools (+60)
//  3. Sending more than 10 req/s  → humans can't click this fast (+20)
//
//  No single weak signal blocks a request on its own: a missing
//  User-Agent (40) or a fast burst (20) only blocks in combination.
//
//  This is a heuristic. A User-Agent is trivial to fake, so it only
//  catches lazy automation, not a determined attacker.
//
//  Redis errors are NOT caught here. They are thrown to the caller.

// These strings in User-Agent = definitely a bot tool
const BOT_TOOLS = ['curl', 'python', 'wget', 'scrapy', 'httpie'];

const SCORE_MISSING_USER_AGENT = 40;
const SCORE_KNOWN_TOOL         = 60;
const SCORE_TOO_FAST           = 20;

const BLOCK_SCORE             = 60;
const MAX_REQUESTS_PER_SECOND = 10;

// Counts requests from this IP in the current 1-second window.
// SET ... NX only creates the key (with its 1s TTL) if it does not exist yet, and
// INCR runs in the same MULTI, so the counter can never be left without an expiry.
async function countRequestsThisSecond(redis, ip) {
  const key = `guard:speed:${ip}`;
  const replies = await redis.multi()
    .set(key, 0, { EX: 1, NX: true })
    .incr(key)
    .exec();
  return replies[1];
}

async function detectBot(redis, req) {
  const userAgent = req.headers['user-agent'] || ''; // what browser/tool sent the request

  let score = 0;
  const reasons = [];
  const signals = { missingUserAgent: false, knownTool: false, tooFast: false };

  // ── Check 1: No User-Agent header ──────────────────────────
  if (!userAgent) {
    signals.missingUserAgent = true;
    score += SCORE_MISSING_USER_AGENT;
    reasons.push('No User-Agent header');
  }

  // ── Check 2: Known bot tool in User-Agent ──────────────────
  const foundTool = BOT_TOOLS.find(tool => userAgent.toLowerCase().includes(tool));
  if (foundTool) {
    signals.knownTool = true;
    score += SCORE_KNOWN_TOOL;
    reasons.push(`Bot tool detected: ${foundTool}`);
  }

  // ── Check 3: Request speed (more than 10 per second) ───────
  const requestCount = await countRequestsThisSecond(redis, req.ip);
  if (requestCount > MAX_REQUESTS_PER_SECOND) {
    signals.tooFast = true;
    score += SCORE_TOO_FAST;
    reasons.push(`Too fast: ${requestCount} requests/sec`);
  }

  // Final verdict.
  // `signals` is for code (the dashboard); `reasons` is human-readable text for logs.
  return { isBot: score >= BLOCK_SCORE, score, reasons, signals };
}

module.exports = { detectBot };
