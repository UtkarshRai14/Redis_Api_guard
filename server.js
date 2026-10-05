// ─────────────────────────────────────────
// server.js  —  Main Entry Point
// ─────────────────────────────────────────

require('dotenv').config();

const express            = require('express');
const http               = require('http');
const { WebSocketServer } = require('ws');
const { createClient }   = require('redis');
const path               = require('path');

const { createMiddleware }        = require('./middleware');
const { MAX_TOKENS, REFILL_RATE } = require('./tokenBucket');

const PORT      = process.env.PORT || 3000;
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

// TRUST_PROXY tells Express whether to believe the X-Forwarded-For header when
// working out req.ip. The rate limiter and bot detector key everything on req.ip.
//   not set / "false" → never trust it (safe default: use the socket address)
//   "1", "2", ...     → trust that many reverse proxies in front of this app
//   "loopback" or a comma-separated list of proxy IPs → trust those addresses
// "true" trusts every hop, so a client can fake its IP. Avoid it.
function parseTrustProxy(value) {
  if (!value || value === 'false') return false;
  if (value === 'true') return true;
  if (/^\d+$/.test(value)) return Number(value);
  return value;
}

const app    = express();
const server = http.createServer(app);

app.set('trust proxy', parseTrustProxy(process.env.TRUST_PROXY));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Redis ───────────────────────────────────────────────────────
// The HTTP server does not wait for Redis. If Redis is down, /health still
// answers and /api requests get a 503. The client keeps retrying in the background.
// disableOfflineQueue makes commands fail straight away while Redis is down,
// instead of waiting in a queue (which would make requests hang).
const redis = createClient({
  url: REDIS_URL,
  disableOfflineQueue: true,
  socket: { reconnectStrategy: (retries) => Math.min(retries * 100, 3000) },
});
redis.on('error', (err) => console.error('Redis error:', err.message));
redis.on('ready', ()    => console.log('Redis ready'));
redis.on('end',   ()    => console.log('Redis connection closed'));

// ── WebSocket (dashboard) ───────────────────────────────────────
const wss = new WebSocketServer({ server });

wss.on('connection', (ws) => {
  console.log('Dashboard connected');
  ws.on('error', (err) => console.error('WebSocket error:', err.message));
  ws.send(JSON.stringify({
    type       : 'INFO',
    message    : 'Connected to Redis API Guard',
    capacity   : MAX_TOKENS,
    refillRate : REFILL_RATE,
  }));
});

function broadcast(data) {
  wss.clients.forEach((client) => {
    if (client.readyState === 1) {
      client.send(JSON.stringify(data));
    }
  });
}

// ── Routes ──────────────────────────────────────────────────────
// /health is outside /api, so it has no WAF, bot check or rate limit.
// It reports Redis state honestly: 200 when Redis is ready, 503 when it is not.
app.get('/health', (req, res) => {
  if (redis.isReady) {
    return res.json({ status: 'ok', redis: 'ready' });
  }
  res.status(503).json({ status: 'degraded', redis: 'unavailable' });
});

// Middleware FIRST, routes AFTER it
app.use('/api', createMiddleware(redis, broadcast));

app.get('/api/hello', (req, res) => {
  res.json({ message: 'Hello! Your request was allowed' });
});

app.get('/api/data', (req, res) => {
  res.json({ data: ['apple', 'banana', 'cherry'] });
});

// ── Error handling ──────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Client mistakes (e.g. malformed JSON) keep their own 4xx status with a safe message.
// Anything else is a server error: log it here, but never send details to the client.
const CLIENT_ERROR_MESSAGES = {
  'entity.parse.failed': 'Invalid JSON body',
  'entity.too.large'   : 'Request body too large',
};

// Express recognises an error handler by its 4 parameters
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  if (err.status >= 400 && err.status < 500) {
    return res.status(err.status).json({ error: CLIENT_ERROR_MESSAGES[err.type] || 'Bad request' });
  }

  console.error('Unexpected error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start ───────────────────────────────────────────────────────
server.listen(PORT, () => {
  const { port } = server.address();
  console.log('');
  console.log(` Server    →  http://localhost:${port}`);
  console.log(` Dashboard →  http://localhost:${port}/dashboard.html`);
  console.log('');
});

redis.connect().catch((err) => console.error('Redis connect failed:', err.message));
