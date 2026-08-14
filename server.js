// ─────────────────────────────────────────
// server.js  —  Main Entry Point
// ─────────────────────────────────────────

require('dotenv').config();

const express            = require('express');
const http               = require('http');
const { WebSocketServer} = require('ws');
const { createClient }   = require('redis');
const path               = require('path');

const { createMiddleware } = require('./middleware');

const app    = express();
const server = http.createServer(app);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const redis = createClient({ url: process.env.REDIS_URL });
redis.on('error', (err) => console.log('❌ Redis Error:', err.message));
redis.on('connect', ()  => console.log('✅ Redis Connected'));

const wss = new WebSocketServer({ server });

wss.on('connection', (ws) => {
  console.log('📡 Dashboard connected');
  ws.send(JSON.stringify({ type: 'INFO', message: 'Connected to rate limiter!' }));
});

function broadcast(data) {
  wss.clients.forEach((client) => {
    if (client.readyState === 1) {
      client.send(JSON.stringify(data));
    }
  });
}

// /health has no rate limiting
app.get('/health', (req, res) => {
  res.json({ status: 'Server is running 🟢' });
});

async function start() {
  await redis.connect();

  // ✅ Middleware FIRST
  const rateLimiter = createMiddleware(redis, broadcast);
  app.use('/api', rateLimiter);

  // ✅ Routes AFTER middleware
  app.get('/api/hello', (req, res) => {
    res.json({ message: 'Hello! Your request was allowed ✅' });
  });

  app.get('/api/data', (req, res) => {
    res.json({ data: ['apple', 'banana', 'cherry'] });
  });

  server.listen(3000, () => {
    console.log('');
    console.log(' Server   →  http://localhost:3000');
    console.log(' Dashboard →  http://localhost:3000/dashboard.html');
    console.log('');
  });
}

start();