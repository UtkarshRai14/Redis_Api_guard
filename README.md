# Redis API Guard

Redis-backed API protection middleware for Express.js combining token-bucket rate limiting, heuristic bot detection, custom WAF rules, and real-time WebSocket monitoring.

## Overview

Redis API Guard is a Node.js/Express.js security layer designed to demonstrate how multiple API protection mechanisms can work together in a request-processing pipeline.

Each request to the protected `/api` routes passes through:

```text
Incoming Request
       ↓
     WAF
       ↓
 Bot Detection
       ↓
Token Bucket
       ↓
Allow / 403 / 429
       ↓
WebSocket Dashboard
```

## Features

* Redis-backed token-bucket rate limiting
* Per-IP request limiting
* Token refill based on elapsed time
* Heuristic bot detection
* Detection of common automation tools
* Request-rate based bot scoring
* Custom WAF request inspection
* SQL injection pattern detection
* XSS pattern detection
* Command injection detection
* Path traversal detection
* Suspicious header detection
* Request body and header size checks
* HTTP method validation
* Real-time WebSocket monitoring
* Live security event dashboard
* Request flood testing script

## Tech Stack

* **Node.js**
* **Express.js**
* **Redis**
* **WebSocket (`ws`)**
* **Axios**
* **HTML / CSS / JavaScript**

## Project Structure

```text
.
├── public/
│   └── dashboard.html
├── botDetector.js
├── middleware.js
├── server.js
├── tokenBucket.js
├── waf.js
├── script.js
├── package.json
├── package-lock.json
├── .env.example
├── .gitignore
└── README.md
```

## Request Protection Flow

The middleware processes protected API requests in three stages.

### 1. WAF Inspection

The request is inspected for suspicious patterns before reaching the application routes.

The WAF checks areas including:

* URL and query parameters
* Request headers
* JSON request bodies
* HTTP methods
* Content type
* Payload size

Suspicious requests receive a `403 Forbidden` response.

### 2. Bot Detection

Requests are assigned a heuristic bot score using signals such as:

* Missing User-Agent
* Known automation tools
* Excessive request frequency

Requests that reach the configured bot threshold are rejected with `403 Forbidden`.

### 3. Token Bucket Rate Limiting

Each client IP receives a Redis-backed token bucket.

The current configuration uses:

* Bucket capacity: **10 tokens**
* Refill rate: **0.2 tokens/second**
* Bucket state stored in Redis
* Bucket entries expire after inactivity

When no token is available, the API returns:

```text
429 Too Many Requests
```

The response includes a `Retry-After` header. Allowed responses include an `X-Tokens-Remaining` header.

If Redis is unavailable, bot detection and rate limiting cannot run, so `/api` requests receive `503 Service Unavailable` instead of being let through or reported as rate-limited.

## API Endpoints

### Health Check

```http
GET /health
```

Returns `200` when Redis is ready and `503` when it is not. It is intentionally outside the rate-limited `/api` middleware.

### Hello

```http
GET /api/hello
```

Returns a response when the request passes the protection layers.

### Data

```http
GET /api/data
```

Returns sample API data when the request is allowed.

## Monitoring Dashboard

The project includes a browser-based dashboard available at:

```text
http://localhost:3000/dashboard.html
```

The dashboard receives live events through WebSocket and provides visibility into:

* Allowed requests
* Rate-limited requests
* Bot detections
* WAF blocks
* Token bucket state
* Recent request activity

## Requirements

Before running the project, make sure you have:

* Node.js installed
* Redis running locally or a reachable Redis instance

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/UtkarshRai14/Redis_Api_guard.git
cd Redis_Api_guard
npm install
```

Create an environment file from the example:

```bash
cp .env.example .env
```

| Variable      | Default                  | Description |
| ------------- | ------------------------ | ----------- |
| `REDIS_URL`   | `redis://localhost:6379` | Redis connection string |
| `PORT`        | `3000`                   | HTTP port for the API and dashboard |
| `TRUST_PROXY` | `false`                  | Set when running behind a reverse proxy so client IPs are read from `X-Forwarded-For`: a hop count (`1`), `loopback`, or a comma-separated list of proxy IPs. Avoid `true`, which lets clients fake their IP. |

## Running the Server

Start the application with:

```bash
npm start
```

The server runs on:

```text
http://localhost:3000
```

Open the monitoring dashboard:

```text
http://localhost:3000/dashboard.html
```

## Deploying to Render

The repository includes a `render.yaml` Blueprint that creates the web service and a Render Key Value (Redis) instance in the same region and connects them.

1. In the Render Dashboard, click **New → Blueprint**.
2. Select this repository and click **Apply**.

Both services use Render's free plan: the web service spins down after 15 minutes without traffic (the next request takes about a minute to wake it), and the free Key Value instance keeps data in memory only, so rate-limit state resets if it restarts.

## Testing Rate Limiting

The repository includes `script.js`, which sends 50 requests per second for 10 seconds to the protected API endpoint and prints how many requests got each response status.

Run it separately after starting the server (the URL is optional and defaults to `http://localhost:3000/api/hello`):

```bash
node script.js [url]
```

The dashboard can then be used to observe allowed and rate-limited requests in real time.

## Security Scope

This project is an educational implementation demonstrating API protection concepts and should not be treated as a production-ready WAF or enterprise security gateway.

The WAF uses pattern-based inspection and therefore cannot detect every possible attack technique. Likewise, the rate limiter demonstrates the token-bucket algorithm using Redis-backed state rather than providing a complete production-grade distributed rate-limiting system.

## License

This project is available for educational and portfolio purposes.
