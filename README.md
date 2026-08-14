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
└── .gitignore
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

## API Endpoints

### Health Check

```http
GET /health
```

Returns the server health status and is intentionally outside the rate-limited `/api` middleware.

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

Create an environment file:

```text
.env
```

Add your Redis connection string:

```env
REDIS_URL=redis://localhost:6379
```

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

## Testing Rate Limiting

The repository includes `script.js`, which repeatedly sends requests to the protected API endpoint to demonstrate the rate limiter.

Run it separately after starting the server:

```bash
node script.js
```

The dashboard can then be used to observe allowed and rate-limited requests in real time.

## Security Scope

This project is an educational implementation demonstrating API protection concepts and should not be treated as a production-ready WAF or enterprise security gateway.

The WAF uses pattern-based inspection and therefore cannot detect every possible attack technique. Likewise, the rate limiter demonstrates the token-bucket algorithm using Redis-backed state rather than providing a complete production-grade distributed rate-limiting system.

## License

This project is available for educational and portfolio purposes.
