// ─────────────────────────────────────────
// script.js  —  Flood Test Script
// ─────────────────────────────────────────
//
//  Sends a burst of requests every second and prints how the
//  server answered, so you can watch the token bucket in action.
//
//  Usage:
//    node script.js [url]
//
//  The url is optional and defaults to http://localhost:3000/api/hello
//  Watch the dashboard at /dashboard.html while it runs.

const axios = require('axios');

const url = process.argv[2] || 'http://localhost:3000/api/hello';

const REQUESTS_PER_SECOND = 50;
const DURATION_SECONDS    = 10;

// Send one request and return how it ended, e.g. "200", "429" or "error (ECONNREFUSED)".
// validateStatus makes axios treat every HTTP status as a normal response.
async function sendRequest() {
  try {
    const res = await axios.get(url, { validateStatus: () => true, timeout: 5000 });
    return String(res.status);
  } catch (err) {
    return `error (${err.code || err.message})`;
  }
}

function addCount(counts, outcome) {
  counts[outcome] = (counts[outcome] || 0) + 1;
}

function formatCounts(counts) {
  return Object.entries(counts).map(([outcome, n]) => `${outcome}: ${n}`).join('   ');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  console.log(`Sending ${REQUESTS_PER_SECOND} requests/second to ${url} for ${DURATION_SECONDS} seconds\n`);

  const totals = {};

  for (let second = 1; second <= DURATION_SECONDS; second++) {
    const startedAt = Date.now();

    // All requests of this second are sent at the same time
    const outcomes = await Promise.all(
      Array.from({ length: REQUESTS_PER_SECOND }, sendRequest)
    );

    const thisSecond = {};
    for (const outcome of outcomes) {
      addCount(thisSecond, outcome);
      addCount(totals, outcome);
    }
    console.log(`second ${String(second).padStart(2)}  ${formatCounts(thisSecond)}`);

    await sleep(Math.max(0, 1000 - (Date.now() - startedAt)));
  }

  console.log(`\nTotal    ${formatCounts(totals)}`);
}

main();
