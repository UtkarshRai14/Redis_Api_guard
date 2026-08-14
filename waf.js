// ─────────────────────────────────────────
// waf.js  —  Web Application Firewall
// ─────────────────────────────────────────
//
//  Inspects every request for attack patterns.
//  Runs before bot detection and rate limiting.
//
//  Checks:
//  1. HTTP Method       — only allow standard methods
//  2. URL / Path        — path traversal, SQLi, XSS in URL & query string
//  3. Request Headers   — oversized values, missing Host, SSRF headers, injection in values
//  4. Request Body      — SQLi, XSS, command injection, path traversal in JSON body
//  5. Content-Type      — POST/PUT/PATCH must declare a content type
//  6. Payload Size      — body > 10 KB is rejected
//
//  Returns: { blocked: true, rule: 'RULE_NAME', detail: '...' }
//        or { blocked: false }
//

// ── Attack pattern libraries ─────────────────────────────────────

const SQL_PATTERNS = [
  /(\b(select|insert|update|delete|drop|truncate|alter|exec|union)\b.*\b(from|where|table)\b)/i,
  /(--|;|\/\*|\*\/|xp_|sp_)/,
  /\b(or|and)\b\s*['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i,
  /\bsleep\s*\(\s*\d+\s*\)/i,
  /\bbenchmark\s*\(/i,
  /\bwaitfor\s+delay\b/i,
  /'\s*(or|and)\s*'/i,
];

const XSS_PATTERNS = [
  /<\s*script[\s\S]*?>/i,
  /<\/\s*script\s*>/i,
  /on\w+\s*=\s*["']?[^"'>]*/i,
  /javascript\s*:/i,
  /(%3c|%3e).*(%3c|%3e)/i,
  /<(iframe|object|embed|svg|img)[^>]*/i,
];

const CMD_PATTERNS = [
  /[;&|`](\s*(ls|cat|id|whoami|uname|wget|curl|bash|sh|nc|python|perl|php)\b)/i,
  /\$\{.*?\}/,
  /\{\{.*?\}\}/,
  /(\/etc\/passwd|\/etc\/shadow|\/proc\/self|cmd\.exe|\/bin\/sh)/i,
];

const TRAVERSAL_PATTERNS = [
  /\.\.[\/\\]/,
  /%2e%2e[%2f%5c]/i,
  /\.\.%2f/i,
  /%252e%252e/i,
  /(\/etc\/|\/var\/|\/proc\/|\/sys\/|\/root\/)/i,
];

// ── Config ────────────────────────────────────────────────────────

const ALLOWED_METHODS  = new Set(['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS']);
const MAX_BODY_BYTES   = 10 * 1024;
const MAX_HEADER_BYTES = 4  * 1024;
const BLOCKED_HEADERS  = ['x-forwarded-host', 'x-original-url', 'x-rewrite-url'];

// ── Helper ────────────────────────────────────────────────────────

function matchesAny(str, patterns) {
  if (typeof str !== 'string') return false;
  return patterns.some(p => p.test(str));
}

// ── Rule checkers ─────────────────────────────────────────────────

function checkMethod(req) {
  if (!ALLOWED_METHODS.has(req.method.toUpperCase()))
    return { blocked: true, rule: 'INVALID_METHOD', detail: `Method "${req.method}" is not allowed` };
  return { blocked: false };
}

function checkPath(req) {
  const raw       = req.url || '';
  const decoded   = (() => { try { return decodeURIComponent(raw); } catch { return raw; } })();
  const qs        = raw.includes('?') ? raw.split('?')[1] : '';
  const decodedQs = (() => { try { return decodeURIComponent(qs); } catch { return qs; } })();

  if (matchesAny(decoded,   TRAVERSAL_PATTERNS)) return { blocked: true, rule: 'PATH_TRAVERSAL',  detail: 'Path traversal attempt in URL' };
  if (matchesAny(decoded,   SQL_PATTERNS))        return { blocked: true, rule: 'SQLI_IN_URL',     detail: 'SQL injection pattern in URL' };
  if (matchesAny(decoded,   XSS_PATTERNS))        return { blocked: true, rule: 'XSS_IN_URL',      detail: 'XSS pattern in URL' };
  if (matchesAny(decoded,   CMD_PATTERNS))        return { blocked: true, rule: 'CMD_IN_URL',      detail: 'Command injection in URL' };
  if (matchesAny(decodedQs, SQL_PATTERNS))        return { blocked: true, rule: 'SQLI_IN_QUERY',   detail: 'SQL injection in query string' };
  if (matchesAny(decodedQs, XSS_PATTERNS))        return { blocked: true, rule: 'XSS_IN_QUERY',    detail: 'XSS pattern in query string' };
  if (matchesAny(decodedQs, CMD_PATTERNS))        return { blocked: true, rule: 'CMD_IN_QUERY',    detail: 'Command injection in query string' };

  return { blocked: false };
}

function checkHeaders(req) {
  const h = req.headers;

  if (!h['host'])
    return { blocked: true, rule: 'MISSING_HOST', detail: 'Host header is required' };

  for (const [name, value] of Object.entries(h)) {
    if (typeof value === 'string') {
      if (value.length > MAX_HEADER_BYTES)
        return { blocked: true, rule: 'OVERSIZED_HEADER', detail: `Header "${name}" exceeds ${MAX_HEADER_BYTES} bytes` };
      if (matchesAny(value, XSS_PATTERNS))
        return { blocked: true, rule: 'XSS_IN_HEADER', detail: `XSS pattern in header "${name}"` };
      if (matchesAny(value, CMD_PATTERNS))
        return { blocked: true, rule: 'CMD_IN_HEADER', detail: `Command injection in header "${name}"` };
    }
  }

  for (const bad of BLOCKED_HEADERS) {
    if (h[bad])
      return { blocked: true, rule: 'SSRF_HEADER', detail: `Header "${bad}" is not permitted` };
  }

  const cl = h['content-length'];
  if (cl !== undefined && (isNaN(Number(cl)) || Number(cl) < 0))
    return { blocked: true, rule: 'INVALID_CONTENT_LENGTH', detail: 'Content-Length has an invalid value' };

  return { blocked: false };
}

function checkBody(req) {
  if (!req.body || typeof req.body !== 'object' || Object.keys(req.body).length === 0)
    return { blocked: false };

  const serialised = JSON.stringify(req.body);
  if (serialised.length > MAX_BODY_BYTES)
    return { blocked: true, rule: 'OVERSIZED_BODY', detail: `Body exceeds ${MAX_BODY_BYTES / 1024} KB` };

  function* strings(obj, depth = 0) {
    if (depth > 10) return;
    if (typeof obj === 'string') { yield obj; return; }
    if (obj && typeof obj === 'object') {
      for (const v of Object.values(obj)) yield* strings(v, depth + 1);
    }
  }

  for (const val of strings(req.body)) {
    if (matchesAny(val, SQL_PATTERNS))       return { blocked: true, rule: 'SQLI_IN_BODY',      detail: 'SQL injection in request body' };
    if (matchesAny(val, XSS_PATTERNS))       return { blocked: true, rule: 'XSS_IN_BODY',       detail: 'XSS pattern in request body' };
    if (matchesAny(val, CMD_PATTERNS))       return { blocked: true, rule: 'CMD_IN_BODY',        detail: 'Command injection in request body' };
    if (matchesAny(val, TRAVERSAL_PATTERNS)) return { blocked: true, rule: 'TRAVERSAL_IN_BODY', detail: 'Path traversal in request body' };
  }

  return { blocked: false };
}

function checkContentType(req) {
  if (!['POST','PUT','PATCH'].includes(req.method.toUpperCase())) return { blocked: false };
  if (!req.headers['content-type'])
    return { blocked: true, rule: 'MISSING_CONTENT_TYPE', detail: 'POST/PUT/PATCH must include Content-Type' };
  return { blocked: false };
}

// ── Main export ───────────────────────────────────────────────────

function runWAF(req) {
  const checks = [checkMethod, checkPath, checkHeaders, checkContentType, checkBody];
  for (const check of checks) {
    const result = check(req);
    if (result.blocked) return result;
  }
  return { blocked: false };
}

module.exports = { runWAF };
