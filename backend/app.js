'use strict';

// The API request handler. No frameworks, no auth libraries: node:crypto only.
// server.js reads the environment and passes the config in, so the tests can
// build the same app with their own config.

const crypto = require('node:crypto');
const jwt = require('./jwt');

const USERNAME = 'admin';
const COOKIE_NAME = '__Host-token';
const MAX_BODY_BYTES = 1024;
const RATE_WINDOW_MS = 10_000;

/**
 * Fixed-window counter per client IP. The whole table is wiped every window,
 * so memory stays bounded no matter how many addresses hit us.
 */
function createRateLimiter(limit, windowMs) {
  const hits = new Map();
  setInterval(() => hits.clear(), windowMs).unref();
  return function allow(ip) {
    if (hits.size > 100_000) hits.clear();
    const count = (hits.get(ip) || 0) + 1;
    hits.set(ip, count);
    return count <= limit;
  };
}

function readCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const pair of header.split(';')) {
    const eq = pair.indexOf('=');
    if (eq !== -1 && pair.slice(0, eq).trim() === name) return pair.slice(eq + 1).trim();
  }
  return null;
}

/** Read a small JSON body. Resolves to null if it is too big or not JSON. */
function readJsonBody(req) {
  return new Promise((resolve) => {
    if (Number(req.headers['content-length']) > MAX_BODY_BYTES) return resolve(null);
    const chunks = [];
    let size = 0;
    let done = false;
    const finish = (value) => {
      if (!done) {
        done = true;
        resolve(value);
      }
    };
    req.on('data', (chunk) => {
      if (done) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) finish(null);
      else chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        finish(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        finish(null);
      }
    });
    req.on('error', () => finish(null));
    req.on('close', () => finish(null));
  });
}

/**
 * @param {object} config
 * @param {string} config.password        admin password
 * @param {string} config.secret          the secret shown on the landing page
 * @param {string} config.jwtKey          JWT signing key (must survive restarts)
 * @param {string[]} config.allowedOrigins  frontend origins allowed by CORS
 * @param {number} [config.tokenTtlSeconds]
 * @param {number} [config.trustedProxyHops]  proxies in front of us that append to X-Forwarded-For
 * @param {number} [config.requestLimit]  requests per IP per 10 s
 * @param {number} [config.loginLimit]    login attempts per IP per 10 s (Infinity = off)
 */
function createApp(config) {
  const {
    password,
    secret,
    jwtKey,
    allowedOrigins,
    tokenTtlSeconds = 3 * 60 * 60,
    trustedProxyHops = 0,
    // Limits are per IP address, and many honest users can share one address
    // (a campus network), so the general limit is a circuit breaker for real
    // floods only: normal requests cost microseconds and need no throttling.
    requestLimit = 20_000,
    loginLimit = 50,
  } = config;

  const allowRequest = createRateLimiter(requestLimit, RATE_WINDOW_MS);
  const allowLogin = createRateLimiter(loginLimit, RATE_WINDOW_MS);

  // Constant-time string comparison. Both sides are HMACed with a random
  // per-process key first, so the buffers are always the same length and the
  // timing reveals nothing about the real password, not even its length.
  // (Deliberately not a slow hash like bcrypt: there is no password database
  // to protect, and a slow hash would hand attackers a CPU-exhaustion lever.)
  const compareKey = crypto.randomBytes(32);
  const digest = (value) => crypto.createHmac('sha256', compareKey).update(String(value)).digest();
  const usernameDigest = digest(USERNAME);
  const passwordDigest = digest(password);
  function credentialsMatch(username, pass) {
    if (typeof username !== 'string' || typeof pass !== 'string') return false;
    const userOk = crypto.timingSafeEqual(digest(username), usernameDigest);
    const passOk = crypto.timingSafeEqual(digest(pass), passwordDigest);
    return userOk && passOk;
  }

  // HttpOnly: page JavaScript cannot read it (XSS cannot steal the token).
  // Secure: HTTPS only. SameSite=None: required because the frontend is on a
  // different site. Partitioned: keeps working when the browser blocks
  // third-party cookies. __Host- prefix: browser refuses the cookie unless it
  // is Secure, Path=/ and has no Domain, so no other subdomain can plant one.
  const cookieAttributes = 'HttpOnly; Secure; SameSite=None; Partitioned; Path=/';
  const sessionCookie = (token) => `${COOKIE_NAME}=${token}; ${cookieAttributes}; Max-Age=${tokenTtlSeconds}`;
  const clearedCookie = `${COOKIE_NAME}=; ${cookieAttributes}; Max-Age=0`;

  function clientIp(req) {
    if (trustedProxyHops > 0) {
      const forwarded = req.headers['x-forwarded-for'];
      if (typeof forwarded === 'string') {
        // Entries are appended left to right; only the ones our own proxies
        // added (the rightmost) can be trusted. The left side is attacker text.
        const chain = forwarded.split(',');
        const ip = chain[chain.length - trustedProxyHops];
        if (ip && ip.trim()) return ip.trim();
      }
    }
    return req.socket.remoteAddress || 'unknown';
  }

  function send(req, res, status, body, extraHeaders) {
    const headers = {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      Vary: 'Origin',
      ...extraHeaders,
    };
    const origin = req.headers.origin;
    if (origin && allowedOrigins.includes(origin)) {
      headers['Access-Control-Allow-Origin'] = origin; // exact origin, never "*"
      headers['Access-Control-Allow-Credentials'] = 'true';
    }
    const text = body === null ? '' : JSON.stringify(body);
    headers['Content-Length'] = Buffer.byteLength(text);
    res.writeHead(status, headers);
    res.end(req.method === 'HEAD' ? undefined : text);
  }

  /** Returns the JWT payload for this request, or null if not logged in. */
  function authenticate(req) {
    return jwt.verify(readCookie(req, COOKIE_NAME), jwtKey);
  }

  async function handleLogin(req, res) {
    if (!allowLogin(clientIp(req))) {
      return send(req, res, 429, { error: 'Too many login attempts. Try again shortly.' }, { 'Retry-After': '10' });
    }
    // Requiring JSON means a cross-site <form> cannot post here.
    if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) {
      return send(req, res, 415, { error: 'Content-Type must be application/json' });
    }
    const body = await readJsonBody(req);
    if (res.destroyed || !res.writable) return undefined;
    if (body === null || typeof body !== 'object') {
      // Connection: close so an oversized upload is not read any further.
      return send(req, res, 400, { error: 'Invalid request body' }, { Connection: 'close' });
    }
    if (!credentialsMatch(body.username, body.password)) {
      return send(req, res, 401, { error: 'Invalid username or password' });
    }
    // The secret is written into the token at login. A token therefore shows
    // the secret that was current when it was issued: tokens handed out before
    // a secret change stay valid, but they never learn the new secret.
    const token = jwt.sign({ sub: USERNAME, secret }, jwtKey, tokenTtlSeconds);
    return send(req, res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(token) });
  }

  function handleProtected(req, res, makeBody) {
    const session = authenticate(req);
    if (!session) return send(req, res, 401, { error: 'Not authenticated' });
    return send(req, res, 200, makeBody(session));
  }

  const routes = {
    'GET /': (req, res) => send(req, res, 200, { status: 'ok' }),
    'GET /health': (req, res) => send(req, res, 200, { status: 'ok' }),
    'POST /api/login': handleLogin,
    // Logout only removes the browser's cookie. Copies of the JWT stay valid
    // until they expire (stateless tokens cannot be revoked).
    'POST /api/logout': (req, res) => send(req, res, 200, { ok: true }, { 'Set-Cookie': clearedCookie }),
    'GET /api/admin': (req, res) => handleProtected(req, res, (session) => ({ secret: String(session.secret) })),
    'GET /api/page1': (req, res) => handleProtected(req, res, () => ({ title: 'Page 1' })),
    'GET /api/page2': (req, res) => handleProtected(req, res, () => ({ title: 'Page 2' })),
  };
  const knownPaths = new Set(Object.keys(routes).map((key) => key.split(' ')[1]));

  async function route(req, res) {
    if (!allowRequest(clientIp(req))) {
      return send(req, res, 429, { error: 'Too many requests' }, { 'Retry-After': '10' });
    }

    // Browsers always send Origin on cross-origin requests. Anything coming
    // from a page that is not our frontend is refused outright.
    const origin = req.headers.origin;
    if (origin && !allowedOrigins.includes(origin)) {
      return send(req, res, 403, { error: 'Origin not allowed' });
    }

    const path = req.url.split('?')[0];

    if (req.method === 'OPTIONS') {
      // CORS preflight
      return send(req, res, 204, null, {
        'Access-Control-Allow-Methods': 'GET, POST',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '600',
      });
    }

    const method = req.method === 'HEAD' ? 'GET' : req.method;
    const handler = Object.hasOwn(routes, `${method} ${path}`) ? routes[`${method} ${path}`] : null;
    if (handler) return handler(req, res);
    if (knownPaths.has(path)) return send(req, res, 405, { error: 'Method not allowed' });
    return send(req, res, 404, { error: 'Not found' });
  }

  return function app(req, res) {
    route(req, res).catch((err) => {
      console.error('Request failed:', err);
      if (!res.headersSent) send(req, res, 500, { error: 'Internal server error' });
      else res.destroy();
    });
  };
}

module.exports = { createApp, COOKIE_NAME };
