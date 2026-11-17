'use strict';

// Entry point: reads configuration from environment variables and starts the
// HTTP server. HTTPS is terminated by the hosting provider's proxy.

const http = require('node:http');
const crypto = require('node:crypto');
const { createApp } = require('./app');

const env = process.env;

const DEFAULT_PASSWORD = 'BCIT12';
const password = env.ADMIN_PASSWORD || DEFAULT_PASSWORD;
// Rate limits count per IP address, and a whole classroom can share one
// address. While the password is the public default, a login wall protects
// nothing and would let one person lock every verifier out, so it is off.
// It switches on by itself once a real password is set (Phase 2).
const loginLimit = password === DEFAULT_PASSWORD ? Infinity : 50;
const secret = env.SECRET || 'defaultSecret';
const allowedOrigins = (env.ALLOWED_ORIGINS || 'http://localhost:5500,http://127.0.0.1:5500')
  .split(',')
  .map((origin) => origin.trim().replace(/\/+$/, ''))
  .filter(Boolean);
const hops = Number.parseInt(env.TRUSTED_PROXY_HOPS ?? '1', 10);
const trustedProxyHops = Number.isInteger(hops) && hops >= 0 ? hops : 1;

// Configuration problems are warnings, never crashes: a server that refuses
// to start is a lost hackathon.
let jwtKey = env.JWT_KEY;
if (!jwtKey || jwtKey.length < 32) {
  jwtKey = crypto.randomBytes(48).toString('base64url');
  console.warn('WARNING: JWT_KEY is missing or shorter than 32 characters. Using a random key:');
  console.warn('         every issued token will stop working when this process restarts.');
}
if (password.length > 6) console.warn('WARNING: ADMIN_PASSWORD is longer than the 6 characters the rules allow.');
if (secret.length >= 20 || /\s/.test(secret)) {
  console.warn('WARNING: SECRET must be fewer than 20 characters with no spaces.');
}

const app = createApp({ password, secret, jwtKey, allowedOrigins, trustedProxyHops, loginLimit });

// connectionsCheckingInterval: Node only enforces the timeouts below when it
// sweeps its connections, and the default sweep is every 30 s. Sweeping every
// second makes the limits real.
const server = http.createServer({ maxHeaderSize: 8192, connectionsCheckingInterval: 1000 }, app);

// Slow-request (slowloris) protection: a client gets this long to send its
// headers and its whole request, otherwise the socket is closed. These are the
// only lever an attacker has on our latency, and 10 s is already under no
// proxy's patience; configurable so the test suite can prove the behaviour
// with a short window.
const positiveInt = (value, fallback) => {
  const n = Number.parseInt(value, 10);
  return Number.isInteger(n) && n > 0 ? n : fallback;
};
server.headersTimeout = positiveInt(env.HEADERS_TIMEOUT_MS, 10_000);
server.requestTimeout = positiveInt(env.REQUEST_TIMEOUT_MS, 10_000);
// Kept longer than typical proxy idle timeouts so the hosting proxy never
// reuses a connection we have already closed (which would surface as a 502).
server.keepAliveTimeout = 65_000;
// One misbehaving keep-alive connection cannot pipeline unlimited requests.
server.maxRequestsPerSocket = 500;

// Logged once so TRUSTED_PROXY_HOPS can be checked against what the host
// really sends: the client address must be the entry counted from the right.
server.once('request', (req) => {
  console.log(`First request: X-Forwarded-For="${req.headers['x-forwarded-for'] || ''}" socket=${req.socket.remoteAddress}`);
});

// Malformed or stalled HTTP: answer briefly and drop the socket.
server.on('clientError', (err, socket) => {
  const statuses = {
    ERR_HTTP_REQUEST_TIMEOUT: '408 Request Timeout',
    HPE_HEADER_OVERFLOW: '431 Request Header Fields Too Large',
  };
  const status = statuses[err && err.code] || '400 Bad Request';
  if (socket.writable) socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`);
  else socket.destroy();
});

// Stay up no matter what: log and carry on.
process.on('uncaughtException', (err) => console.error('Uncaught exception:', err));
process.on('unhandledRejection', (err) => console.error('Unhandled rejection:', err));

// PORT=0 lets the OS choose a free port (used by the test suite); we log the
// one actually bound so callers never have to guess it.
const port = Number.isInteger(Number.parseInt(env.PORT, 10)) ? Number.parseInt(env.PORT, 10) : 3000;
server.listen(port, '0.0.0.0', () => {
  console.log(`API listening on port ${server.address().port}`);
  console.log(`Allowed frontend origins: ${allowedOrigins.join(', ')}`);
  console.log(`Trusted proxy hops: ${trustedProxyHops}`);
  console.log(`Login rate limit: ${loginLimit === Infinity ? 'off (default password in use)' : `${loginLimit} per 10 s per address`}`);
});
