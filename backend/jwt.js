'use strict';

// Hand-written JWT (HS256) using only node:crypto.
// A token is  base64url(header) . base64url(payload) . base64url(HMAC-SHA256(header.payload, key))

const crypto = require('node:crypto');

const MAX_TOKEN_LENGTH = 1024;

// We only ever issue one header, so on verification we demand exactly this
// string. That shuts down "alg":"none" and algorithm-confusion attacks: the
// attacker's header is never parsed, let alone trusted.
const HEADER = toBase64Url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));

function toBase64Url(text) {
  return Buffer.from(text, 'utf8').toString('base64url');
}

function hmac(data, key) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

/**
 * Create a signed token.
 * @param {object} claims  data to store in the token
 * @param {string} key     signing key
 * @param {number} ttlSeconds  lifetime
 * @param {number} [nowSeconds]  current time (injectable for tests)
 */
function sign(claims, key, ttlSeconds, nowSeconds = Math.floor(Date.now() / 1000)) {
  const payload = { ...claims, iat: nowSeconds, exp: nowSeconds + ttlSeconds };
  const body = `${HEADER}.${toBase64Url(JSON.stringify(payload))}`;
  return `${body}.${hmac(body, key).toString('base64url')}`;
}

/**
 * Check a token. Returns the payload if the signature is ours and the token
 * has not expired; otherwise null. Never throws.
 */
function verify(token, key, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH) return null;

  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, payloadPart, signaturePart] = parts;
  if (header !== HEADER) return null;

  // Check the signature BEFORE parsing the payload, in constant time so the
  // response time does not reveal how many signature bytes were correct.
  const expected = hmac(`${header}.${payloadPart}`, key);
  const given = Buffer.from(signaturePart, 'base64url');
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;

  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (payload === null || typeof payload !== 'object') return null;
  if (typeof payload.exp !== 'number' || payload.exp <= nowSeconds) return null;
  return payload;
}

module.exports = { sign, verify };
