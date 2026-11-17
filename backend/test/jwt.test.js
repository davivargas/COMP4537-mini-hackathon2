'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const jwt = require('../jwt');

const KEY = 'k'.repeat(40);
const NOW = 1_800_000_000;
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

test('a signed token verifies and returns its claims', () => {
  const token = jwt.sign({ sub: 'admin', secret: 's' }, KEY, 7200, NOW);
  const payload = jwt.verify(token, KEY, NOW + 10);
  assert.equal(payload.sub, 'admin');
  assert.equal(payload.secret, 's');
  assert.equal(payload.exp, NOW + 7200);
});

test('token is valid until expiry and rejected from then on', () => {
  const token = jwt.sign({ sub: 'admin' }, KEY, 7200, NOW);
  assert.ok(jwt.verify(token, KEY, NOW + 7199));
  assert.equal(jwt.verify(token, KEY, NOW + 7200), null);
});

test('wrong key is rejected', () => {
  const token = jwt.sign({ sub: 'admin' }, KEY, 7200, NOW);
  assert.equal(jwt.verify(token, 'x'.repeat(40), NOW), null);
});

test('tampered payload is rejected', () => {
  const [header, , signature] = jwt.sign({ sub: 'admin', secret: 'old' }, KEY, 7200, NOW).split('.');
  const forged = `${header}.${b64({ sub: 'admin', secret: 'new', exp: NOW + 9999 })}.${signature}`;
  assert.equal(jwt.verify(forged, KEY, NOW), null);
});

test('alg none is rejected', () => {
  const body = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: 'admin', exp: NOW + 9999 })}`;
  assert.equal(jwt.verify(`${body}.`, KEY, NOW), null);
  assert.equal(jwt.verify(body, KEY, NOW), null);
});

test('a different header is rejected even with a correct HMAC over it', () => {
  const body = `${b64({ typ: 'JWT', alg: 'HS256' })}.${b64({ sub: 'admin', exp: NOW + 9999 })}`;
  const signature = crypto.createHmac('sha256', KEY).update(body).digest('base64url');
  assert.equal(jwt.verify(`${body}.${signature}`, KEY, NOW), null);
});

test('garbage input returns null and never throws', () => {
  for (const value of [undefined, null, 42, {}, '', '.', '..', 'a.b.c', 'a.b.c.d', 'x'.repeat(5000)]) {
    assert.equal(jwt.verify(value, KEY, NOW), null);
  }
});

test('token without a numeric exp is rejected', () => {
  const header = b64({ alg: 'HS256', typ: 'JWT' });
  for (const payload of [{ sub: 'admin' }, { sub: 'admin', exp: '9999999999' }, null, 'text']) {
    const body = `${header}.${b64(payload)}`;
    const signature = crypto.createHmac('sha256', KEY).update(body).digest('base64url');
    assert.equal(jwt.verify(`${body}.${signature}`, KEY, NOW), null);
  }
});
