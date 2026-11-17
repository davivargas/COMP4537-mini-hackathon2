'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createApp, COOKIE_NAME } = require('../app');
const jwt = require('../jwt');

const ORIGIN = 'https://frontend.example';
const JWT_KEY = 'test-key-'.repeat(5);

/** Start a server with the given config on a random port. */
async function start(overrides = {}) {
  const config = { password: 'BCIT12', secret: 'defaultSecret', jwtKey: JWT_KEY, allowedOrigins: [ORIGIN], ...overrides };
  const server = http.createServer(createApp(config));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    base,
    close: () => new Promise((resolve) => {
      server.closeAllConnections();
      server.close(resolve);
    }),
  };
}

function login(base, username, password, headers = {}) {
  return fetch(`${base}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN, ...headers },
    body: JSON.stringify({ username, password }),
  });
}

/** "name=value" part of the Set-Cookie header, ready to send back. */
function cookieFrom(response) {
  return response.headers.get('set-cookie').split(';')[0];
}

const get = (base, path, cookie, headers = {}) =>
  fetch(`${base}${path}`, { headers: { ...(cookie ? { Cookie: cookie } : {}), ...headers } });

test('login with correct credentials sets a hardened JWT cookie', async () => {
  const { base, close } = await start();
  try {
    const response = await login(base, 'admin', 'BCIT12');
    assert.equal(response.status, 200);
    const setCookie = response.headers.get('set-cookie');
    assert.match(setCookie, new RegExp(`^${COOKIE_NAME}=[\\w-]+\\.[\\w-]+\\.[\\w-]+;`));
    for (const attribute of ['HttpOnly', 'Secure', 'SameSite=None', 'Partitioned', 'Path=/']) {
      assert.ok(setCookie.includes(attribute), `missing ${attribute}`);
    }
    const maxAge = Number(/Max-Age=(\d+)/.exec(setCookie)[1]);
    assert.ok(maxAge >= 7200, 'cookie must live at least two hours');
    const payload = jwt.verify(cookieFrom(response).split('=')[1], JWT_KEY);
    assert.ok(payload.exp - payload.iat >= 7200, 'JWT must live at least two hours');
    assert.equal(response.headers.get('access-control-allow-origin'), ORIGIN);
    assert.equal(response.headers.get('access-control-allow-credentials'), 'true');
    assert.equal((await response.text()).includes('defaultSecret'), false);
  } finally {
    await close();
  }
});

test('wrong or malformed credentials are rejected without a cookie', async () => {
  const { base, close } = await start();
  try {
    const attempts = [
      ['admin', 'wrong'], ['admin', ''], ['Admin', 'BCIT12'], ['root', 'BCIT12'], ['admin', 'BCIT12 '],
      ['admin', ['BCIT12']], ['admin', { $ne: null }], ['admin', null], [undefined, undefined], ['admin', true],
    ];
    for (const [username, password] of attempts) {
      const response = await login(base, username, password);
      assert.equal(response.status, 401, JSON.stringify([username, password]));
      assert.equal(response.headers.get('set-cookie'), null);
    }
  } finally {
    await close();
  }
});

test('bad login requests get 4xx, not a crash', async () => {
  const { base, close } = await start();
  try {
    const post = (body, headers) => fetch(`${base}/api/login`, { method: 'POST', headers, body });
    const json = { 'Content-Type': 'application/json' };
    assert.equal((await post('not json', json)).status, 400);
    assert.equal((await post('null', json)).status, 400);
    assert.equal((await post('"admin"', json)).status, 400);
    assert.equal((await post('', json)).status, 400);
    assert.equal((await post(JSON.stringify({ username: 'admin', password: 'x'.repeat(5000) }), json)).status, 400);
    assert.equal((await post('username=admin&password=BCIT12', { 'Content-Type': 'application/x-www-form-urlencoded' })).status, 415);
    assert.equal((await fetch(`${base}/api/login`)).status, 405);
    assert.equal((await get(base, '/health')).status, 200); // still alive
  } finally {
    await close();
  }
});

test('protected endpoints need a valid token', async () => {
  const { base, close } = await start();
  try {
    for (const path of ['/api/admin', '/api/page1', '/api/page2']) {
      assert.equal((await get(base, path)).status, 401);
      assert.equal((await get(base, path, `${COOKIE_NAME}=garbage`)).status, 401);
      assert.equal((await get(base, path, `${COOKIE_NAME}=a.b.c`)).status, 401);
    }
    const cookie = cookieFrom(await login(base, 'admin', 'BCIT12'));
    assert.deepEqual(await (await get(base, '/api/admin', cookie)).json(), { secret: 'defaultSecret' });
    assert.deepEqual(await (await get(base, '/api/page1', cookie)).json(), { title: 'Page 1' });
    assert.deepEqual(await (await get(base, '/api/page2', cookie)).json(), { title: 'Page 2' });
    // Sending the token under another cookie name, or as a bearer header, does nothing.
    const token = cookie.split('=')[1];
    assert.equal((await get(base, '/api/admin', `token=${token}`)).status, 401);
    assert.equal((await get(base, '/api/admin', null, { Authorization: `Bearer ${token}` })).status, 401);
  } finally {
    await close();
  }
});

test('forged tokens are rejected', async () => {
  const { base, close } = await start();
  try {
    const wrongKey = jwt.sign({ sub: 'admin', secret: 'x' }, 'another-key-'.repeat(4), 7200);
    const expired = jwt.sign({ sub: 'admin', secret: 'x' }, JWT_KEY, -1);
    for (const token of [wrongKey, expired]) {
      assert.equal((await get(base, '/api/admin', `${COOKIE_NAME}=${token}`)).status, 401);
    }
  } finally {
    await close();
  }
});

test('after a password and secret change, old tokens stay valid but never reveal the new secret', async () => {
  const before = await start();
  const oldCookie = cookieFrom(await login(before.base, 'admin', 'BCIT12'));
  await before.close();

  // "Restart" with new credentials and the same JWT key.
  const { base, close } = await start({ password: 'n3wPw!', secret: 'brandNewSecret' });
  try {
    // The old token is still accepted on every protected endpoint...
    assert.equal((await get(base, '/api/page1', oldCookie)).status, 200);
    assert.equal((await get(base, '/api/page2', oldCookie)).status, 200);
    const oldView = await get(base, '/api/admin', oldCookie);
    assert.equal(oldView.status, 200);
    // ...but it only ever shows the secret it was issued with.
    const text = await oldView.text();
    assert.equal(text.includes('brandNewSecret'), false);
    assert.deepEqual(JSON.parse(text), { secret: 'defaultSecret' });

    assert.equal((await login(base, 'admin', 'BCIT12')).status, 401);
    const newCookie = cookieFrom(await login(base, 'admin', 'n3wPw!'));
    assert.deepEqual(await (await get(base, '/api/admin', newCookie)).json(), { secret: 'brandNewSecret' });
  } finally {
    await close();
  }
});

test('logout clears the cookie but the token itself stays valid', async () => {
  const { base, close } = await start();
  try {
    const cookie = cookieFrom(await login(base, 'admin', 'BCIT12'));
    const response = await fetch(`${base}/api/logout`, { method: 'POST', headers: { Cookie: cookie, Origin: ORIGIN } });
    assert.equal(response.status, 200);
    const setCookie = response.headers.get('set-cookie');
    assert.ok(setCookie.startsWith(`${COOKIE_NAME}=;`));
    assert.ok(setCookie.includes('Max-Age=0'));
    assert.ok(setCookie.includes('Partitioned'));
    assert.equal((await get(base, '/api/admin', cookie)).status, 200);
  } finally {
    await close();
  }
});

test('CORS: only the configured frontend origin is served', async () => {
  const { base, close } = await start();
  try {
    const preflight = await fetch(`${base}/api/login`, {
      method: 'OPTIONS',
      headers: { Origin: ORIGIN, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' },
    });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get('access-control-allow-origin'), ORIGIN);
    assert.match(preflight.headers.get('access-control-allow-headers'), /content-type/i);

    const cookie = cookieFrom(await login(base, 'admin', 'BCIT12'));
    for (const origin of ['https://evil.example', 'null', `${ORIGIN}.evil.example`, 'http://frontend.example']) {
      const response = await get(base, '/api/admin', cookie, { Origin: origin });
      assert.equal(response.status, 403, origin);
      assert.equal(response.headers.get('access-control-allow-origin'), null);
      assert.equal((await response.text()).includes('defaultSecret'), false);
    }
    assert.equal((await login(base, 'admin', 'BCIT12', { Origin: 'https://evil.example' })).status, 403);
  } finally {
    await close();
  }
});

test('unknown routes, odd methods and odd paths are handled', async () => {
  const { base, close } = await start();
  try {
    assert.equal((await get(base, '/nope')).status, 404);
    assert.equal((await get(base, '/api/admin/')).status, 404);
    assert.equal((await get(base, '/constructor')).status, 404);
    assert.equal((await get(base, '/%')).status, 404);
    assert.equal((await fetch(`${base}/api/admin`, { method: 'DELETE' })).status, 405);
    assert.equal((await get(base, '/health?x=1')).status, 200);
    const head = await fetch(`${base}/health`, { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(await head.text(), '');
  } finally {
    await close();
  }
});

test('login attempts are rate limited per client', async () => {
  const { base, close } = await start({ loginLimit: 5 });
  try {
    for (let i = 0; i < 5; i += 1) assert.equal((await login(base, 'admin', 'wrong')).status, 401);
    const blocked = await login(base, 'admin', 'BCIT12');
    assert.equal(blocked.status, 429);
    assert.equal(blocked.headers.get('set-cookie'), null);
    assert.equal((await get(base, '/health')).status, 200); // other routes unaffected
  } finally {
    await close();
  }
});

test('all requests are rate limited per client', async () => {
  const { base, close } = await start({ requestLimit: 10 });
  try {
    for (let i = 0; i < 10; i += 1) assert.equal((await get(base, '/health')).status, 200);
    assert.equal((await get(base, '/health')).status, 429);
  } finally {
    await close();
  }
});

test('client address comes from the trusted end of X-Forwarded-For', async () => {
  const { base, close } = await start({ requestLimit: 3, trustedProxyHops: 1 });
  try {
    // Attacker rotates the spoofable left side; the proxy-added right side is constant.
    const statuses = [];
    for (let i = 0; i < 5; i += 1) {
      statuses.push((await get(base, '/health', null, { 'X-Forwarded-For': `10.0.0.${i}, 203.0.113.7` })).status);
    }
    assert.deepEqual(statuses, [200, 200, 200, 429, 429]);
    // A different real client is not affected.
    assert.equal((await get(base, '/health', null, { 'X-Forwarded-For': '203.0.113.8' })).status, 200);
  } finally {
    await close();
  }
});

test('stays fast under a burst of concurrent requests', async () => {
  const { base, close } = await start({ requestLimit: 100_000, loginLimit: 100_000 });
  try {
    const started = Date.now();
    // Waves of 50: more simultaneous new connections than that overflows the
    // local OS listen backlog, which is not what this test is measuring.
    for (let wave = 0; wave < 6; wave += 1) {
      const burst = [];
      for (let i = 0; i < 50; i += 1) burst.push(login(base, 'admin', `guess${wave}-${i}`).then((r) => r.status));
      const statuses = await Promise.all(burst);
      assert.ok(statuses.every((status) => status === 401));
    }
    assert.ok(Date.now() - started < 5000, 'burst took too long');
  } finally {
    await close();
  }
});
