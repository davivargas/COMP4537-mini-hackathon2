"use strict";

// Hackathon dress rehearsal: boot the REAL server.js (not just the handler)
// and attack it the way another team would. Defeat conditions from the rules:
//   1. the new secret is discovered
//   2. the server becomes unreachable
//   3. any required request takes longer than 5 s
// Every attack below must fail on all three counts.

const test = require("node:test");
const assert = require("node:assert/strict");
const net = require("node:net");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");

const ORIGIN = "https://prjT1-client.example";
const JWT_KEY = crypto.randomBytes(48).toString("base64url");
const NEW_PASSWORD = "Qz7!pk";
// The "Phase 2" secret. If this string ever shows up in a response to an
// attacker, we have lost.
const NEW_SECRET = "SENTINELsecret9x";
const RULE_LIMIT_MS = 5000;

const SERVER = path.join(__dirname, "..", "server.js");

/** Spawn server.js with env, resolve once it prints its bound port. */
function bootServer(env) {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [SERVER], {
      env: {
        ...process.env,
        PORT: "0",
        TRUSTED_PROXY_HOPS: "0",
        ALLOWED_ORIGINS: ORIGIN,
        JWT_KEY,
        ...env,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    const timer = setTimeout(
      () => reject(new Error(`server did not start:\n${output}`)),
      10_000,
    );
    const onData = (chunk) => {
      output += chunk;
      const match = /listening on port (\d+)/.exec(output);
      if (match) {
        clearTimeout(timer);
        resolve({
          base: `http://127.0.0.1:${match[1]}`,
          port: Number(match[1]),
          logs: () => output,
          stop: () =>
            new Promise((done) => {
              if (proc.exitCode !== null) return done();
              proc.once("exit", done);
              proc.kill();
            }),
        });
      }
    };
    proc.stdout.on("data", onData);
    proc.stderr.on("data", onData);
    proc.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`server exited early (${code}):\n${output}`));
    });
  });
}

/** fetch + timing + body, never throws on HTTP errors. */
async function hit(url, options = {}) {
  const started = performance.now();
  const response = await fetch(url, options);
  const text = await response.text();
  return {
    status: response.status,
    headers: response.headers,
    text,
    ms: performance.now() - started,
  };
}

const login = (base, password, extra = {}) =>
  hit(`${base}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: ORIGIN, ...extra },
    body: JSON.stringify({ username: "admin", password }),
  });

const cookieOf = (response) =>
  (response.headers.get("set-cookie") || "").split(";")[0];
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");

function assertNoLeak(response, label) {
  assert.equal(
    response.text.includes(NEW_SECRET),
    false,
    `SECRET LEAKED via ${label}`,
  );
}

/** Raw TCP: send bytes, collect whatever comes back until close or timeout. */
function rawExchange(port, payload, waitMs) {
  return new Promise((resolve) => {
    const socket = net.connect(port, "127.0.0.1");
    let received = "";
    const started = performance.now();
    const finish = (closedByServer) => {
      clearTimeout(timer);
      socket.destroy();
      resolve({ received, closedByServer, ms: performance.now() - started });
    };
    const timer = setTimeout(() => finish(false), waitMs);
    socket.on("connect", () => socket.write(payload));
    socket.on("data", (chunk) => {
      received += chunk;
    });
    socket.on("close", () => finish(true));
    socket.on("error", () => finish(true));
  });
}

// ---------------------------------------------------------------------------
// Attack 1: the big one. Keep a token from Phase 1, wait for the team to
// change password + secret, replay the token. The rules force us to keep
// accepting it, so it must not be able to see the new secret.
// ---------------------------------------------------------------------------
test("ATTACK replay: a Phase-1 token cannot read the Phase-2 secret", async () => {
  const phase1 = await bootServer({});
  const stolen = cookieOf(await login(phase1.base, "BCIT12"));
  assert.match(stolen, /^__Host-token=/);
  await phase1.stop();

  // Phase 2: the one allowed restart, new credentials, SAME JWT key.
  const phase2 = await bootServer({
    ADMIN_PASSWORD: NEW_PASSWORD,
    SECRET: NEW_SECRET,
  });
  try {
    const replay = await hit(`${phase2.base}/api/admin`, {
      headers: { Cookie: stolen, Origin: ORIGIN },
    });
    assert.equal(replay.status, 200, "rules: old tokens must stay valid");
    assertNoLeak(replay, "replayed Phase-1 token");
    assert.deepEqual(JSON.parse(replay.text), { secret: "defaultSecret" });

    // The old password is dead, so no fresh token can be minted with it.
    const oldPw = await login(phase2.base, "BCIT12");
    assert.equal(oldPw.status, 401);
    assert.equal(oldPw.headers.get("set-cookie"), null);
    assertNoLeak(oldPw, "old password");

    // Sanity: the real owner still sees the new secret.
    const owner = cookieOf(await login(phase2.base, NEW_PASSWORD));
    const ownerView = await hit(`${phase2.base}/api/admin`, {
      headers: { Cookie: owner, Origin: ORIGIN },
    });
    assert.deepEqual(JSON.parse(ownerView.text), { secret: NEW_SECRET });
  } finally {
    await phase2.stop();
  }
});

// ---------------------------------------------------------------------------
// Attack 2: sabotage verification. Everyone in class may share one IP address,
// so if bad logins could trip a per-address lockout during Phase 1, one rival
// could stop every other team from verifying us (= 0 for the assignment).
// ---------------------------------------------------------------------------
test("ATTACK lockout: Phase-1 logins cannot be blocked by a rival spamming bad passwords", async () => {
  const phase1 = await bootServer({});
  try {
    for (let wave = 0; wave < 6; wave += 1) {
      const spam = [];
      for (let i = 0; i < 50; i += 1)
        spam.push(login(phase1.base, `bad${wave}-${i}`));
      for (const r of await Promise.all(spam)) assert.equal(r.status, 401);
    }
    // A verifier on the same address logs in straight after 300 bad attempts.
    const verifier = await login(phase1.base, "BCIT12");
    assert.equal(verifier.status, 200);
    assert.ok(verifier.ms < RULE_LIMIT_MS);
    const view = await hit(`${phase1.base}/api/admin`, {
      headers: { Cookie: cookieOf(verifier), Origin: ORIGIN },
    });
    assert.deepEqual(JSON.parse(view.text), { secret: "defaultSecret" });
  } finally {
    await phase1.stop();
  }
});

// ---------------------------------------------------------------------------
// Everything else runs against Phase-2 servers.
// ---------------------------------------------------------------------------
test("Phase-2 server under attack", async (t) => {
  const phase2Env = { ADMIN_PASSWORD: NEW_PASSWORD, SECRET: NEW_SECRET };
  const srv = await bootServer({
    ...phase2Env,
    REQUEST_TIMEOUT_MS: "1500",
    HEADERS_TIMEOUT_MS: "1500",
  });
  const { base, port } = srv;
  const alive = async () => {
    const r = await hit(`${base}/health`);
    assert.equal(r.status, 200, "server must still be up");
    assert.ok(r.ms < RULE_LIMIT_MS, `health took ${r.ms}ms`);
  };

  try {
    await t.test(
      "ATTACK forgery: crafted tokens never authenticate",
      async () => {
        const hs = b64({ alg: "HS256", typ: "JWT" });
        const claims = b64({ sub: "admin", secret: "x", exp: 9_999_999_999 });
        const sigWith = (key, body) =>
          crypto.createHmac("sha256", key).update(body).digest("base64url");
        const forged = [
          `${b64({ alg: "none", typ: "JWT" })}.${claims}.`, // alg none
          `${b64({ alg: "none", typ: "JWT" })}.${claims}`, // alg none, 2 parts
          `${b64({ alg: "HS512", typ: "JWT" })}.${claims}.${sigWith(JWT_KEY, "x")}`, // alg swap
          `${hs}.${claims}.${sigWith("", `${hs}.${claims}`)}`, // empty key
          `${hs}.${claims}.${sigWith("secret", `${hs}.${claims}`)}`, // common weak keys
          `${hs}.${claims}.${sigWith("BCIT12", `${hs}.${claims}`)}`,
          `${hs}.${claims}.${sigWith(NEW_PASSWORD, `${hs}.${claims}`)}`, // password as key
          `${hs}.${claims}.`, // signature stripped
          `${hs}.${claims}.${"A".repeat(43)}`, // zero-ish signature
          `${hs}.${claims}.sig.extra`, // extra segment
          `${hs}..`, // empty payload
        ];
        for (const token of forged) {
          const r = await hit(`${base}/api/admin`, {
            headers: { Cookie: `__Host-token=${token}`, Origin: ORIGIN },
          });
          assert.equal(
            r.status,
            401,
            `forged token accepted: ${token.slice(0, 40)}`,
          );
          assertNoLeak(r, "forged token");
        }
        // A real token smuggled anywhere but the cookie is ignored.
        const real = cookieOf(await login(base, NEW_PASSWORD)).split("=")[1];
        assert.ok(real, "owner login failed");
        for (const headers of [
          { Authorization: `Bearer ${real}` },
          { Cookie: `token=${real}` },
          { Cookie: `__host-token=${real}` }, // wrong case
          { "X-Access-Token": real },
        ]) {
          const r = await hit(`${base}/api/admin`, {
            headers: { ...headers, Origin: ORIGIN },
          });
          assert.equal(r.status, 401, JSON.stringify(Object.keys(headers)));
        }
      },
    );

    await t.test(
      "ATTACK CORS: other websites cannot read anything",
      async () => {
        const cookie = cookieOf(await login(base, NEW_PASSWORD));
        assert.ok(cookie, "owner login failed");
        const evilOrigins = [
          "https://evil.example",
          "null",
          `${ORIGIN}.evil.example`,
          ORIGIN.replace("https", "http"),
          `${ORIGIN}:443`,
          `${ORIGIN}/`,
          ORIGIN.toUpperCase(),
          "https://prjT1-client.example.evil.example",
        ];
        for (const origin of evilOrigins) {
          for (const p of ["/api/admin", "/api/page1"]) {
            const r = await hit(`${base}${p}`, {
              headers: { Cookie: cookie, Origin: origin },
            });
            assert.equal(r.status, 403, `${origin} ${p}`);
            assert.equal(r.headers.get("access-control-allow-origin"), null);
            assertNoLeak(r, `CORS ${origin}`);
          }
          const pre = await hit(`${base}/api/admin`, {
            method: "OPTIONS",
            headers: { Origin: origin, "Access-Control-Request-Method": "GET" },
          });
          assert.equal(
            pre.headers.get("access-control-allow-origin"),
            null,
            `preflight ${origin}`,
          );
        }
        // CSRF-style post without a JSON content type is refused before any check.
        const form = await hit(`${base}/api/login`, {
          method: "POST",
          headers: { "Content-Type": "text/plain", Origin: ORIGIN },
          body: JSON.stringify({ username: "admin", password: NEW_PASSWORD }),
        });
        assert.notEqual(form.status, 200);
        assert.equal(form.headers.get("set-cookie"), null);
      },
    );

    await t.test(
      "ATTACK probing: weird paths and methods leak nothing",
      async () => {
        // (/.env, /api/secret and friends are decoys now: see the honeypot tests.)
        const probes = [
          ["GET", "/.env.local"],
          ["GET", "/.git/config"],
          ["GET", "/server.js"],
          ["GET", "/app.js"],
          ["GET", "/package.json"],
          ["GET", "/api/users"],
          ["GET", "/api/admin/"],
          ["GET", "/API/ADMIN"],
          ["GET", "/api//admin"],
          ["GET", "/api/admin%00"],
          ["GET", "/__proto__"],
          ["GET", "/constructor"],
          ["GET", "/api/admin?debug=true"],
          ["PUT", "/api/admin"],
          ["PATCH", "/api/login"],
          ["DELETE", "/api/admin"],
          ["GET", "/api/login"],
        ];
        for (const [method, p] of probes) {
          const r = await hit(`${base}${p}`, {
            method,
            headers: { Origin: ORIGIN },
          });
          assert.ok(
            [401, 404, 405].includes(r.status),
            `${method} ${p} -> ${r.status}`,
          );
          assertNoLeak(r, `${method} ${p}`);
          assert.equal(
            /at .+\.js:\d+/.test(r.text),
            false,
            `stack trace leaked on ${method} ${p}`,
          );
        }
        await alive();
      },
    );

    await t.test(
      "ATTACK injection: odd login bodies never authenticate or crash",
      async () => {
        const bodies = [
          { username: "admin", password: { $ne: null } },
          { username: "admin", password: { $gt: "" } },
          { username: "admin", password: [NEW_PASSWORD] },
          { username: ["admin"], password: NEW_PASSWORD },
          { username: "admin", password: true },
          { username: "admin", password: 0 },
          { username: "admin\u0000", password: NEW_PASSWORD },
          { username: "admin", password: `${NEW_PASSWORD}\u0000` },
          { username: "ADMIN", password: NEW_PASSWORD },
          { username: " admin", password: NEW_PASSWORD },
          { username: "admin' OR '1'='1", password: "' OR '1'='1" },
          { username: "admin", password: NEW_PASSWORD.toLowerCase() },
        ];
        const raw = [
          `{"__proto__":{"username":"admin","password":"${NEW_PASSWORD}"}}`,
          `{"constructor":{"prototype":{"password":"${NEW_PASSWORD}"}},"username":"admin"}`,
          `[{"username":"admin","password":"${NEW_PASSWORD}"}]`,
        ];
        for (const body of [...bodies.map((b) => JSON.stringify(b)), ...raw]) {
          const r = await hit(`${base}/api/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json", Origin: ORIGIN },
            body,
          });
          assert.notEqual(r.status, 200, `authenticated with ${body}`);
          assert.equal(r.headers.get("set-cookie"), null);
          assertNoLeak(r, "injection body");
        }
        // Nothing above polluted shared state: an anonymous request is still anonymous.
        const after = await hit(`${base}/api/admin`, {
          headers: { Origin: ORIGIN },
        });
        assert.equal(after.status, 401);
      },
    );

    await t.test(
      "ATTACK oversized input: big bodies, headers and cookies are rejected safely",
      async () => {
        const huge = JSON.stringify({
          username: "admin",
          password: "x".repeat(2_000_000),
        });
        const big = await hit(`${base}/api/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: huge,
        }).catch((err) => ({ status: 0, ms: 0, text: String(err) })); // server may cut the upload: also fine
        assert.ok(
          [0, 400, 413].includes(big.status),
          `big body -> ${big.status}`,
        );
        assert.ok(big.ms < RULE_LIMIT_MS);

        // Body streamed in chunks with no Content-Length.
        const stream = new ReadableStream({
          start(controller) {
            for (let i = 0; i < 50; i += 1)
              controller.enqueue(new TextEncoder().encode("x".repeat(10_000)));
            controller.close();
          },
        });
        const chunked = await hit(`${base}/api/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: stream,
          duplex: "half",
        }).catch((err) => ({ status: 0, text: String(err) }));
        assert.ok(
          [0, 400].includes(chunked.status),
          `chunked -> ${chunked.status}`,
        );

        // Headers past the 8 KB cap get a 4xx instead of a crash.
        const fatHeader = await rawExchange(
          port,
          `GET /api/admin HTTP/1.1\r\nHost: x\r\nCookie: ${"a=b; ".repeat(4000)}\r\n\r\n`,
          3000,
        );
        assert.match(fatHeader.received, /^HTTP\/1\.1 4\d\d/);

        // Deeply nested JSON within the size cap.
        const nested = await hit(`${base}/api/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: `${"[".repeat(400)}${"]".repeat(400)}`,
        });
        assert.notEqual(nested.status, 200);
        await alive();
      },
    );

    await t.test(
      "ATTACK malformed HTTP: garbage bytes are refused, server survives",
      async () => {
        for (const garbage of [
          "ÿþ\u0000\u0001 nonsense\r\n\r\n",
          "GET / HTTP/9.9\r\n\r\n",
          "GET\r\n\r\n",
        ]) {
          const r = await rawExchange(port, garbage, 3000);
          assert.ok(
            r.closedByServer || /400/.test(r.received),
            `garbage not handled: ${JSON.stringify(garbage)}`,
          );
        }
        await alive();
      },
    );

    await t.test(
      "ATTACK slowloris: stalled sockets are cut, others are served meanwhile",
      async () => {
        // Open stalled connections that never finish their headers.
        const stalled = [];
        for (let i = 0; i < 30; i += 1) {
          stalled.push(
            rawExchange(
              port,
              "GET /health HTTP/1.1\r\nHost: x\r\nX-Slow: ",
              8000,
            ),
          );
        }
        // While they hang, a normal visitor is served quickly.
        await new Promise((r) => setTimeout(r, 200));
        const during = await hit(`${base}/health`);
        assert.equal(during.status, 200);
        assert.ok(
          during.ms < 1000,
          `served in ${during.ms}ms while under slowloris`,
        );

        const results = await Promise.all(stalled);
        for (const r of results) {
          assert.ok(
            r.closedByServer,
            "stalled socket was never closed by the server",
          );
          // 1.5 s limit + 1 s sweep interval + slack
          assert.ok(
            r.ms < 4500,
            `stalled socket held for ${r.ms.toFixed(0)}ms`,
          );
          assert.match(r.received, /^HTTP\/1\.1 408/);
        }
      },
    );

    await t.test(
      "ATTACK brute force: the login wall engages and blocks even the right password",
      async () => {
        let walled = false;
        for (let i = 0; i < 80; i += 1) {
          const r = await login(base, `g${i}`);
          assertNoLeak(r, "brute force");
          assert.ok(r.ms < RULE_LIMIT_MS);
          if (r.status === 429) {
            walled = true;
            break;
          }
          assert.equal(r.status, 401);
        }
        assert.ok(walled, "login rate limit never engaged");
        const r = await login(base, NEW_PASSWORD);
        assert.equal(r.status, 429);
        assert.equal(r.headers.get("set-cookie"), null);
        await alive(); // the wall is for /api/login only
      },
    );

    await t.test(
      "ATTACK flood: 500 concurrent-wave requests, every one under 5 s",
      async () => {
        const fresh = await bootServer(phase2Env);
        try {
          const kinds = [
            () =>
              hit(`${fresh.base}/api/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  username: "admin",
                  password: crypto.randomUUID().slice(0, 6),
                }),
              }),
            () =>
              hit(`${fresh.base}/api/admin`, {
                headers: { Cookie: "__Host-token=a.b.c" },
              }),
            () => hit(`${fresh.base}/health`),
            () => hit(`${fresh.base}/nope`),
          ];
          let worst = 0;
          let count = 0;
          for (let wave = 0; wave < 10; wave += 1) {
            const batch = [];
            for (let i = 0; i < 50; i += 1)
              batch.push(kinds[i % kinds.length]());
            const results = await Promise.all(batch);
            for (const r of results) {
              count += 1;
              worst = Math.max(worst, r.ms);
              assert.ok(
                [200, 401, 404, 429].includes(r.status),
                `unexpected ${r.status}`,
              );
              assertNoLeak(r, "flood");
            }
          }
          assert.equal(count, 500);
          assert.ok(
            worst < RULE_LIMIT_MS,
            `slowest request ${worst.toFixed(0)}ms breaks the 5 s rule`,
          );
          t.diagnostic(
            `flood: slowest of 500 requests = ${worst.toFixed(0)} ms`,
          );
          // The defender's own check right after the flood.
          const health = await hit(`${fresh.base}/health`);
          assert.ok(health.ms < 1000, `post-flood health ${health.ms}ms`);
        } finally {
          await fresh.stop();
        }
      },
    );

    await t.test(
      "server is still alive and never logged an unexpected error",
      async () => {
        await alive();
        assert.equal(
          /Uncaught exception|Unhandled rejection|Request failed/.test(
            srv.logs(),
          ),
          false,
          srv.logs(),
        );
      },
    );
  } finally {
    await srv.stop();
  }
});

// ===========================================================================
// ROUND 2: decoy endpoints, then deeper protocol-level attacks.
// ===========================================================================
const { DECOY_NOTICE } = require("../app");
const PHASE2 = { ADMIN_PASSWORD: NEW_PASSWORD, SECRET: NEW_SECRET };
const DECOYS = ["/.env", "/backup.json", "/robots.txt", "/api/debug", "/api/config", "/api/secret"];
const adminView = (base, cookie) =>
  hit(`${base}/api/admin`, { headers: { Cookie: cookie, Origin: ORIGIN } });

test("DECOYS: every decoy says it is a decoy, answers fast and holds nothing real", async () => {
  const srv = await bootServer(PHASE2);
  const { base } = srv;
  try {
    for (const p of DECOYS) {
      const r = await hit(`${base}${p}`);
      assert.equal(r.status, 200, p);
      assert.ok(r.text.includes(DECOY_NOTICE), `${p} is not labelled as a decoy`);
      assertNoLeak(r, `decoy ${p}`);
      assert.equal(r.text.includes(NEW_PASSWORD), false, `${p} leaks the password`);
      assert.equal(r.text.includes(JWT_KEY), false, `${p} leaks the signing key`);
      assert.ok(r.ms < 1000, `decoy ${p} slow: ${r.ms}ms`);
    }
    // No fake server fingerprint: nothing may suggest we use a framework.
    assert.equal((await hit(`${base}/api/secret`)).headers.get("x-powered-by"), null);

    // Values copied out of a decoy are useless against the real app.
    const leakedKey = /^JWT_KEY=(.+)$/m.exec((await hit(`${base}/.env`)).text)[1];
    const body = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ sub: "admin", secret: "x", exp: 9_999_999_999 })}`;
    const sig = crypto.createHmac("sha256", leakedKey).update(body).digest("base64url");
    assert.equal((await adminView(base, `__Host-token=${body}.${sig}`)).status, 401);
    const leakedPassword = /^ADMIN_PASSWORD=(.+)$/m.exec((await hit(`${base}/.env`)).text)[1];
    assert.equal((await login(base, leakedPassword)).status, 401);

    // There is no bait login: every wrong password, the old default included,
    // gets the proper error and no cookie.
    for (const wrong of ["BCIT12", "bcit12", "password", "123456", "admin", "Qz7!pK", ""]) {
      const r = await login(base, wrong);
      assert.equal(r.status, 401, `wrong password ${JSON.stringify(wrong)}`);
      assert.equal(r.headers.get("set-cookie"), null);
    }
    // The owner still gets the real secret, and required endpoints are untouched.
    const owner = await adminView(base, cookieOf(await login(base, NEW_PASSWORD)));
    assert.deepEqual(JSON.parse(owner.text), { secret: NEW_SECRET });
    assert.equal((await hit(`${base}/health`)).status, 200);
  } finally {
    await srv.stop();
  }
});

test("DECOYS: HONEYPOT=off removes them", async () => {
  const srv = await bootServer({ ...PHASE2, HONEYPOT: "off" });
  try {
    for (const p of DECOYS) {
      assert.equal((await hit(`${srv.base}${p}`)).status, 404, p);
    }
    const owner = await adminView(srv.base, cookieOf(await login(srv.base, NEW_PASSWORD)));
    assert.deepEqual(JSON.parse(owner.text), { secret: NEW_SECRET });
    assert.match(srv.logs(), /Decoy endpoints: off/);
  } finally {
    await srv.stop();
  }
});

test("ROUND 2 protocol attacks", async (t) => {
  const srv = await bootServer({ ...PHASE2, REQUEST_TIMEOUT_MS: "1500", HEADERS_TIMEOUT_MS: "1500" });
  const { base, port } = srv;
  const alive = async (label) => {
    const r = await hit(`${base}/health`);
    assert.equal(r.status, 200, `down after ${label}`);
    assert.ok(r.ms < 1000, `slow after ${label}: ${r.ms}ms`);
  };
  const ownerCookie = cookieOf(await login(base, NEW_PASSWORD));
  assert.ok(ownerCookie);

  try {
    await t.test("request smuggling: Content-Length together with Transfer-Encoding is refused", async () => {
      const r = await rawExchange(
        port,
        "POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /api/admin HTTP/1.1\r\nHost: x\r\n\r\n",
        3000,
      );
      assert.match(r.received, /^HTTP\/1\.1 400/);
      assert.equal(r.received.includes(NEW_SECRET), false);
      await alive("smuggling");
    });

    await t.test("slow body: a login that never finishes its body is cut off", async () => {
      const stalled = [];
      for (let i = 0; i < 20; i += 1) {
        stalled.push(rawExchange(
          port,
          'POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{"username":"admin","pass',
          8000,
        ));
      }
      await new Promise((r) => setTimeout(r, 200));
      await alive("slow bodies in flight");
      for (const r of await Promise.all(stalled)) {
        assert.ok(r.closedByServer, "slow-body socket never closed");
        assert.ok(r.ms < 4500, `slow-body socket held ${r.ms.toFixed(0)}ms`);
      }
    });

    await t.test("pipelining: 200 requests in one packet are all answered", async () => {
      const one = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n";
      const last = "GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
      const r = await rawExchange(port, one.repeat(199) + last, 5000);
      assert.equal((r.received.match(/HTTP\/1\.1 200/g) || []).length, 200);
      assert.ok(r.ms < RULE_LIMIT_MS);
    });

    await t.test("odd verbs and upgrades: WebSocket, CONNECT, TRACE, method override", async () => {
      const ws = await rawExchange(port, "GET /api/admin HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", 2500);
      assert.equal(ws.received.includes("101 Switching"), false);
      assert.equal(ws.received.includes(NEW_SECRET), false);
      const connect = await rawExchange(port, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", 2500);
      assert.equal(/^HTTP\/1\.1 200/.test(connect.received), false);
      const trace = await rawExchange(port, `TRACE /api/admin HTTP/1.1\r\nHost: x\r\nCookie: ${ownerCookie}\r\nConnection: close\r\n\r\n`, 2500);
      assert.equal(trace.received.includes(ownerCookie), false, "TRACE echoed the cookie back");
      // A header cannot turn a POST into a GET.
      const override = await hit(`${base}/api/admin`, { method: "POST", headers: { "X-HTTP-Method-Override": "GET", Cookie: ownerCookie } });
      assert.equal(override.status, 405);
      await alive("odd verbs");
    });

    await t.test("cookie tricks: duplicates, padding and case never promote a bad token", async () => {
      const token = ownerCookie.split("=")[1];
      const bad = [
        `__Host-token=garbage; ${ownerCookie}`, // first one wins, and it is garbage
        `__Host-token=; ${ownerCookie}`,
        `__Host-Token=${token}`,
        `__host-token=${token}`,
        `__Secure-token=${token}`,
        `__Host-token="${token}"`,
        `__Host-token=${token}.`,
        `__Host-token=${token.slice(0, -2)}`,
        `__Host-token=${token.replace(/\.[^.]+$/, "")}`,
        `x=1;__Host-token =${token.toUpperCase()}`,
      ];
      for (const cookie of bad) {
        const r = await hit(`${base}/api/admin`, { headers: { Cookie: cookie } });
        assert.equal(r.status, 401, `accepted: ${cookie.slice(0, 40)}`);
        assertNoLeak(r, "cookie trick");
      }
    });

    await t.test("signature probing: changing any sampled character of a real token invalidates it", async () => {
      const token = ownerCookie.split("=")[1];
      for (let i = 0; i < token.length - 1; i += 7) {
        if (token[i] === ".") continue;
        const flipped = token.slice(0, i) + (token[i] === "A" ? "B" : "A") + token.slice(i + 1);
        const r = await hit(`${base}/api/admin`, { headers: { Cookie: `__Host-token=${flipped}` } });
        assert.equal(r.status, 401, `flip at ${i} accepted`);
      }
    });

    await t.test("connection hoarding: 300 idle keep-alive sockets do not slow a visitor", async () => {
      const sockets = [];
      for (let i = 0; i < 300; i += 1) {
        const s = net.connect(port, "127.0.0.1");
        s.on("error", () => {});
        s.on("connect", () => s.write("GET /health HTTP/1.1\r\nHost: x\r\n\r\n"));
        sockets.push(s);
      }
      await new Promise((r) => setTimeout(r, 500));
      await alive("300 hoarded connections");
      const owner = await adminView(base, ownerCookie);
      assert.equal(owner.status, 200);
      for (const s of sockets) s.destroy();
    });

    await t.test("decoy flood: hammering the decoys cannot slow the real app", async () => {
      let worst = 0;
      for (let wave = 0; wave < 6; wave += 1) {
        const batch = [];
        for (let i = 0; i < 50; i += 1) {
          batch.push(hit(`${base}${DECOYS[i % DECOYS.length]}`));
        }
        for (const r of await Promise.all(batch)) {
          worst = Math.max(worst, r.ms);
          assert.equal(r.status, 200);
          assertNoLeak(r, "decoy flood");
        }
      }
      assert.ok(worst < RULE_LIMIT_MS, `decoy flood worst ${worst.toFixed(0)}ms`);
      await alive("decoy flood");
      // Tripwire output is one summary line per window, not one line per hit.
      assert.ok((srv.logs().match(/\[honeypot\]/g) || []).length <= 3);
    });

    await t.test("nothing unexpected was logged", async () => {
      assert.equal(/Uncaught exception|Unhandled rejection|Request failed/.test(srv.logs()), false, srv.logs());
    });
  } finally {
    await srv.stop();
  }
});
