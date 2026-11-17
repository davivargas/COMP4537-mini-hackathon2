# Password Hackathon: JWT + HttpOnly cookie

Every team member can be asked to explain this. Read it top to bottom once; it is short on purpose.

## What it is

Two separate deployments on two different HTTPS origins:

| Part   | Folder      | What it does                                                                                                                                    |
| ------ | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Client | `frontend/` | Static HTML/CSS/JS. Login page, Admin Landing Page, Page 1, Page 2. Holds no secrets.                                                           |
| API    | `backend/`  | Node.js, built-in modules only (`http`, `crypto`). Zero npm dependencies. Checks the password, issues and verifies the JWT, returns the secret. |

API endpoints:

| Endpoint                           | Auth | Returns                           |
| ---------------------------------- | ---- | --------------------------------- |
| `POST /api/login`                  | none | Sets the JWT cookie, or `401`     |
| `POST /api/logout`                 | none | Deletes the cookie in the browser |
| `GET /api/admin`                   | JWT  | `{ "secret": "..." }`             |
| `GET /api/page1`, `GET /api/page2` | JWT  | `{ "title": "Page 1" }`           |
| `GET /health`                      | none | `{ "status": "ok" }`              |

## How a login works

1. The login page sends `POST /api/login` with `{ username, password }` as JSON.
2. The server compares both to the configured values in constant time (`backend/app.js`, `credentialsMatch`).
3. If they match, the server builds a JWT (`backend/jwt.js`): `base64url(header).base64url(payload).base64url(HMAC-SHA256(header.payload, JWT_KEY))`. The payload holds `sub`, `secret`, `iat`, and `exp` (3 hours).
4. The JWT goes back in a cookie: `__Host-token=...; HttpOnly; Secure; SameSite=None; Partitioned; Path=/; Max-Age=10800`.
5. Each protected page calls its API endpoint with `credentials: 'include'`. The browser attaches the cookie; the server recomputes the HMAC and checks `exp`. `200` shows the page, `401` redirects to the login page.

The server stores no sessions. A token is valid if its signature matches and it has not expired, which is why refresh and navigation keep working and why a token cannot be revoked.

Why each cookie attribute:

- `HttpOnly`: page JavaScript cannot read the cookie, so XSS cannot steal the token.
- `Secure`: sent over HTTPS only.
- `SameSite=None`: needed because the client and API are on different sites; the default (`Lax`) would not send it on `fetch`.
- `Partitioned`: keeps the cookie working in browsers that block third-party cookies (Chrome incognito, Firefox, recent Safari).
- `__Host-` prefix: the browser only accepts it with `Secure`, `Path=/` and no `Domain`, so another subdomain cannot plant a fake one.

## Defences, and the problem each one answers

| Concern                                                                                                                                                                     | Defence                                                                                                                                                                                                                                                                                                              |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A JWT copied during Phase 1 is replayed later to read the new secret.** The rules keep old JWTs valid, so anyone who logged in during verification holds a working token. | The secret is a claim inside the token, written at login. An old token is still accepted everywhere, but it shows the secret it was issued with (`defaultSecret`). The new secret only enters tokens issued after a login with the new password. The server never looks the current secret up for an existing token. |
| A forged token (`alg: none`, a changed algorithm, an edited payload)                                                                                                        | The header must equal our one fixed header string, the signature is checked with `crypto.timingSafeEqual` before the payload is parsed, and the key is 48 random bytes. A forged token could not reveal the secret anyway: the secret is not looked up from it.                                                      |
| Password guessing (maximum six characters)                                                                                                                                  | Random password from 71 characters (about 1.3 × 10¹¹ possibilities) plus at most 50 login attempts per 10 s per address. The wall is off while the password is still the public default and switches on by itself once a real password is set (see the next row).                                                                                                                                                                                             |
| Timing side channel on the password check                                                                                                                                   | Both sides are HMACed and compared with `timingSafeEqual`.                                                                                                                                                                                                                                                           |
| Response time over 5 s counts as a defeat                                                                                                                                   | No slow hash, no disk or database access, nothing blocking: 500 mixed requests in waves of 50 peaked at about 30 ms locally. Request bodies capped at 1 KB, headers at 8 KB. A client gets 10 s to send a whole request, checked every second, then a `408` and the socket is closed (slowloris). A general limit of 20,000 requests per 10 s per address is a circuit breaker for real floods only.                                                                                                  |
| **Our own rate limit used against us.** Limits count per IP address and a whole classroom can share one address, so a rival spamming bad logins could lock every verifier out during Phase 1 (not working at verification = 0). | While the password is the public `BCIT12` there is no login wall: it would protect nothing. The general limit is set far above normal use for the same reason. |
| Back button after logout shows the secret again (the browser restores the old page from memory) | A page restored that way reloads itself and is re-checked with the API, which sends it to the login page. |
| A crash takes the server down                                                                                                                                               | Every handler is wrapped; bad JSON, odd types and bad paths all return a 4xx. `uncaughtException` is logged, not fatal.                                                                                                                                                                                              |
| Another website reading the secret (CORS / CSRF)                                                                                                                            | `Access-Control-Allow-Origin` is our exact frontend origin, never `*`. Any other `Origin` gets `403`. Login only accepts `application/json`, which a cross-site form cannot send.                                                                                                                                    |
| XSS on the client                                                                                                                                                           | Server data is written with `textContent` only. A Content-Security-Policy allows only our own script files; inline script cannot run.                                                                                                                                                                                |
| The secret leaking through the client code or repo                                                                                                                          | The client never contains it. Password, secret and key are environment variables on the API host, not in git.                                                                                                                                                                                                        |

Not a slow password hash such as bcrypt, on purpose: there is no password database to protect, and a slow hash would let login requests burn our CPU until we exceed the 5 s limit.

## Decoy endpoints

Scanners and AI agents go looking for paths like `/.env` or `/api/debug`. The API answers six of them with decoys: `/robots.txt`, `/.env`, `/backup.json`, `/api/debug`, `/api/config`, `/api/secret`.

- **Every decoy says it is one.** Each response contains the line `HONEYPOT DECOY - nothing here is real`, and every value in it is the text `DECOY-not-real`. Nobody, an instructor included, can mistake one for a real leak.
- **They hold nothing real** and our frontend never requests them. A test checks that the real password, secret and signing key never appear in any of them.
- **They point to each other** (`/robots.txt` → `/api/debug` → `/api/config` → `/api/secret`), so an automated attacker spends requests on leads that go nowhere.
- **They answer instantly.** A slow trap would hold attackers' connections open and could make our own server slow or unreachable.
- **They are a tripwire.** The API log prints one line per 10 s listing which decoys were requested, for example `[honeypot] decoys requested: /.env x3, /api/debug x1`, so we can see when someone is probing.

Logging in is not part of this: every wrong password, the old `BCIT12` included, gets the normal `401` error. Setting `HONEYPOT=off` on the API host removes the decoys.

What code cannot defend: the hosting provider going down or blocking us, and anyone leaking the password or secret (Discord, screen share, a screenshot of the dashboard).

## Run locally

```
cd backend
npm test          # 46 tests, no install needed
npm run dev       # API on http://localhost:3000
```

Serve `frontend/` on port 5500 (VS Code Live Server does this) and open `http://localhost:5500`. Log in with `admin` / `BCIT12`.

## Deploy

**API** (any always-on Node host; lab 5 used Railway):

1. Root directory `backend`, start command `npm start`.
2. Give the service a domain that contains the team number, for example `prjT1-api.up.railway.app`.
3. Run `npm run credentials` once and set the printed `JWT_KEY`. Never change it afterwards: that would invalidate issued tokens, which the rules forbid.
4. Set `ALLOWED_ORIGINS` to the client origin exactly, for example `https://prjT1.netlify.app` (no trailing slash).
5. Leave `ADMIN_PASSWORD` and `SECRET` unset for Phase 1; the defaults are `BCIT12` and `defaultSecret`.
6. Make sure the host does not sleep the app when idle. A cold start over 5 s is a defeat.
7. Open the client once, then read the API log line `First request: X-Forwarded-For="..."`. The visitor's real address must be the last entry. If a proxy address is last instead, set `TRUSTED_PROXY_HOPS` to its position counted from the right (2 for second-to-last). If the header is empty, set it to 0.

**Client** (any static host: Netlify, Cloudflare Pages, GitHub Pages):

1. Edit `frontend/config.js`: set `TEAM` and `API_URL`.
2. Publish the `frontend` folder. The site name or path must contain the team number.

Then check on the deployed site, in a normal window and a private window (and Safari if anyone has it): log in, see the secret, refresh, visit both pages, log out.

## Hackathon runbook

**Phase 1 — publish and verify.** Post the client URL. Verify at least one other team so you can proceed.

**Phase 2 — change credentials (5 minutes).**

1. Before class, run `npm run credentials` and keep the output private.
2. In the API host's variables set `ADMIN_PASSWORD` and `SECRET` to the generated values. Do not touch `JWT_KEY`.
3. Save. The redeploy is the one permitted restart.
4. Log out, log in with the new password, confirm the new secret is shown. The API log should now say `Login rate limit: 50 per 10 s per address`.
5. Post the READY message before the deadline.

**Phase 3 — defend.** No further changes or restarts are allowed. Keep the deployed API reachable and under 5 s; that is now the whole job. Watch the host dashboard for the app sleeping or being rate-limited by the provider. The replay defence above is what protects the secret, so there is nothing to change during the attack window — only to keep the server up.

Attacking other teams is allowed by the rules against registered teams only; coordinate that live in class. This repo is our defensive build.

## Deliverables checklist

- [ ] ZIP named `prjT1_passwordHackathon.zip` with `frontend/` and `backend/` as separate directories.
- [ ] Both HTTPS URLs posted in Learning Hub, clickable, each containing the team number.
- [ ] `frontend/config.js` points at the deployed API; `ALLOWED_ORIGINS` points at the deployed client.
