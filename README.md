# SE4030 – Secure Software Development Assignment

Hardening of a MERN doctor-appointment booking application (**Prescripto**):
identifying and fixing security vulnerabilities, and adding a Google
OpenID Connect sign-in feature.

---

## Group Members

| # | Name | Index Number |
|---|------|--------------|
| 1 | Nethmina W.P.R. | IT22253958 |
| 2 | Appuhami M.N.H. | IT22140852 |
| 3 | Madurapperuma H.A.S.I. | IT22230942 |
| 4 | Aron Charles J. | IT22203380 |

## Links

| Item | Link |
|------|------|
| **Original project** (third-party baseline) | https://github.com/RVNethmina/AppointmentBookingSystem |
| **Modified (hardened) project** | https://github.com/RVNethmina/SE4030-secure-appointment-system |
| **Demo video (≤20 min)** | *TODO – paste YouTube link here* |
| **Report (PDF)** | [`SE4030_Security_Report.pdf`](./SE4030_Security_Report.pdf) |

> The original application is a third-party MERN "Prescripto" doctor-appointment
> clone. Its last commit predates the semester start, its improved version is not
> publicly available, and it is not a security-teaching app (per the assignment
> constraints).

---

## What was done

- Identified and fixed **20 distinct vulnerabilities** in two review rounds
  (see the tables below and the full report).
- Implemented **"Sign in with Google"** using the OpenID Connect flow
  (Google Identity Services + `google-auth-library`), hardened with a
  server-issued single-use `nonce`.
- Added an automated **security regression test suite** (41 tests) and a
  **CI security pipeline** (tests, `npm audit`, gitleaks, CodeQL, Dependabot).
- Every fix is an individual, descriptively-commented git commit so the
  before → after history is auditable.

### Vulnerabilities fixed – round 1

| # | Vulnerability | OWASP / CWE | Fix commit (subject) |
|---|---------------|-------------|----------------------|
| 1 | Hard-coded secrets committed to git (DB, Cloudinary, admin pw, JWT secret) | A02 / CWE-798, CWE-312 | `fix(secrets): remove committed .env files…` |
| 2 | Broken admin auth – token = `sign(email+password)` | A07 / CWE-287, CWE-306 | `fix(admin-auth): replace forgeable admin token…` |
| 3 | JWT with no expiry + weak secret `RBRO` | A07 / CWE-613, CWE-521, CWE-330 | `fix(jwt): add token expiry, strong-secret enforcement…` |
| 4 | No brute-force / rate limiting on auth | A07 / CWE-307 | `fix(rate-limit): throttle authentication endpoints…` |
| 5 | Wide-open CORS + missing security headers | A05 / CWE-942, CWE-693 | `fix(http): add Helmet, CORS allow-list…` |
| 6 | NoSQL injection via unsanitized query inputs | A03 / CWE-943 | `fix(nosql-injection): validate input types…` |
| 7 | Unrestricted file upload (attacker-controlled name, no limits) | A04 / CWE-434, CWE-22 | `fix(upload): restrict multer to safe image uploads` |
| 8 | Sensitive logging + raw error messages to clients | A09 / CWE-532, CWE-209 | `fix(info-leak): stop logging secrets…` |
| 9 | Weak password policy + IDOR / broken ownership check | A01 / CWE-521, CWE-639 | `fix(authz): enforce strong passwords…` |
| 10 | Vulnerable npm dependencies (17 backend incl. 1 critical) | A06 / CWE-1104 | `fix(deps): patch vulnerable dependencies…` |

A related availability fix (`fix(availability): handle DB connection failure…`)
stops a failed DB connection from crashing the whole process.

### Vulnerabilities fixed – round 2

| # | Vulnerability | OWASP / CWE | Fix commit (subject) |
|---|---------------|-------------|----------------------|
| 11 | Missing role enforcement: doctor/admin tokens accepted as patient sessions, role-less tokens as doctor sessions; JWT algorithm not pinned | A01 / CWE-863, CWE-639, CWE-347 | `fix(authz): require exact role claims…` |
| 12 | Anonymous file upload (multer ran before auth), spoofable image type, temp files never deleted | A01, A04 / CWE-306, CWE-434, CWE-400 | `fix(upload): authenticate before accepting files…` |
| 13 | Rate-limit bypass by spoofing `X-Forwarded-For` (`trust proxy` always on) | A07 / CWE-348, CWE-307 | `fix(rate-limit): stop trusting X-Forwarded-For…` |
| 14 | Account pre-hijacking through Google account linking; login timing / 500 enumeration oracles | A07 / CWE-287, CWE-1390, CWE-204, CWE-208 | `fix(auth): block account pre-hijacking…` |
| 15 | Weak bootstrap admin password accepted at boot; credential length leak | A07 / CWE-521, CWE-208 | `fix(admin-auth): refuse weak bootstrap admin credentials…` |
| 16 | Double booking race condition; unvalidated slot/doctor input; appointment state flaws | A04 / CWE-362, CWE-20, CWE-840 | `fix(booking): atomic slot reservation…` |
| 17 | Mass assignment / unvalidated profile and doctor fields (e.g. negative fees) | A04, A08 / CWE-915, CWE-20 | `fix(validation): whitelist and validate profile…` |
| 18 | Google ID token replay – no OIDC `nonce` | A07 / CWE-294 | `feat(oauth): bind Google ID tokens to a server-issued single-use OIDC nonce` |
| 19 | Doctor passwords, JWTs and patient PII written to the browser console | A09 / CWE-532, CWE-359 | `fix(client-info-leak): stop logging passwords…` |
| 20 | Clients never discard expired/revoked tokens (users locked out of login) | A07 / CWE-613 | `fix(session): clear expired or revoked tokens…` |

A second dependency audit (`fix(deps): patch advisories published since July…`)
fixed newly disclosed advisories and moved multer to 2.x.

### Vulnerabilities not fixed (and why)

| Issue | Reason | Recommendation |
|-------|--------|----------------|
| Leaked credentials remain in the **original** repository's history | Rotation is an operational action in the MongoDB Atlas / Cloudinary / Razorpay dashboards, not a code change | Rotate every leaked key; purge history with `git filter-repo` |
| JWTs stored in `localStorage` (readable by any XSS) | Moving to `httpOnly` cookies needs CSRF tokens and CORS/credential changes in all three apps. Partly mitigated: the Docker nginx images send a strict Content-Security-Policy (no inline or third-party scripts except Google sign-in and Razorpay) | `httpOnly` + `SameSite` cookies with CSRF protection |
| No logout endpoint / refresh-token rotation | Account-wide revocation now exists (`sessionsValidAfter`), but per-token revocation needs a token store | Short-lived access tokens + rotating refresh tokens + denylist |
| No email verification for local sign-up | Needs an email provider; the Google-linking takeover path is already closed | Verify email ownership before activating local accounts |
| Admin is a single env credential without MFA | Needs a DB-backed admin model and an MFA flow | Admin accounts in the database with bcrypt hashes, RBAC and TOTP/WebAuthn |
| Rate limits, OIDC nonce replay cache are in-memory | Correct for one API instance only | Use Redis / MongoDB TTL collections when scaling out |
| "Pay Online" (Razorpay) is not implemented | No server-side payment endpoint exists; the button calls an undefined function | Implement server-side order creation and signature verification |
| No security event logging / alerting | Requires logging infrastructure | Structured audit logs for logins, lockouts and admin actions |

---

## Project structure

```
backend/    Node.js + Express + MongoDB (Mongoose) REST API
  app.js      Express app (middleware, routes, error handler)
  server.js   loads .env, boot-time secret checks, DB connection, listen
  tests/      security regression tests (node:test + supertest)
  Dockerfile  non-root Node 22 Alpine image
frontend/   React + Vite patient-facing app (has the Google sign-in)
  Dockerfile  Vite build served by unprivileged nginx (nginx.conf: CSP, /api proxy)
admin/      React + Vite admin & doctor panel (same Docker layout)
docker-compose.yml   MongoDB + API + both web apps
.github/    CI security pipeline, CodeQL and Dependabot
```

## Running with Docker (recommended)

Prerequisites: Docker Desktop (or Docker Engine) with Compose v2.

```bash
# 1. Compose variables: MongoDB container credentials and host ports
cp .env.example .env
#    set MONGO_ROOT_PASSWORD to a random hex string, e.g.
node -e "console.log(require('crypto').randomBytes(24).toString('hex'))"

# 2. API secrets (JWT_SECRET, ADMIN_EMAIL/ADMIN_PASSWORD, Cloudinary, Google)
cp backend/.env.example backend/.env

# 3. Build the images and start the containers
docker compose up -d --build
docker compose ps          # wait until all four services are "healthy"
```

| Service | URL / exposure | Image |
|---------|----------------|-------|
| Patient app | http://localhost:5173 | `prescripto-frontend` (nginx, serves the SPA, proxies `/api`) |
| Admin & doctor panel | http://localhost:5174 | `prescripto-admin` (nginx, serves the SPA, proxies `/api`) |
| API | internal only (`backend:4000`) | `prescripto-backend` (Node 22 Alpine) |
| MongoDB | internal only (`mongo:27017`), data in the `mongo-data` volume | `mongo:7` |

- Stop the Vite dev servers first if they are running: the containers use the
  same ports 5173/5174 (so the Google OAuth origin `http://localhost:5173` and
  the CORS allow-list work unchanged). Change them with `FRONTEND_PORT` /
  `ADMIN_PORT` in `.env`.
- Compose overrides `MONGODB_URI`, `ALLOWED_ORIGINS`, `PORT` and
  `TRUST_PROXY=1` from `backend/.env`, so the API uses the MongoDB container.
- `VITE_GOOGLE_CLIENT_ID` in `.env` is baked into the patient app at build
  time; run `docker compose up -d --build frontend` after changing it.
- Adding doctors (image upload) needs real Cloudinary keys in `backend/.env`.
- Stop with `docker compose down` (add `-v` to also delete the database volume).

Container security:
- The API and MongoDB publish no host ports; browsers reach the API only through
  nginx, which overwrites `X-Forwarded-For`, so rate limits see the real client IP.
- Every app container runs as a non-root user with a read-only root filesystem,
  all Linux capabilities dropped and `no-new-privileges`; only `/tmp` and the
  upload temp directory are writable (tmpfs).
- MongoDB requires authentication; secrets come from git-ignored `.env` files
  and are never copied into images (`.dockerignore`).
- nginx adds Content-Security-Policy, X-Frame-Options, nosniff,
  Referrer-Policy and Permissions-Policy headers and hides its version.
- Health checks gate start-up order (MongoDB → API → web apps).

## Running locally (without Docker)

Prerequisites: Node.js 20+, a MongoDB (Atlas or local), a Cloudinary account,
and a Google OAuth 2.0 Client ID.

```bash
# 1. Backend
cd backend
cp .env.example .env         # then fill in real values
npm install
npm run server               # http://localhost:4000

# 2. Frontend (patient app)
cd ../frontend
cp .env.example .env         # set VITE_BACKEND_URL and VITE_GOOGLE_CLIENT_ID
npm install
npm run dev                  # http://localhost:5173

# 3. Admin panel
cd ../admin
cp .env.example .env         # set VITE_BACKEND_URL
npm install
npm run dev                  # http://localhost:5174
```

The backend refuses to start if `JWT_SECRET` is shorter than 32 characters or
`ADMIN_PASSWORD` is not a strong password of at least 12 characters.

### Generating a strong `JWT_SECRET`

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

### Setting up Google sign-in

1. In the [Google Cloud Console](https://console.cloud.google.com/) create an
   **OAuth 2.0 Client ID** (type *Web application*).
2. Add `http://localhost:5173` to **Authorized JavaScript origins**.
3. Put the client id in `backend/.env` (`GOOGLE_CLIENT_ID`) and
   `frontend/.env` (`VITE_GOOGLE_CLIENT_ID`).

Sign-in flow: the patient app fetches a one-time nonce from
`GET /api/user/auth/google/nonce`, passes it to the Google button, and posts the
returned ID token with the signed nonce token to `POST /api/user/auth/google`.
The backend verifies the ID token (signature, issuer, audience, expiry, verified
email) and that it carries the issued nonce, then returns the app's own JWT.

> ⚠️ **Credential rotation:** the secrets that were committed to the *original*
> repository (MongoDB, Cloudinary, Razorpay keys, admin password) are still
> exposed in that repo's git history and **must be rotated** in their
> respective dashboards.

### Running the security tests

```bash
cd backend
npm test
```

No database or third-party account is needed; the suite runs the Express app
in-process with the data layer stubbed.

---

## Security controls added (quick reference)

- `helmet` security headers, `express-mongo-sanitize`, 1 MB body cap.
- CORS restricted to an `ALLOWED_ORIGINS` allow-list.
- `express-rate-limit` on all auth endpoints; `X-Forwarded-For` trusted only
  when `TRUST_PROXY` is set.
- Central error handler that never leaks internals.
- JWTs signed centrally (HS256 pinned) with expiry + boot-time strong-secret
  and admin-password checks.
- Exact role checks for admin/doctor/patient tokens; identity taken only from
  the verified token; account-wide session revocation.
- Uploads: authenticated first, random names, MIME/extension allow-list,
  magic-byte check, 2 MB cap, temp files deleted.
- Strong password policy (`validator.isStrongPassword`), constant-work login
  (no user-enumeration oracle).
- Google OIDC: server-side ID-token verification, single-use nonce, safe
  account linking (no pre-hijacking).
- Atomic slot booking/cancellation and validated, whitelisted profile updates.
- No secrets or PII in browser consoles; clients drop expired sessions.
- Docker: non-root, read-only, capability-free containers; API and database
  not exposed; CSP and security headers from nginx.
- CI: security tests, `npm audit --audit-level=high`, gitleaks, CodeQL,
  Dependabot.
