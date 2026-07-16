# SE4030 – Secure Software Development Assignment

Hardening of a MERN doctor-appointment booking application (**Prescripto**):
identifying and fixing security vulnerabilities, and adding a Google
OpenID Connect sign-in feature.

---

## Group Members

> ⚠️ **TODO – fill in real names and index numbers before submission.**

| # | Name | Index Number |
|---|------|--------------|
| 1 | Ravindu Nethmina | *TODO* |
| 2 | *TODO* | *TODO* |
| 3 | *TODO* | *TODO* |
| 4 | *TODO* | *TODO* |

## Links

| Item | Link |
|------|------|
| **Original project** (third-party baseline) | https://github.com/RVNethmina/AppointmentBookingSystem |
| **Modified (hardened) project** | *TODO – create the new GitHub repo and paste the link here* |
| **Demo video (≤20 min)** | *TODO – paste YouTube link here* |
| **Report (PDF)** | [`SE4030_Security_Report.pdf`](./SE4030_Security_Report.pdf) |

> The original application is a third-party MERN "Prescripto" doctor-appointment
> clone. Its last commit predates the semester start, its improved version is not
> publicly available, and it is not a security-teaching app (per the assignment
> constraints).

---

## What was done

- Identified and fixed **10 distinct vulnerabilities** (see the table below and
  the full report).
- Implemented **"Sign in with Google"** using the OpenID Connect flow
  (Google Identity Services + `google-auth-library`).
- Every fix is an individual, descriptively-commented git commit so the
  before → after history is auditable.

### Vulnerabilities fixed

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

---

## Project structure

```
backend/    Node.js + Express + MongoDB (Mongoose) REST API
frontend/   React + Vite patient-facing app (has the Google sign-in)
admin/      React + Vite admin & doctor panel
```

## Running locally

Prerequisites: Node.js 18+, a MongoDB (Atlas or local), a Cloudinary account,
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

> ⚠️ **Credential rotation:** the secrets that were committed to the *original*
> repository (MongoDB, Cloudinary, Razorpay keys, admin password) are still
> exposed in that repo's git history and **must be rotated** in their
> respective dashboards. Our repository never contains the live values.

---

## Security controls added (quick reference)

- `helmet` security headers, `express-mongo-sanitize`, 1 MB body cap.
- CORS restricted to an `ALLOWED_ORIGINS` allow-list.
- `express-rate-limit` on all auth endpoints.
- Central error handler that never leaks internals.
- JWTs signed centrally with expiry + a boot-time strong-secret check.
- Role-based authorization for admin/doctor/user tokens.
- Random, type-restricted, size-capped image uploads.
- Strong password policy (`validator.isStrongPassword`).
