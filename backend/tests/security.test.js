import {
  ADMIN_EMAIL,
  ADMIN_PASSWORD,
  DOCTOR_ID,
  JWT_SECRET,
  PNG_BYTES,
  USER_ID,
  query,
  sign,
  stub,
} from './setup.js'
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { spawnSync } from 'node:child_process'
import jwt from 'jsonwebtoken'
import request from 'supertest'
import { OAuth2Client } from 'google-auth-library'
import app from '../app.js'
import userModel from '../models/userModel.js'
import { signNonceToken } from '../utils/token.js'

// Security regression tests: each block maps to a vulnerability that was fixed
// in this repository. They run in-process against the Express app with the
// database layer stubbed.

const userToken = () => sign({ id: USER_ID, role: 'user' })
const doctorToken = () => sign({ id: DOCTOR_ID, role: 'doctor' })
const adminToken = () => sign({ role: 'admin', email: ADMIN_EMAIL })

// authUser loads the account to check revocation; make it exist.
const withExistingUser = (t, account = { _id: USER_ID, sessionsValidAfter: 0 }) =>
  stub(t, userModel, 'findById', () => query(account))

const uploadedFiles = () =>
  fs.existsSync('uploads') ? fs.readdirSync('uploads').filter((f) => f !== '.gitkeep') : []

describe('HTTP hardening (Helmet, CORS, body limits)', () => {
  test('sets security headers and hides the framework banner', async () => {
    const res = await request(app).get('/')
    assert.equal(res.headers['x-content-type-options'], 'nosniff')
    assert.ok(res.headers['x-frame-options'])
    assert.ok(res.headers['content-security-policy'])
    assert.equal(res.headers['x-powered-by'], undefined)
  })

  test('rejects browser requests from origins outside the allow-list', async () => {
    const evil = await request(app).get('/api/doctor/list').set('Origin', 'https://evil.example')
    assert.equal(evil.status, 403)
    assert.equal(evil.body.message, 'Origin not allowed.')

    const ok = await request(app).options('/api/doctor/list').set('Origin', 'http://localhost:5173')
    assert.equal(ok.headers['access-control-allow-origin'], 'http://localhost:5173')
  })

  test('rejects oversized JSON bodies before they reach a route', async () => {
    const res = await request(app)
      .post('/api/doctor/update-profile')
      .set('Content-Type', 'application/json')
      .send(JSON.stringify({ about: 'x'.repeat(2 * 1024 * 1024) }))
    assert.equal(res.status, 413)
  })
})

describe('JWT validation and role-based authorization', () => {
  test('requires a token', async () => {
    const res = await request(app).get('/api/user/appointments')
    assert.equal(res.status, 401)
  })

  test('rejects unsigned (alg=none) tokens', async () => {
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url')
    const forged = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ id: USER_ID, role: 'user' })}.`
    const res = await request(app).get('/api/user/appointments').set('token', forged)
    assert.equal(res.status, 401)
  })

  test("rejects tokens signed with the original weak secret 'RBRO'", async () => {
    const forged = jwt.sign({ id: USER_ID, role: 'user' }, 'RBRO')
    const res = await request(app).get('/api/user/appointments').set('token', forged)
    assert.equal(res.status, 401)
  })

  test('rejects expired tokens', async () => {
    const expired = jwt.sign(
      { id: USER_ID, role: 'user', exp: Math.floor(Date.now() / 1000) - 60 },
      JWT_SECRET,
      { algorithm: 'HS256' }
    )
    const res = await request(app).get('/api/user/appointments').set('token', expired)
    assert.equal(res.status, 401)
  })

  test('rejects tokens signed with a different algorithm (HS256 is pinned)', async () => {
    const hs512 = jwt.sign({ id: USER_ID, role: 'user' }, JWT_SECRET, { algorithm: 'HS512' })
    const res = await request(app).get('/api/user/appointments').set('token', hs512)
    assert.equal(res.status, 401)
  })

  test("rejects the original forgeable admin token (sign(email + password))", async () => {
    const legacy = jwt.sign(ADMIN_EMAIL + ADMIN_PASSWORD, JWT_SECRET)
    const res = await request(app).get('/api/admin/dashboard').set('atoken', legacy)
    assert.equal(res.status, 403)
  })

  test('a doctor or admin token is not a patient session', async () => {
    for (const token of [doctorToken(), adminToken()]) {
      const res = await request(app).get('/api/user/appointments').set('token', token)
      assert.equal(res.status, 403)
    }
  })

  test('patient tokens and role-less tokens cannot use the doctor panel', async () => {
    for (const token of [userToken(), sign({ id: DOCTOR_ID })]) {
      const res = await request(app).get('/api/doctor/appointments').set('dtoken', token)
      assert.equal(res.status, 403)
    }
  })

  test('a patient token cannot use admin endpoints', async () => {
    const res = await request(app).get('/api/admin/dashboard').set('atoken', userToken())
    assert.equal(res.status, 403)
  })

  test('tokens issued before a session revocation are rejected', async (t) => {
    withExistingUser(t, { _id: USER_ID, sessionsValidAfter: Math.floor(Date.now() / 1000) + 60 })
    const res = await request(app).get('/api/user/appointments').set('token', userToken())
    assert.equal(res.status, 401)
  })

  test('tokens of deleted accounts are rejected', async (t) => {
    stub(t, userModel, 'findById', () => query(null))
    const res = await request(app).get('/api/user/appointments').set('token', userToken())
    assert.equal(res.status, 401)
  })
})

describe('Boot-time secret checks', () => {
  const boot = (overrides) =>
    spawnSync(process.execPath, ['server.js'], {
      env: { ...process.env, PORT: '0', ...overrides },
      encoding: 'utf8',
      timeout: 20000,
    })

  test("refuses to start with the original JWT secret 'RBRO'", () => {
    const run = boot({ JWT_SECRET: 'RBRO' })
    assert.notEqual(run.status, 0)
    assert.match(run.stderr, /JWT_SECRET is missing or too weak/)
  })

  test("refuses to start with the original admin password 'qwerty123'", () => {
    const run = boot({ ADMIN_PASSWORD: 'qwerty123' })
    assert.notEqual(run.status, 0)
    assert.match(run.stderr, /ADMIN_PASSWORD must be/)
  })
})

describe('NoSQL injection and login oracles', () => {
  test('operator objects in login bodies never reach a query', async () => {
    for (const path of ['/api/user/login', '/api/doctor/login']) {
      const res = await request(app)
        .post(path)
        .send({ email: { $ne: null }, password: { $ne: null } })
      assert.equal(res.status, 200)
      assert.equal(res.body.success, false)
      assert.equal(res.body.message, 'Invalid Credentials!')
    }
  })

  test('a Google-only account (no password) fails like any wrong password', async (t) => {
    stub(t, userModel, 'findOne', () =>
      query({ _id: USER_ID, email: 'g@example.com', authProvider: 'google' })
    )
    const res = await request(app)
      .post('/api/user/login')
      .send({ email: 'g@example.com', password: 'Whatever1!' })
    assert.equal(res.status, 200)
    assert.equal(res.body.message, 'Invalid Credentials!')
  })
})

describe('File uploads', () => {
  test('anonymous uploads are rejected before anything is written to disk', async () => {
    const before = uploadedFiles().length
    const res = await request(app)
      .post('/api/user/update-profile')
      .attach('image', PNG_BYTES, { filename: 'a.png', contentType: 'image/png' })
    assert.equal(res.status, 401)
    assert.equal(uploadedFiles().length, before)
  })

  test('a non-image disguised as PNG is rejected and deleted', async (t) => {
    withExistingUser(t)
    const before = uploadedFiles().length
    const res = await request(app)
      .post('/api/user/update-profile')
      .set('token', userToken())
      .attach('image', Buffer.from('<?php system($_GET["c"]); ?>'), {
        filename: 'avatar.png',
        contentType: 'image/png',
      })
    assert.equal(res.status, 400)
    assert.equal(res.body.message, 'Uploaded file is not a valid image.')
    assert.equal(uploadedFiles().length, before)
  })

  test('disallowed extensions and MIME types are rejected', async (t) => {
    withExistingUser(t)
    const res = await request(app)
      .post('/api/user/update-profile')
      .set('token', userToken())
      .attach('image', PNG_BYTES, { filename: 'shell.php', contentType: 'application/x-php' })
    assert.equal(res.status, 400)
  })

  test('files over 2 MB are rejected', async () => {
    const res = await request(app)
      .post('/api/admin/add-doctor')
      .set('atoken', adminToken())
      .attach('image', Buffer.concat([PNG_BYTES, Buffer.alloc(3 * 1024 * 1024)]), {
        filename: 'big.png',
        contentType: 'image/png',
      })
    assert.equal(res.status, 400)
    assert.equal(res.body.message, 'File too large')
  })

  test('temporary upload files are deleted even when validation fails', async () => {
    const before = uploadedFiles().length
    const res = await request(app)
      .post('/api/admin/add-doctor')
      .set('atoken', adminToken())
      .attach('image', PNG_BYTES, { filename: 'doc.png', contentType: 'image/png' })
    assert.equal(res.body.message, 'Missing Details')
    assert.equal(uploadedFiles().length, before)
  })
})

describe('Input validation and mass assignment', () => {
  test('booking rejects prototype keys, bad dates and malformed ids', async (t) => {
    withExistingUser(t)
    const d = new Date()
    const today = `${d.getDate()}_${d.getMonth() + 1}_${d.getFullYear()}`
    const bad = [
      { docId: DOCTOR_ID, slotDate: '__proto__', slotTime: '10:00 AM' },
      { docId: DOCTOR_ID, slotDate: '31_2_2026', slotTime: '10:00 AM' },
      { docId: DOCTOR_ID, slotDate: '1_1_2020', slotTime: '10:00 AM' },
      { docId: 'not-an-id', slotDate: today, slotTime: '10:00 AM' },
      { docId: { $gt: '' }, slotDate: today, slotTime: '10:00 AM' },
      { docId: DOCTOR_ID, slotDate: today, slotTime: { $ne: '' } },
    ]
    for (const body of bad) {
      const res = await request(app)
        .post('/api/user/book-appointment')
        .set('token', userToken())
        .send(body)
      assert.equal(res.status, 400, JSON.stringify(body))
    }
  })

  test('patient profile rejects malformed address JSON and invalid fields', async (t) => {
    withExistingUser(t)
    const res = await request(app)
      .post('/api/user/update-profile')
      .set('token', userToken())
      .field('name', 'Alice')
      .field('phone', '0771234567')
      .field('dob', '2000-01-01')
      .field('gender', 'Female')
      .field('address', '{not json')
    assert.equal(res.status, 400)
    assert.equal(res.body.message, 'Invalid profile details.')
  })

  test('doctors cannot set a negative fee or a non-object address', async () => {
    for (const body of [
      { fees: -500, address: { line1: 'a', line2: 'b' }, available: true },
      { fees: 50, address: 'x', available: true },
      { fees: 50, address: { line1: 'a', line2: 'b' }, available: 'yes' },
    ]) {
      const res = await request(app)
        .post('/api/doctor/update-profile')
        .set('dtoken', doctorToken())
        .send(body)
      assert.equal(res.status, 400, JSON.stringify(body))
    }
  })

  test('appointment ids must be ObjectIds (no operator objects)', async (t) => {
    withExistingUser(t)
    const user = await request(app)
      .post('/api/user/cancel-appointment')
      .set('token', userToken())
      .send({ appointmentId: { $gt: '' } })
    assert.equal(user.status, 400)

    const admin = await request(app)
      .post('/api/admin/cancel-appointment')
      .set('atoken', adminToken())
      .send({ appointmentId: '123' })
    assert.equal(admin.status, 400)
  })
})

describe('Google OpenID Connect sign-in', () => {
  const googleLogin = (credential, nonceToken) =>
    request(app).post('/api/user/auth/google').send({ credential, nonceToken })

  const fakeGoogle = (t, payload) =>
    stub(t, OAuth2Client.prototype, 'verifyIdToken', async () => ({ getPayload: () => payload }))

  test('issues a random, non-cacheable nonce', async () => {
    const a = await request(app).get('/api/user/auth/google/nonce')
    const b = await request(app).get('/api/user/auth/google/nonce')
    assert.equal(a.status, 200)
    assert.equal(a.headers['cache-control'], 'no-store')
    assert.ok(a.body.nonce.length >= 43)
    assert.notEqual(a.body.nonce, b.body.nonce)
  })

  test('requires a nonce token', async () => {
    const res = await googleLogin('header.payload.signature', undefined)
    assert.equal(res.status, 400)
  })

  test('nonce tokens cannot be used as access tokens', async () => {
    const res = await request(app)
      .get('/api/user/appointments')
      .set('token', signNonceToken('abc'))
    assert.equal(res.status, 401)
  })

  test('rejects a valid Google ID token that was issued for a different nonce', async (t) => {
    fakeGoogle(t, { sub: 'g-1', email: 'a@gmail.com', email_verified: true, nonce: 'other' })
    const res = await googleLogin('id-token', signNonceToken('expected'))
    assert.equal(res.status, 401)
    assert.equal(res.body.message, 'Google sign-in failed.')
  })

  test('linking an existing local account drops the pre-set password, and replays fail', async (t) => {
    const nonce = 'nonce-for-linking-test'
    const nonceToken = signNonceToken(nonce)
    fakeGoogle(t, { sub: 'g-victim', email: 'victim@gmail.com', email_verified: true, nonce })

    // An attacker pre-registered the victim's email with their own password.
    const preRegistered = {
      _id: USER_ID,
      email: 'victim@gmail.com',
      authProvider: 'local',
      password: '$2b$10$attackerchosenpasswordhashxxxxxxxxxxxxxxxxxxxxxxxxxx',
      sessionsValidAfter: 0,
      saved: false,
      async save() {
        this.saved = true
      },
    }
    stub(t, userModel, 'findOne', (filter) => query(filter.googleId ? null : preRegistered))

    const res = await googleLogin('id-token', nonceToken)
    assert.equal(res.status, 200)
    assert.equal(res.body.success, true)
    assert.equal(jwt.verify(res.body.token, JWT_SECRET).role, 'user')

    assert.equal(preRegistered.saved, true)
    assert.equal(preRegistered.password, undefined)
    assert.equal(preRegistered.authProvider, 'google')
    assert.ok(preRegistered.sessionsValidAfter >= Math.floor(Date.now() / 1000) - 5)

    // The same ID token + nonce token pair cannot be used a second time.
    const replay = await googleLogin('id-token', nonceToken)
    assert.equal(replay.status, 401)
    assert.equal(replay.body.message, 'Google sign-in expired, please try again.')
  })
})
