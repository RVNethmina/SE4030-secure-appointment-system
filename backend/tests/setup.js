// Shared test environment. Every test file imports this module FIRST, so the
// values below exist before application modules read process.env at import
// time. No MongoDB, Cloudinary or Google account is needed to run the suite.
import mongoose from 'mongoose'
import jwt from 'jsonwebtoken'

export const JWT_SECRET = 'unit-test-signing-secret-'.padEnd(64, 'x')
export const ADMIN_EMAIL = 'admin@example.com'
export const ADMIN_PASSWORD = 'Str0ng!Admin#Pass'

process.env.JWT_SECRET = JWT_SECRET
process.env.JWT_EXPIRES_IN = '1h'
process.env.ALLOWED_ORIGINS = 'http://localhost:5173'
process.env.ADMIN_EMAIL = ADMIN_EMAIL
process.env.ADMIN_PASSWORD = ADMIN_PASSWORD
process.env.GOOGLE_CLIENT_ID = 'test-client-id.apps.googleusercontent.com'
delete process.env.TRUST_PROXY

// There is no database: any query a test did not stub fails immediately
// instead of buffering for 10 seconds.
mongoose.set('bufferCommands', false)

export const USER_ID = '64b000000000000000000001'
export const DOCTOR_ID = '64b000000000000000000002'

/** Sign an access token the way the API does (HS256, short expiry). */
export const sign = (claims, options = {}) =>
  jwt.sign(claims, JWT_SECRET, { algorithm: 'HS256', expiresIn: '5m', ...options })

/** Replace `target[method]` for the duration of one test. */
export function stub(t, target, method, implementation) {
  const original = target[method]
  target[method] = implementation
  t.after(() => {
    target[method] = original
  })
}

/**
 * A stand-in for a Mongoose query that resolves to `value`, supporting the
 * `.select()`, `.lean()` and direct `await` forms the controllers use.
 */
export const query = (value) => ({
  select() {
    return this
  },
  lean: async () => value,
  then: (resolve, reject) => Promise.resolve(value).then(resolve, reject),
})

// Minimal valid file headers for upload tests.
export const PNG_BYTES = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  Buffer.alloc(32),
])
