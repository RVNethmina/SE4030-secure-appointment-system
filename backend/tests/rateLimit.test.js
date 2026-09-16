import './setup.js'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import app from '../app.js'

// Runs in its own process (node --test isolates files), so the in-memory rate
// limit counters start at zero.

test('login attempts are throttled after 10 and spoofed X-Forwarded-For does not reset the limit', async () => {
  const statuses = []
  for (let i = 0; i < 12; i++) {
    const res = await request(app)
      .post('/api/admin/login')
      .set('X-Forwarded-For', `10.0.0.${i}`)
      .send({ email: 1, password: 1 })
    statuses.push(res.status)
  }
  assert.deepEqual(statuses.slice(0, 10), Array(10).fill(400))
  assert.deepEqual(statuses.slice(10), [429, 429])
})
