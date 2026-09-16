import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import bcrypt from 'bcrypt'
import {
  isObjectId,
  isValidDob,
  isValidPhone,
  isValidSlotDate,
  isValidSlotTime,
  parseAddress,
  parseFees,
} from '../utils/validation.js'
import { verifyPassword } from '../utils/password.js'

describe('slot validators', () => {
  const now = new Date(2026, 8, 17, 12) // 17 Sep 2026

  test('accepts today, yesterday (time-zone slack) and dates up to 60 days ahead', () => {
    for (const date of ['17_9_2026', '16_9_2026', '1_10_2026', '16_11_2026']) {
      assert.equal(isValidSlotDate(date, now), true, date)
    }
  })

  test('rejects past, far-future, impossible and non-date keys', () => {
    for (const date of ['15_9_2026', '17_11_2026', '31_2_2026', '__proto__', 'constructor', '1_1_2026.x', '$where', 17, { $ne: '' }]) {
      assert.equal(isValidSlotDate(date, now), false, String(date))
    }
  })

  test('accepts locale time formats and rejects anything else', () => {
    for (const time of ['10:00 AM', '10:00', '09:30 PM', '10:30 a.m.']) {
      assert.equal(isValidSlotTime(time), true, time)
    }
    for (const time of ['', '10:00 AM; DROP', '<script>', ['10:00'], { $ne: '' }]) {
      assert.equal(isValidSlotTime(time), false, String(time))
    }
  })

  test('ObjectId check only accepts 24 hex characters', () => {
    assert.equal(isObjectId('64b000000000000000000002'), true)
    for (const id of ['64b0', { $gt: '' }, ['64b000000000000000000002'], 'zzzzzzzzzzzzzzzzzzzzzzzz']) {
      assert.equal(isObjectId(id), false)
    }
  })
})

describe('profile validators', () => {
  test('parseAddress keeps only line1/line2 strings', () => {
    assert.deepEqual(parseAddress('{"line1":"a","line2":"b","role":"admin"}'), { line1: 'a', line2: 'b' })
    assert.deepEqual(parseAddress({ line1: 'a' }), { line1: 'a', line2: '' })
    for (const bad of ['{oops', '[1]', 'null', { line1: { $gt: '' } }, { line1: 'x'.repeat(201) }]) {
      assert.equal(parseAddress(bad), null, JSON.stringify(bad))
    }
  })

  test('parseFees accepts only finite non-negative amounts', () => {
    assert.equal(parseFees('50'), 50)
    assert.equal(parseFees(0), 0)
    for (const bad of [-1, 'abc', '', [50], Infinity, 2e6]) {
      assert.equal(parseFees(bad), null, String(bad))
    }
  })

  test('date of birth and phone formats', () => {
    assert.equal(isValidDob('2000-02-29'), true)
    assert.equal(isValidDob('Not Selected'), true)
    assert.equal(isValidDob('2001-02-29'), false)
    assert.equal(isValidDob('2999-01-01'), false)
    assert.equal(isValidPhone('+94 77 123 4567'), true)
    assert.equal(isValidPhone('<img src=x>'), false)
  })
})

describe('verifyPassword', () => {
  test('matches only the right password and never throws on missing hashes', async () => {
    const hash = await bcrypt.hash('Correct#123', 10)
    assert.equal(await verifyPassword('Correct#123', hash), true)
    assert.equal(await verifyPassword('wrong', hash), false)
    assert.equal(await verifyPassword('anything', undefined), false)
  })
})
