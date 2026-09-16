import test from 'node:test'
import assert from 'node:assert/strict'
import { z } from 'zod'

// Define / import the schemas matching contracts
import {
  userReportTypeSchema,
  userReportStatusSchema,
  createUserReportSchema,
  userReportSchema,
  moderationActionSchema,
  verifiedIntelligenceSchema,
} from '../src/index.ts'

test('userReportTypeSchema accepts valid types and rejects invalid', () => {
  assert.equal(userReportTypeSchema.parse('suspicious'), 'suspicious')
  assert.equal(userReportTypeSchema.parse('false_positive'), 'false_positive')
  assert.equal(userReportTypeSchema.parse('false_negative'), 'false_negative')

  assert.throws(() => userReportTypeSchema.parse('invalid_type'))
  assert.throws(() => userReportTypeSchema.parse(''))
})

test('userReportStatusSchema accepts valid statuses', () => {
  for (const status of ['PENDING', 'REVIEWED', 'REJECTED', 'APPROVED', 'RETIRED']) {
    assert.equal(userReportStatusSchema.parse(status), status)
  }
  assert.throws(() => userReportStatusSchema.parse('UNKNOWN'))
})

test('createUserReportSchema validates 64-char SHA256 hashes strictly', () => {
  const validHash = 'a'.repeat(64)
  const validPayload = {
    reportType: 'suspicious',
    contentSha256: validHash,
    reportedDomain: 'fake-bank-lk.com',
    notes: 'Posed as official bank asking for OTP verification.',
  }

  const parsed = createUserReportSchema.parse(validPayload)
  assert.equal(parsed.contentSha256, validHash)
  assert.equal(parsed.reportedDomain, 'fake-bank-lk.com')

  // Reject non-hex characters
  assert.throws(() =>
    createUserReportSchema.parse({
      ...validPayload,
      contentSha256: 'z'.repeat(64),
    })
  )

  // Reject short hashes
  assert.throws(() =>
    createUserReportSchema.parse({
      ...validPayload,
      contentSha256: 'a'.repeat(63),
    })
  )

  // Reject long hashes
  assert.throws(() =>
    createUserReportSchema.parse({
      ...validPayload,
      contentSha256: 'a'.repeat(65),
    })
  )
})

test('createUserReportSchema enforces maximum notes limit of 2,000 characters', () => {
  const validHash = 'b'.repeat(64)
  const okPayload = {
    reportType: 'false_positive',
    contentSha256: validHash,
    notes: 'x'.repeat(2000),
  }
  assert.doesNotThrow(() => createUserReportSchema.parse(okPayload))

  const tooLongPayload = {
    reportType: 'false_positive',
    contentSha256: validHash,
    notes: 'x'.repeat(2001),
  }
  assert.throws(() => createUserReportSchema.parse(tooLongPayload))
})

test('moderationActionSchema accepts APPROVE, REJECT, RETIRE with UUID', () => {
  const reportId = '123e4567-e89b-12d3-a456-426614174000'
  const action = moderationActionSchema.parse({
    reportId,
    action: 'APPROVE',
    notes: 'Confirmed malicious domain impersonating department.',
    indicatorType: 'domain',
    category: 'Impersonation',
  })

  assert.equal(action.reportId, reportId)
  assert.equal(action.action, 'APPROVE')

  // Non-UUID reportId must be rejected
  assert.throws(() =>
    moderationActionSchema.parse({
      reportId: 'not-a-uuid',
      action: 'APPROVE',
    })
  )

  // Invalid action must be rejected
  assert.throws(() =>
    moderationActionSchema.parse({
      reportId,
      action: 'DELETE',
    })
  )
})

test('verifiedIntelligenceSchema enforces confidence bounds and required fields', () => {
  const validIntel = {
    id: 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    sourceReportId: '123e4567-e89b-12d3-a456-426614174000',
    indicatorType: 'domain',
    indicatorValue: 'scam-lottery-lk.xyz',
    defangedValue: 'hxxps://scam-lottery-lk[.]xyz',
    riskLevel: 'CONFIRMED_SCAM',
    confidence: 1.0,
    active: true,
    createdAt: new Date().toISOString(),
  }

  const parsed = verifiedIntelligenceSchema.parse(validIntel)
  assert.equal(parsed.indicatorType, 'domain')
  assert.equal(parsed.riskLevel, 'CONFIRMED_SCAM')

  // Reject confidence outside 0-1
  assert.throws(() =>
    verifiedIntelligenceSchema.parse({
      ...validIntel,
      confidence: 1.5,
    })
  )
})
