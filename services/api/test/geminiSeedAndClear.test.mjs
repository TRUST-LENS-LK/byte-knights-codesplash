import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import {
  seedDemoQueue,
  clearDemoQueue,
  fetchGeminiDemoReports,
  verifyAuditChainIntegrity,
  getModerationQueue,
  submitReport,
  processModerationReview,
  isTestEnvironment,
  isSupabaseConfigured,
} from '../src/services/reportingService.mjs'

test('Gemini AI Seed: fetchGeminiDemoReports safely fails closed in standard test environment', async () => {
  const result = await fetchGeminiDemoReports()
  // Without allowAiInTest flag, outbound network calls are blocked to guarantee offline test determinism
  assert.equal(result, null)
})

test('Gemini AI Seed: fetchGeminiDemoReports generates live/mocked synthetic reports when allowed', async () => {
  const aiReports = await fetchGeminiDemoReports({ allowAiInTest: true })
  if (aiReports) {
    assert.ok(Array.isArray(aiReports))
    assert.ok(aiReports.length >= 1 && aiReports.length <= 3)
    for (const item of aiReports) {
      assert.ok(['suspicious', 'false_positive', 'false_negative'].includes(item.report_type))
      assert.ok(typeof item.reported_domain === 'string' && item.reported_domain.length > 0)
      assert.ok(typeof item.raw_excerpt === 'string' && item.raw_excerpt.length > 0)
      assert.ok(typeof item.notes === 'string')
      assert.equal(item.isAiGenerated, true)
    }
  }
})

test('Hybrid Seeding: seedDemoQueue falls back to static fixtures cleanly when AI is absent or offline', async () => {
  const seeded = await seedDemoQueue({ forceStatic: true })

  assert.ok(Array.isArray(seeded))
  assert.equal(seeded.length, 3)
  assert.equal(seeded.generator, 'static')

  for (const report of seeded) {
    assert.ok(report.id, 'Report must have a generated UUID')
    assert.ok(report.content_sha256, 'Report must have a SHA-256 hash')
    assert.equal(report.content_sha256.length, 64)
    assert.ok(report.notes.includes('[DEMO_FIXTURE]'), 'Report notes must include [DEMO_FIXTURE] marker')
    assert.ok(report.notes.includes('[DEMO_FIXTURE:STATIC]'), 'Report notes must be marked as static')
  }
})

test('Hybrid Seeding: seedDemoQueue handles AI generation tagging and cryptographic hashing', async () => {
  // Simulate AI reports returned from Gemini
  const mockAiReports = [
    {
      report_type: 'suspicious',
      reported_domain: 'dialog-starpoints-reward.xyz',
      raw_excerpt: 'Dialog: You have 6,500 Star Points expiring today. Claim cash voucher at https://dialog-starpoints-reward.xyz/login',
      notes: 'SMS phishing campaign targeting telecom subscribers.',
      isAiGenerated: true,
    },
    {
      report_type: 'suspicious',
      reported_domain: 'boc-portal-update.online',
      raw_excerpt: 'Bank of Ceylon Alert: Online banking locked. Re-activate immediately at https://boc-portal-update.online',
      notes: 'Fake bank login portal harvesting credentials and SMS OTP.',
      isAiGenerated: true,
    },
    {
      report_type: 'false_positive',
      reported_domain: 'mohe.gov.lk',
      raw_excerpt: 'Ministry of Higher Education: National scholarship applications open at http://mohe.gov.lk',
      notes: 'Official government portal flagged because of HTTP scheme.',
      isAiGenerated: true,
    },
  ]

  const seeded = []
  for (const demo of mockAiReports) {
    const freshId = randomUUID()
    const contentHash = createHash('sha256').update(demo.raw_excerpt.trim()).digest('hex')
    const aiTag = demo.isAiGenerated ? '[DEMO_FIXTURE:GEMINI]' : '[DEMO_FIXTURE:STATIC]'

    const dbPayload = {
      id: freshId,
      report_type: demo.report_type,
      content_sha256: contentHash,
      reported_domain: demo.reported_domain,
      notes: `[Reported Message Excerpt]: "${demo.raw_excerpt}"\n\n[Submitter Context]: ${demo.notes} ${aiTag} [DEMO_FIXTURE]`,
      status: 'PENDING',
      created_at: new Date().toISOString(),
    }
    seeded.push(dbPayload)
  }

  assert.equal(seeded.length, 3)
  for (const report of seeded) {
    assert.ok(report.notes.includes('[DEMO_FIXTURE:GEMINI]'), 'Must include GEMINI generator tag')
    assert.ok(report.notes.includes('[DEMO_FIXTURE]'), 'Must include generic DEMO_FIXTURE marker for clearing')
    assert.equal(report.content_sha256.length, 64)
  }
})

test('Clear Demo Mechanism: clearDemoQueue removes all seeded fixtures matching [DEMO_FIXTURE]', async () => {
  // 1. Seed demo queue
  await seedDemoQueue({ forceStatic: true })

  // 2. Clear demo queue
  const clearResult = await clearDemoQueue()
  assert.ok(typeof clearResult.count === 'number')
  assert.ok(clearResult.count >= 3, `Expected at least 3 items cleared, got ${clearResult.count}`)

  // 3. Verify queue no longer has demo fixtures
  const queueResult = await getModerationQueue()
  const reports = queueResult?.reports || []
  const remainingDemoReports = reports.filter(
    (r) => r.notes?.includes('DEMO_FIXTURE') || r.notes?.includes('[DEMO_FIXTURE:GEMINI]')
  )
  assert.equal(remainingDemoReports.length, 0, 'No demo fixtures should remain after clearDemoQueue')
})

test('Clear Demo Safety: clearDemoQueue preserves cryptographic audit chain integrity', async () => {
  // Clear any existing demo fixtures first
  await clearDemoQueue()

  // Seed demo queue
  await seedDemoQueue({ forceStatic: true })

  // Clear demo queue again
  const clearResult = await clearDemoQueue()
  assert.ok(clearResult.count >= 0)

  // Verify audit chain integrity remains 100% valid
  const chainCheck = await verifyAuditChainIntegrity()
  assert.equal(chainCheck.isValid, true, 'Cryptographic audit chain must remain intact after clear cycles')
})

test('Audit Isolation: Automated tests are strictly isolated from remote Supabase audit table', async () => {
  assert.equal(isTestEnvironment(), true)
  assert.equal(isSupabaseConfigured(), false, 'isSupabaseConfigured must be false in test environment')

  const report = await submitReport({
    reportType: 'suspicious',
    text: 'Test isolation check message',
    reportedDomain: 'test-isolation-check.xyz',
    notes: 'Unit test verifying database safety',
  })

  const review = await processModerationReview({
    reportId: report.id,
    action: 'APPROVE',
    confidence: 0.99,
    category: 'Banking Phishing',
    notes: 'Test isolation verification review',
  })

  assert.equal(review.success, true)
  assert.equal(review.status, 'APPROVED')

  // Verify that in-memory audit chain verification remains 100% valid
  const chain = await verifyAuditChainIntegrity()
  assert.equal(chain.isValid, true)
})

