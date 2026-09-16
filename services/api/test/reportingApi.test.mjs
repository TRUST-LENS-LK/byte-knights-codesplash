import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'

const port = 18795
const moderatorSecret = 'test-mod-secret-key-123'
let child

function waitForStartup(processChild, port, label = 'Reporting API') {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} did not start on port ${port}`)), 5000)
    processChild.stdout.on('data', (chunk) => {
      if (chunk.toString().includes(`:${port}`)) {
        clearTimeout(timer)
        resolve()
      }
    })
    processChild.on('error', reject)
  })
}

test.before(async () => {
  child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: {
      ...process.env,
      PORT: String(port),
      MODERATOR_SECRET: moderatorSecret,
      SUPABASE_URL: '',
      SUPABASE_SERVICE_ROLE_KEY: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  await waitForStartup(child, port)
})

test.after(() => child?.kill())

test('POST /api/reports: rejects invalid report payloads', async () => {
  // Missing required contentSha256
  const res1 = await fetch(`http://localhost:${port}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ reportType: 'suspicious' }),
  })
  assert.equal(res1.status, 400)
  const body1 = await res1.json()
  assert.equal(body1.code, 'INVALID_REPORT')

  // Invalid reportType
  const res2 = await fetch(`http://localhost:${port}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'unsupported_type',
      contentSha256: 'a'.repeat(64),
    }),
  })
  assert.equal(res2.status, 400)

  // Non-64-char hash
  const res3 = await fetch(`http://localhost:${port}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: 'short-hash',
    }),
  })
  assert.equal(res3.status, 400)
})

test('POST /api/reports: successfully creates a user report with PENDING status', async () => {
  const payload = {
    reportType: 'suspicious',
    contentSha256: 'f'.repeat(64),
    reportedDomain: 'phishing-srilanka-portal.xyz',
    notes: 'Received SMS pretending to be Sri Lanka Telecom asking for bill payment.',
  }

  const res = await fetch(`http://localhost:${port}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  })

  assert.equal(res.status, 201)
  const body = await res.json()
  assert.ok(body.report)
  assert.equal(body.report.status, 'PENDING')
  assert.equal(body.report.report_type, 'suspicious')
  assert.equal(body.report.reported_domain, 'phishing-srilanka-portal.xyz')
  assert.match(body.report.id, /^[0-9a-f-]{36}$/)
})

test('GET /api/moderation/queue: blocks unauthorized requests', async () => {
  const res = await fetch(`http://localhost:${port}/api/moderation/queue`)
  assert.equal(res.status, 401)
  const body = await res.json()
  assert.equal(body.code, 'UNAUTHORIZED')
})

test('GET /api/moderation/queue: allows authorized moderator and returns pending reports', async () => {
  const res = await fetch(`http://localhost:${port}/api/moderation/queue`, {
    headers: {
      'x-moderator-key': moderatorSecret,
    },
  })

  assert.equal(res.status, 200)
  const body = await res.json()
  assert.ok(Array.isArray(body.reports))
  assert.ok(body.count >= 1)
  assert.equal(body.reports[0].reported_domain, 'phishing-srilanka-portal.xyz')
})

test('POST /api/moderation/review: blocks unauthorized review actions', async () => {
  const res = await fetch(`http://localhost:${port}/api/moderation/review`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportId: '123e4567-e89b-12d3-a456-426614174000',
      action: 'APPROVE',
    }),
  })
  assert.equal(res.status, 401)
})

test('POST /api/moderation/review: approves a pending report and creates sanitized verified intelligence', async () => {
  // 1. Create a report first
  const createRes = await fetch(`http://localhost:${port}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: 'e'.repeat(64),
      reportedDomain: 'urgent-bank-verify-lk.com',
      notes: 'Fake bank login link.',
    }),
  })
  const { report } = await createRes.json()
  assert.ok(report?.id)

  // 2. Approve the report as moderator
  const reviewRes = await fetch(`http://localhost:${port}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-moderator-key': moderatorSecret,
    },
    body: JSON.stringify({
      reportId: report.id,
      action: 'APPROVE',
      notes: 'Confirmed phishing website impersonating local bank.',
      indicatorType: 'domain',
      category: 'Banking Phishing',
    }),
  })

  assert.equal(reviewRes.status, 200)
  const reviewBody = await reviewRes.json()
  assert.equal(reviewBody.result.success, true)
  assert.equal(reviewBody.result.status, 'APPROVED')
  assert.ok(reviewBody.result.verifiedIntelligenceId)

  // 3. Verify report status updated in queue
  const queueRes = await fetch(`http://localhost:${port}/api/moderation/queue?status=APPROVED`, {
    headers: { 'x-moderator-key': moderatorSecret },
  })
  const queueBody = await queueRes.json()
  const approvedItem = queueBody.reports.find((r) => r.id === report.id)
  assert.ok(approvedItem)
  assert.equal(approvedItem.status, 'APPROVED')
})

test('POST /api/moderation/review: rejects a false alarm report cleanly', async () => {
  // 1. Create a report
  const createRes = await fetch(`http://localhost:${port}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'false_positive',
      contentSha256: 'c'.repeat(64),
      reportedDomain: 'official-gov-agency.gov.lk',
      notes: 'Not a scam, this is official.',
    }),
  })
  const { report } = await createRes.json()

  // 2. Reject the report
  const reviewRes = await fetch(`http://localhost:${port}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-moderator-key': moderatorSecret,
    },
    body: JSON.stringify({
      reportId: report.id,
      action: 'REJECT',
      notes: 'Verified as non-malicious.',
    }),
  })

  assert.equal(reviewRes.status, 200)
  const reviewBody = await reviewRes.json()
  assert.equal(reviewBody.result.status, 'REJECTED')
})
