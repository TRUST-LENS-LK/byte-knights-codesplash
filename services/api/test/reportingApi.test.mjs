import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'

const apiPort = 18795
const mockSupabasePort = 18796
const validModeratorToken = 'valid-moderator-jwt-token-xyz'
const regularUserToken = 'regular-citizen-jwt-token-abc'

let child
let mockSupabaseServer
const mockReports = new Map()

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
  // 1. Start mock Supabase server for testing auth & persistence
  mockSupabaseServer = createServer(async (req, res) => {
    let raw = ''
    for await (const chunk of req) raw += chunk

    // Auth endpoint simulation
    if (req.url === '/auth/v1/user') {
      const auth = req.headers['authorization'] || ''
      if (auth === `Bearer ${validModeratorToken}`) {
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ id: 'mod-uuid-1', email: 'moderator@trustlens.lk', app_metadata: { role: 'moderator' } }))
      }
      if (auth === `Bearer ${regularUserToken}`) {
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ id: 'user-uuid-2', email: 'citizen@example.lk', app_metadata: { role: 'user' } }))
      }
      res.writeHead(401, { 'content-type': 'application/json' })
      return res.end(JSON.stringify({ error: 'invalid_token' }))
    }

    if (req.method === 'POST' && req.url.startsWith('/rest/v1/user_reports')) {
      const data = JSON.parse(raw)
      mockReports.set(data.id, data)
      res.writeHead(201, { 'content-type': 'application/json' })
      return res.end(JSON.stringify([data]))
    }

    if (req.method === 'GET' && req.url.startsWith('/rest/v1/user_reports')) {
      const match = req.url.match(/id=eq\.([a-f0-9-]+)/i)
      if (match) {
        const item = mockReports.get(match[1])
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify(item ? [item] : []))
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      return res.end(JSON.stringify(Array.from(mockReports.values())))
    }

    if (req.method === 'PATCH' && req.url.startsWith('/rest/v1/user_reports')) {
      const match = req.url.match(/id=eq\.([a-f0-9-]+)/i)
      if (match && mockReports.has(match[1])) {
        const existing = mockReports.get(match[1])
        const updates = JSON.parse(raw || '{}')
        mockReports.set(match[1], { ...existing, ...updates })
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      return res.end(JSON.stringify([{ status: 'ok' }]))
    }

    // Default REST endpoints simulation
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify([]))
  })

  await new Promise((resolve) => mockSupabaseServer.listen(mockSupabasePort, '127.0.0.1', resolve))

  // 2. Spawn the API server connected to the mock Supabase instance
  child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: {
      ...process.env,
      PORT: String(apiPort),
      SUPABASE_URL: `http://127.0.0.1:${mockSupabasePort}`,
      SUPABASE_SERVICE_ROLE_KEY: 'test-service-key-456',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  await waitForStartup(child, apiPort)
})

test.after(async () => {
  child?.kill()
  await new Promise((resolve) => mockSupabaseServer.close(resolve))
})

test('POST /api/reports: rejects invalid report payloads', async () => {
  // Missing required contentSha256
  const res1 = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ reportType: 'suspicious' }),
  })
  assert.equal(res1.status, 400)
  const body1 = await res1.json()
  assert.equal(body1.code, 'INVALID_REPORT')

  // Invalid reportType
  const res2 = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'unsupported_type',
      contentSha256: 'a'.repeat(64),
    }),
  })
  assert.equal(res2.status, 400)

  // Non-64-char hash
  const res3 = await fetch(`http://localhost:${apiPort}/api/reports`, {
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

  const res = await fetch(`http://localhost:${apiPort}/api/reports`, {
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

test('GET /api/moderation/queue: blocks requests without token', async () => {
  const res = await fetch(`http://localhost:${apiPort}/api/moderation/queue`)
  assert.equal(res.status, 401)
  const body = await res.json()
  assert.equal(body.code, 'UNAUTHORIZED')
})

test('GET /api/moderation/queue: blocks users who do not have the moderator role', async () => {
  const res = await fetch(`http://localhost:${apiPort}/api/moderation/queue`, {
    headers: {
      Authorization: `Bearer ${regularUserToken}`,
    },
  })
  assert.equal(res.status, 401)
  const body = await res.json()
  assert.match(body.message, /moderator privileges/i)
})

test('GET /api/moderation/queue: allows verified Supabase moderator JWT', async () => {
  const res = await fetch(`http://localhost:${apiPort}/api/moderation/queue?status=PENDING`, {
    headers: {
      Authorization: `Bearer ${validModeratorToken}`,
    },
  })

  assert.equal(res.status, 200)
  const body = await res.json()
  assert.ok(Array.isArray(body.reports))
  assert.ok(body.count >= 1)
})

test('POST /api/moderation/review: blocks unauthorized review actions', async () => {
  const res = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportId: '123e4567-e89b-12d3-a456-426614174000',
      action: 'APPROVE',
    }),
  })
  assert.equal(res.status, 401)
})

test('POST /api/moderation/review: approves a pending report using Supabase JWT and creates sanitized intelligence', async () => {
  // 1. Create a report first
  const createRes = await fetch(`http://localhost:${apiPort}/api/reports`, {
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

  // 2. Approve the report as verified moderator
  const reviewRes = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
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
})

test('POST /api/moderation/review: rejects a report cleanly with Supabase JWT', async () => {
  // 1. Create a report
  const createRes = await fetch(`http://localhost:${apiPort}/api/reports`, {
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
  const reviewRes = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
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
