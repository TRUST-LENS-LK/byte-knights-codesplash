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

    if (req.method === 'POST' && req.url.startsWith('/auth/v1/token')) {
      const { email, password } = JSON.parse(raw || '{}')
      if (email === 'moderator@trustlens.lk' && password === 'ValidPassword123!') {
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({
          access_token: validModeratorToken,
          user: { id: 'mod-uuid-1', email: 'moderator@trustlens.lk', app_metadata: { role: 'moderator' } },
        }))
      }
      if (email === 'citizen@example.lk') {
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({
          access_token: regularUserToken,
          user: { id: 'user-uuid-2', email: 'citizen@example.lk', app_metadata: { role: 'user' } },
        }))
      }
      res.writeHead(400, { 'content-type': 'application/json' })
      return res.end(JSON.stringify({ error_description: 'Invalid login credentials' }))
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
      let allItems = Array.from(mockReports.values())
      const statusMatch = req.url.match(/status=eq\.([A-Z_]+)/i)
      if (statusMatch && statusMatch[1] !== 'ALL') {
        allItems = allItems.filter((r) => r.status === statusMatch[1])
      }
      const hashMatch = req.url.match(/content_sha256=eq\.([a-f0-9]+)/i)
      if (hashMatch) {
        allItems = allItems.filter((r) => r.content_sha256 === hashMatch[1].toLowerCase())
      }
      const typeMatch = req.url.match(/report_type=eq\.([a-z_]+)/i)
      if (typeMatch) {
        allItems = allItems.filter((r) => r.report_type === typeMatch[1])
      }

      const total = allItems.length
      const limitMatch = req.url.match(/limit=(\d+)/)
      const offsetMatch = req.url.match(/offset=(\d+)/)
      let sliced = allItems
      if (limitMatch) {
        const lim = parseInt(limitMatch[1], 10)
        const off = offsetMatch ? parseInt(offsetMatch[1], 10) : 0
        sliced = allItems.slice(off, off + lim)
        res.setHeader('content-range', `${off}-${Math.max(off, off + sliced.length - 1)}/${total}`)
      } else {
        res.setHeader('content-range', `0-${Math.max(0, total - 1)}/${total}`)
      }

      res.writeHead(200, { 'content-type': 'application/json' })
      return res.end(JSON.stringify(sliced))
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

    if (req.method === 'DELETE' && req.url.startsWith('/rest/v1/user_reports')) {
      const deletedItems = []
      for (const [id, report] of mockReports.entries()) {
        if (report.notes?.includes('DEMO_FIXTURE') || ['phishing-scam.lk', 'fake-ceb-bill.lk', 'suspicious-lottery.lk'].includes(report.reported_domain)) {
          deletedItems.push(report)
          mockReports.delete(id)
        }
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      return res.end(JSON.stringify(deletedItems))
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

test('POST /api/reports: coalesces duplicate pending report within cooldown window instead of creating duplicate rows', async () => {
  const hash = 'a1'.repeat(32)
  const payload1 = {
    reportType: 'suspicious',
    contentSha256: hash,
    reportedDomain: 'duplicate-check.lk',
    notes: 'Initial citizen report about suspicious message.',
  }

  // 1. First submission creates the report
  const res1 = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload1),
  })
  assert.equal(res1.status, 201)
  const body1 = await res1.json()
  assert.ok(body1.report?.id)
  const initialId = body1.report.id

  // 2. Second submission with the same hash within 15 minutes coalesces
  const payload2 = {
    reportType: 'suspicious',
    contentSha256: hash,
    reportedDomain: 'duplicate-check.lk',
    notes: 'Second user reporting the same scam message.',
  }
  const res2 = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload2),
  })
  assert.equal(res2.status, 201)
  const body2 = await res2.json()
  assert.equal(body2.report.id, initialId, 'Should return the same existing report ID')
  assert.equal(body2.report.coalesced, true, 'Should indicate report was coalesced')
  assert.equal(body2.report.submission_count, 2, 'Should increment submission count to 2')
  assert.match(body2.report.notes, /Corroborated Submissions:\s*2/)
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
  assert.equal(body.page, 1)
  assert.ok(body.limit > 0)
  assert.ok(body.total >= 1)
  assert.ok(body.totalPages >= 1)
})

test('GET /api/moderation/stats: blocks requests without token or non-moderators', async () => {
  const unauth = await fetch(`http://localhost:${apiPort}/api/moderation/stats`)
  assert.equal(unauth.status, 401)

  const nonMod = await fetch(`http://localhost:${apiPort}/api/moderation/stats`, {
    headers: { Authorization: `Bearer ${regularUserToken}` },
  })
  assert.equal(nonMod.status, 401)
})

test('GET /api/moderation/stats: returns aggregated metrics, velocity, and threat categories with moderator JWT', async () => {
  const res = await fetch(`http://localhost:${apiPort}/api/moderation/stats`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(res.status, 200)
  const body = await res.json()
  assert.ok(body.metrics)
  assert.ok(typeof body.metrics.totalReports === 'number')
  assert.ok(typeof body.metrics.pendingCount === 'number')
  assert.ok(typeof body.metrics.verificationVelocity === 'number')
  assert.ok(Array.isArray(body.weeklyActivity))
  assert.equal(body.weeklyActivity.length, 7)
  assert.ok(Array.isArray(body.threatCategories))
})

test('GET /api/moderation/queue: supports pagination with custom page and limit', async () => {
  // First seed or verify multiple reports exist
  const resPage1 = await fetch(`http://localhost:${apiPort}/api/moderation/queue?status=ALL&page=1&limit=2`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(resPage1.status, 200)
  const body1 = await resPage1.json()
  assert.equal(body1.page, 1)
  assert.equal(body1.limit, 2)
  assert.ok(body1.reports.length <= 2)
  assert.ok(body1.totalPages >= 1)

  const resPage2 = await fetch(`http://localhost:${apiPort}/api/moderation/queue?status=ALL&page=2&limit=2`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(resPage2.status, 200)
  const body2 = await resPage2.json()
  assert.equal(body2.page, 2)
  assert.equal(body2.limit, 2)

  // Out of bounds page should return empty reports array with total intact
  const resOob = await fetch(`http://localhost:${apiPort}/api/moderation/queue?status=ALL&page=99999&limit=10`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(resOob.status, 200)
  const bodyOob = await resOob.json()
  assert.equal(bodyOob.page, 99999)
  assert.equal(bodyOob.reports.length, 0)
  assert.ok(bodyOob.total >= 1)
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

test('POST /api/moderation/login: rejects invalid credentials or non-moderator accounts', async () => {
  // Invalid credentials
  const badRes = await fetch(`http://localhost:${apiPort}/api/moderation/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'bad@user.com', password: 'wrong' }),
  })
  assert.equal(badRes.status, 401)

  // Non-moderator account (citizen)
  const citizenRes = await fetch(`http://localhost:${apiPort}/api/moderation/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'citizen@example.lk', password: 'pass' }),
  })
  assert.equal(citizenRes.status, 403)
  const citizenBody = await citizenRes.json()
  assert.match(citizenBody.message, /moderator privileges/i)
})

test('POST /api/moderation/login: succeeds for verified moderator account and returns JWT', async () => {
  const loginRes = await fetch(`http://localhost:${apiPort}/api/moderation/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'moderator@trustlens.lk', password: 'ValidPassword123!' }),
  })

  assert.equal(loginRes.status, 200)
  const body = await loginRes.json()
  assert.ok(body.accessToken)
  assert.equal(body.user.role, 'moderator')
  assert.equal(body.user.email, 'moderator@trustlens.lk')
})

test('POST /api/moderation/seed-demo: blocks requests without moderator token', async () => {
  const unauthRes = await fetch(`http://localhost:${apiPort}/api/moderation/seed-demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
  })
  assert.equal(unauthRes.status, 401)
})

test('POST /api/moderation/seed-demo: populates demo fixtures when called by verified moderator', async () => {
  const seedRes = await fetch(`http://localhost:${apiPort}/api/moderation/seed-demo`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
  })
  assert.equal(seedRes.status, 200)
  const body = await seedRes.json()
  assert.ok(Array.isArray(body.seeded))
  assert.equal(body.count, 3)
})

test('GET & PATCH /api/moderation/settings: manages engine settings dynamically', async () => {
  // 1. Blocks unauthorized
  const unauthRes = await fetch(`http://localhost:${apiPort}/api/moderation/settings`)
  assert.equal(unauthRes.status, 401)

  // 2. GET settings with valid token
  const getRes = await fetch(`http://localhost:${apiPort}/api/moderation/settings`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(getRes.status, 200)
  const getBody = await getRes.json()
  assert.equal(getBody.success, true)
  assert.equal(typeof getBody.settings.enableVerifiedIntel, 'boolean')

  // 3. PATCH settings to toggle off
  const patchRes = await fetch(`http://localhost:${apiPort}/api/moderation/settings`, {
    method: 'PATCH',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({ enableVerifiedIntel: false }),
  })
  assert.equal(patchRes.status, 200)
  const patchBody = await patchRes.json()
  assert.equal(patchBody.settings.enableVerifiedIntel, false)

  // 4. PATCH auditRetentionDays
  const patchRetentionRes = await fetch(`http://localhost:${apiPort}/api/moderation/settings`, {
    method: 'PATCH',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({ auditRetentionDays: 60 }),
  })
  assert.equal(patchRetentionRes.status, 200)
  const patchRetentionBody = await patchRetentionRes.json()
  assert.equal(patchRetentionBody.settings.auditRetentionDays, 60)

  // 5. Restore setting to true and 90 days
  await fetch(`http://localhost:${apiPort}/api/moderation/settings`, {
    method: 'PATCH',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({ enableVerifiedIntel: true, auditRetentionDays: 90 }),
  })
})

test('GET & PATCH /api/moderation/intelligence: lists and toggles verified intelligence', async () => {
  // 1. Blocks unauthorized
  const unauthRes = await fetch(`http://localhost:${apiPort}/api/moderation/intelligence`)
  assert.equal(unauthRes.status, 401)

  // 2. GET intelligence with valid token
  const getRes = await fetch(`http://localhost:${apiPort}/api/moderation/intelligence?status=all&page=1&limit=10`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(getRes.status, 200)
  const getBody = await getRes.json()
  assert.equal(getBody.success, true)
  assert.ok(Array.isArray(getBody.intelligence))
  assert.ok(getBody.total >= 0)

  // 3. PATCH status if an item exists
  if (getBody.intelligence.length > 0) {
    const item = getBody.intelligence[0]
    const patchRes = await fetch(`http://localhost:${apiPort}/api/moderation/intelligence/${item.id}`, {
      method: 'PATCH',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${validModeratorToken}`,
      },
      body: JSON.stringify({ active: false, notes: 'Retired for test' }),
    })
    assert.equal(patchRes.status, 200)
    const patchBody = await patchRes.json()
    assert.equal(patchBody.success, true)
    assert.equal(patchBody.updated.active, false)
  }
})

test('POST /api/moderation/clear-demo: blocks requests without moderator token', async () => {
  const unauthRes = await fetch(`http://localhost:${apiPort}/api/moderation/clear-demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
  })
  assert.equal(unauthRes.status, 401)
})

test('POST /api/moderation/clear-demo: clears demo reports when called by verified moderator', async () => {
  // First ensure there is at least one seed
  await fetch(`http://localhost:${apiPort}/api/moderation/seed-demo`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
  })

  // Clear demo data
  const clearRes = await fetch(`http://localhost:${apiPort}/api/moderation/clear-demo`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
  })

  assert.equal(clearRes.status, 200)
  const body = await clearRes.json()
  assert.equal(body.success, true)
  assert.ok(typeof body.count === 'number')
})

test('GET /api/moderation/audit-logs: blocks unauthenticated requests and returns audit trail for moderator', async () => {
  // 1. Unauthenticated request blocked
  const unauthRes = await fetch(`http://localhost:${apiPort}/api/moderation/audit-logs`)
  assert.equal(unauthRes.status, 401)

  // 2. Authenticated query succeeds
  const authRes = await fetch(`http://localhost:${apiPort}/api/moderation/audit-logs?page=1&limit=10`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(authRes.status, 200)
  const body = await authRes.json()
  assert.equal(body.success, true)
  assert.ok(Array.isArray(body.auditLogs))
  assert.ok(typeof body.total === 'number')
  assert.equal(body.retentionDays, 90)
})

test('GET /api/moderation/audit-logs/stats: returns storage volume and retention health', async () => {
  const statsRes = await fetch(`http://localhost:${apiPort}/api/moderation/audit-logs/stats`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(statsRes.status, 200)
  const body = await statsRes.json()
  assert.equal(body.success, true)
  assert.ok(body.stats)
  assert.equal(body.stats.retentionDays, 90)
  assert.ok(['OPTIMAL', 'WARNING', 'CAPACITY_REACHED'].includes(body.stats.storageStatus))
})

test('POST /api/moderation/audit-logs/purge: executes retention purge and removes expired records', async () => {
  const purgeRes = await fetch(`http://localhost:${apiPort}/api/moderation/audit-logs/purge`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({}),
  })
  assert.equal(purgeRes.status, 200)
  const body = await purgeRes.json()
  assert.equal(body.success, true)
  assert.ok(typeof body.purgedCount === 'number')
  assert.equal(body.retentionDays, 90)
})

