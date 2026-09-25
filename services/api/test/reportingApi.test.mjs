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
const mockIntel = new Map()
const mockAuditLogs = []

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

    if (req.method === 'GET' && req.url.startsWith('/rest/v1/approved_organizations')) {
      const orgs = [
        {
          id: 1,
          name: 'Sri Lanka Police',
          official_domain: 'police.lk',
          category: 'Government / Law Enforcement',
          active: true,
          status: 'ACTIVE',
        },
        {
          id: 2,
          name: 'Central Bank of Sri Lanka',
          official_domain: 'cbsl.gov.lk',
          category: 'Banking & Finance',
          active: true,
          status: 'ACTIVE',
        },
      ]
      res.writeHead(200, { 'content-type': 'application/json' })
      return res.end(JSON.stringify(orgs))
    }

    if (req.method === 'POST' && req.url.startsWith('/rest/v1/verified_intelligence')) {
      const data = JSON.parse(raw || '{}')
      mockIntel.set(data.id, data)
      res.writeHead(201, { 'content-type': 'application/json' })
      return res.end(JSON.stringify([data]))
    }

    if (req.method === 'GET' && req.url.startsWith('/rest/v1/verified_intelligence')) {
      const decodedUrl = decodeURIComponent(req.url)
      let items = Array.from(mockIntel.values())
      const idMatch = decodedUrl.match(/id=eq\.([a-f0-9-]+)/i)
      if (idMatch) {
        items = items.filter((i) => i.id === idMatch[1])
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify(items))
      }
      const indMatch = decodedUrl.match(/indicator_value=eq\.([^&]+)/)
      if (indMatch) {
        const decoded = indMatch[1].toLowerCase()
        items = items.filter((i) => (i.indicator_value || '').toLowerCase() === decoded)
      }
      const inMatch = decodedUrl.match(/indicator_value\.in\.\(([^)]+)\)/)
      if (inMatch) {
        const allowed = inMatch[1].split(',').map((s) => s.replace(/^"|"$/g, '').toLowerCase().trim())
        items = items.filter((i) => allowed.includes((i.indicator_value || '').toLowerCase()) || allowed.includes((i.defanged_value || '').toLowerCase()))
      }
      if (decodedUrl.includes('active=eq.true')) {
        items = items.filter((i) => i.active === true)
      } else if (decodedUrl.includes('active=eq.false')) {
        items = items.filter((i) => i.active === false)
      }
      items.sort((a, b) => {
        if (Boolean(a.active) !== Boolean(b.active)) return a.active ? -1 : 1
        return new Date(b.updated_at || b.created_at || 0).getTime() - new Date(a.updated_at || a.created_at || 0).getTime()
      })
      res.writeHead(200, { 'content-type': 'application/json' })
      return res.end(JSON.stringify(items))
    }

    if (req.method === 'PATCH' && req.url.startsWith('/rest/v1/verified_intelligence')) {
      const match = req.url.match(/id=eq\.([a-f0-9-]+)/i)
      if (match && mockIntel.has(match[1])) {
        const existing = mockIntel.get(match[1])
        const updates = JSON.parse(raw || '{}')
        const merged = { ...existing, ...updates }
        mockIntel.set(match[1], merged)
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify([merged]))
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      return res.end(JSON.stringify([{ status: 'ok' }]))
    }

    if (req.method === 'POST' && req.url.startsWith('/rest/v1/moderation_audit_logs')) {
      const data = JSON.parse(raw || '{}')
      mockAuditLogs.unshift(data)
      res.writeHead(201, { 'content-type': 'application/json' })
      return res.end(JSON.stringify([data]))
    }

    if (req.method === 'GET' && req.url.startsWith('/rest/v1/moderation_audit_logs')) {
      const decodedUrl = decodeURIComponent(req.url)
      let items = [...mockAuditLogs]
      const inMatch = decodedUrl.match(/target_indicator\.in\.\(([^)]+)\)/)
      if (inMatch) {
        const allowed = inMatch[1].split(',').map((s) => s.replace(/^"|"$/g, '').toLowerCase().trim())
        items = items.filter((l) => {
          const target = (l.target_indicator || l.raw_target_indicator || '').toLowerCase().trim()
          return allowed.includes(target)
        })
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      return res.end(JSON.stringify(items))
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

test('GET /api/moderation/queue: enriches reports with protected_entity metadata dynamically', async () => {
  // 1. Submit a report for official domain police.lk
  const submitRes = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      reportedDomain: 'police.lk',
      rawExcerpt: 'Suspicious sms claiming to be Sri Lanka police traffic fine',
    }),
  })
  assert.equal(submitRes.status, 201)

  // 2. Fetch moderation queue as moderator
  const queueRes = await fetch(`http://localhost:${apiPort}/api/moderation/queue`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(queueRes.status, 200)
  const queueBody = await queueRes.json()
  assert.equal(queueBody.success, true)

  const policeReport = queueBody.reports.find((r) => r.reported_domain === 'police.lk')
  assert.ok(policeReport, 'Report for police.lk should be in the queue')
  assert.ok(policeReport.protected_entity, 'police.lk should have protected_entity metadata')
  assert.equal(policeReport.protected_entity.isProtected, true)
  assert.equal(policeReport.protected_entity.type, 'OFFICIAL_NATIONAL')
  assert.equal(policeReport.protected_entity.name, 'Sri Lanka Police')
  assert.equal(policeReport.protected_entity.recommendedAction, 'REJECT')
})

test('POST /api/moderation/review: Circuit Breaker blocks approval of protected entities without override (HTTP 422)', async () => {
  // 1. Submit a report for global platform facebook.com
  const submitRes = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3',
      reportedDomain: 'facebook.com',
      rawExcerpt: 'Citizen reported seeing a scam advert on facebook',
    }),
  })
  assert.equal(submitRes.status, 201)
  const submitBody = await submitRes.json()
  const reportId = submitBody.report.id

  // 2. Try to APPROVE without overrideProtectedEntity -> HTTP 422 PROTECTED_ENTITY_OVERRIDE_REQUIRED
  const reviewRes = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({
      reportId,
      action: 'APPROVE',
      category: 'Phishing',
      notes: 'Trying to approve facebook.com without circuit breaker override',
    }),
  })

  assert.equal(reviewRes.status, 422)
  const reviewBody = await reviewRes.json()
  assert.equal(reviewBody.code, 'PROTECTED_ENTITY_OVERRIDE_REQUIRED')
  assert.ok(reviewBody.protectedEntity)
  assert.equal(reviewBody.protectedEntity.type, 'TOP_GLOBAL')
})

test('POST /api/moderation/review: Circuit Breaker permits approval when overrideProtectedEntity=true and incidentReason provided', async () => {
  // 1. Submit a report for cbsl.gov.lk (Central Bank)
  const submitRes = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: 'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4',
      reportedDomain: 'cbsl.gov.lk',
      rawExcerpt: 'Severe defacement or incident',
    }),
  })
  assert.equal(submitRes.status, 201)
  const submitBody = await submitRes.json()
  const reportId = submitBody.report.id

  // 2. APPROVE with overrideProtectedEntity: true and incidentReason
  const overrideRes = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({
      reportId,
      action: 'APPROVE',
      category: 'Compromised Infrastructure',
      notes: 'Confirmed by CERT emergency incident team',
      overrideProtectedEntity: true,
      incidentReason: 'CERT-INC-2026-999: Active DNS Hijack Incident',
    }),
  })

  assert.equal(overrideRes.status, 200)
  const overrideBody = await overrideRes.json()
  assert.equal(overrideBody.result.success, true)
  assert.equal(overrideBody.result.status, 'APPROVED')
})

test('GET /api/moderation/reports/:id/context: Blocks requests without token or with non-moderator token (HTTP 401)', async () => {
  // 1. Unauthenticated request
  const unauthRes = await fetch(`http://localhost:${apiPort}/api/moderation/reports/any-uuid/context`)
  assert.equal(unauthRes.status, 401)
  const unauthBody = await unauthRes.json()
  assert.equal(unauthBody.code, 'UNAUTHORIZED')

  // 2. Regular citizen token (non-moderator)
  const userRes = await fetch(`http://localhost:${apiPort}/api/moderation/reports/any-uuid/context`, {
    headers: { Authorization: `Bearer ${regularUserToken}` },
  })
  assert.equal(userRes.status, 401)
})

test('GET /api/moderation/reports/:id/context: Returns HTTP 404 for non-existent report ID', async () => {
  const missingRes = await fetch(`http://localhost:${apiPort}/api/moderation/reports/00000000-0000-0000-0000-000000000000/context`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(missingRes.status, 404)
  const missingBody = await missingRes.json()
  assert.equal(missingBody.code, 'NOT_FOUND')
})

test('GET /api/moderation/reports/:id/context: Delivers context radar for fresh report with no prior history', async () => {
  // 1. Submit a fresh report
  const submitRes = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a101',
      reportedDomain: 'brand-new-unknown-domain.top',
      rawExcerpt: 'Fresh scam target',
    }),
  })
  assert.equal(submitRes.status, 201)
  const { report } = await submitRes.json()

  // 2. Query intelligence context
  const ctxRes = await fetch(`http://localhost:${apiPort}/api/moderation/reports/${report.id}/context`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(ctxRes.status, 200)
  const ctxBody = await ctxRes.json()
  assert.equal(ctxBody.success, true)
  assert.equal(ctxBody.context.hasActiveIntel, false)
  assert.equal(ctxBody.context.isConflict, false)
  assert.equal(ctxBody.context.isCorroborating, false)
  assert.equal(ctxBody.context.priorDecisions.totalPriorEvents, 0)
})

test('GET /api/moderation/reports/:id/context: Surfaces past rejections for indicator', async () => {
  // 1. Submit a report for spammy-domain.xyz and REJECT it
  const submit1 = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a102',
      reportedDomain: 'spammy-domain.xyz',
      rawExcerpt: 'Fake alarm',
    }),
  })
  const { report: rep1 } = await submit1.json()

  const rejectRes = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({
      reportId: rep1.id,
      action: 'REJECT',
      notes: 'No malicious indicators detected. Citizen dispute.',
    }),
  })
  assert.equal(rejectRes.status, 200)

  // 2. Submit second report for the same domain
  const submit2 = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a103',
      reportedDomain: 'spammy-domain.xyz',
      rawExcerpt: 'Second report',
    }),
  })
  const { report: rep2 } = await submit2.json()

  // 3. Context query should show 1 prior rejection with notes
  const ctxRes = await fetch(`http://localhost:${apiPort}/api/moderation/reports/${rep2.id}/context`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(ctxRes.status, 200)
  const { context } = await ctxRes.json()
  assert.equal(context.priorDecisions.totalRejections, 1)
  assert.ok(context.priorDecisions.latestRejection)
  assert.equal(context.priorDecisions.latestRejection.notes, 'No malicious indicators detected. Citizen dispute.')
})

test('GET /api/moderation/reports/:id/context: Detects conflict when false alarm is submitted against confirmed threat', async () => {
  // 1. Submit and APPROVE a scam report for malicious-gateway.biz
  const submitScam = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: 'b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6b101',
      reportedDomain: 'malicious-gateway.biz',
      rawExcerpt: 'Fake gateway harvesting cards',
    }),
  })
  const { report: scamReport } = await submitScam.json()

  const approveScamRes = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({
      reportId: scamReport.id,
      action: 'APPROVE',
      category: 'Banking Phishing',
      confidence: 0.95,
      notes: 'Active credential theft site',
    }),
  })
  assert.equal(approveScamRes.status, 200)

  // 2. Submit a false_positive report for the same domain
  const submitFalseAlarm = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'false_positive',
      contentSha256: 'b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6b102',
      reportedDomain: 'malicious-gateway.biz',
      rawExcerpt: 'Dispute: this is legitimate',
    }),
  })
  const { report: falseAlarmReport } = await submitFalseAlarm.json()

  // 3. Inspect context: must report conflict!
  const ctxRes = await fetch(`http://localhost:${apiPort}/api/moderation/reports/${falseAlarmReport.id}/context`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(ctxRes.status, 200)
  const { context } = await ctxRes.json()
  assert.equal(context.hasActiveIntel, true)
  assert.equal(context.activeIntel.risk_level, 'CONFIRMED_SCAM')
  assert.equal(context.isConflict, true)
  assert.equal(context.conflictType, 'FALSE_ALARM_AGAINST_SCAM')
  assert.ok(context.conflictExplanation.includes('Active Intelligence already classifies this domain as a CONFIRMED SCAM'))
  assert.ok(context.revocationConsequence.includes('Approving this report will REVOKE'))
})

test('POST /api/moderation/review: Approving false alarm revokes threat indicator and reclassifies target as VERIFIED_SAFE', async () => {
  // 1. Submit false alarm on malicious-gateway.biz
  const submitFalseAlarm = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'false_positive',
      contentSha256: 'c1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6c101',
      reportedDomain: 'malicious-gateway.biz',
      rawExcerpt: 'Site clean audit complete',
    }),
  })
  const { report: falseAlarmReport } = await submitFalseAlarm.json()

  // 2. Moderator APPROVES the false alarm
  const approveRes = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({
      reportId: falseAlarmReport.id,
      action: 'APPROVE',
      category: 'False Alarm',
      confidence: 1.0,
      notes: 'Cleared after verified security patch',
    }),
  })
  assert.equal(approveRes.status, 200)

  // 3. Re-query context: active threat indicator must be superseded by VERIFIED_SAFE
  const ctxRes = await fetch(`http://localhost:${apiPort}/api/moderation/reports/${falseAlarmReport.id}/context`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(ctxRes.status, 200)
  const { context } = await ctxRes.json()
  assert.equal(context.activeIntel.risk_level, 'VERIFIED_SAFE')
  assert.equal(context.isConflict, false)
})

test('GET /api/moderation/reports/:id/context: Rejects empty report ID with HTTP 400', async () => {
  const badIdRes = await fetch(`http://localhost:${apiPort}/api/moderation/reports//context`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(badIdRes.status, 400)
  const body = await badIdRes.json()
  assert.equal(body.code, 'INVALID_ID')
})

test('GET /api/moderation/reports/:id/context: Detects reverse conflict (SCAM_AGAINST_SAFE) and revocation consequence', async () => {
  // 1. Submit and APPROVE a false_positive report for verified-clean-firm.lk (creating active VERIFIED_SAFE indicator)
  const fpRes = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'false_positive',
      contentSha256: 'd1d2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6d101',
      reportedDomain: 'verified-clean-firm.lk',
      rawExcerpt: 'Legitimate business domain dispute',
    }),
  })
  assert.equal(fpRes.status, 201)
  const { report: fpReport } = await fpRes.json()

  const approveFp = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({
      reportId: fpReport.id,
      action: 'APPROVE',
      category: 'False Alarm',
      confidence: 1.0,
      notes: 'Verified legitimate enterprise domain',
    }),
  })
  assert.equal(approveFp.status, 200)

  // 2. Submit a suspicious scam report against verified-clean-firm.lk
  const scamRes = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: 'd1d2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6d102',
      reportedDomain: 'verified-clean-firm.lk',
      rawExcerpt: 'Recent compromise detected hosting phishing kit',
    }),
  })
  assert.equal(scamRes.status, 201)
  const { report: scamReport } = await scamRes.json()

  // 3. Query context for the new suspicious report
  const ctxRes = await fetch(`http://localhost:${apiPort}/api/moderation/reports/${scamReport.id}/context`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(ctxRes.status, 200)
  const { context } = await ctxRes.json()
  assert.equal(context.hasActiveIntel, true)
  assert.equal(context.activeIntel.risk_level, 'VERIFIED_SAFE')
  assert.equal(context.isConflict, true)
  assert.equal(context.conflictType, 'SCAM_AGAINST_SAFE')
  assert.ok(context.conflictExplanation.includes('VERIFIED SAFE'))
  assert.ok(context.revocationConsequence.includes('REVOKE the VERIFIED_SAFE status and escalate the domain to CONFIRMED_SCAM'))
})

test('POST /api/moderation/review: Approving scam against safe indicator deactivates safe intel and records RECLASSIFY_INDICATOR audit log', async () => {
  // 1. Submit a suspicious scam report on verified-clean-firm.lk (which is currently active VERIFIED_SAFE)
  const scamRes = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: 'e1d2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6e101',
      reportedDomain: 'verified-clean-firm.lk',
      rawExcerpt: 'Phishing credential harvester detected on subpath',
    }),
  })
  assert.equal(scamRes.status, 201)
  const { report: scamReport } = await scamRes.json()

  // 2. Moderator overrides and approves the scam report
  const approveScam = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({
      reportId: scamReport.id,
      action: 'APPROVE',
      category: 'Credential Harvesting',
      confidence: 0.95,
      notes: 'Investigated: domain DNS was hijacked, now serving malicious malware',
    }),
  })
  assert.equal(approveScam.status, 200)

  // 3. Verify context now reflects CONFIRMED_SCAM
  const ctxRes = await fetch(`http://localhost:${apiPort}/api/moderation/reports/${scamReport.id}/context`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(ctxRes.status, 200)
  const { context } = await ctxRes.json()
  assert.equal(context.hasActiveIntel, true)
  assert.equal(context.activeIntel.risk_level, 'CONFIRMED_SCAM')
  assert.equal(context.isConflict, false)

  // 4. Verify audit log captures RECLASSIFY_INDICATOR
  const auditRes = await fetch(`http://localhost:${apiPort}/api/moderation/audit-logs`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(auditRes.status, 200)
  const auditBody = await auditRes.json()
  const reclassifyLog = auditBody.auditLogs.find((l) => l.action === 'RECLASSIFY_INDICATOR')
  assert.ok(reclassifyLog, 'RECLASSIFY_INDICATOR audit log must be recorded')
  assert.match(reclassifyLog.moderator_notes, /REVOKED & RECLASSIFIED/i)
})

test('GET /api/moderation/reports/:id/context: Projects corroboration report count and Bayesian confidence scaling for repeated threat report', async () => {
  // 1. Create and approve a scam report for repeat-scam-lanka.com with base confidence 0.85
  const rep1 = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: 'f1d2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6f101',
      reportedDomain: 'repeat-scam-lanka.com',
      rawExcerpt: 'Fake lottery winning message',
    }),
  })
  const { report: report1 } = await rep1.json()

  const approve1 = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({
      reportId: report1.id,
      action: 'APPROVE',
      category: 'Financial Scam',
      confidence: 0.85,
      notes: 'Initial confirmation of fake lottery lure',
    }),
  })
  assert.equal(approve1.status, 200)

  // 2. Submit second independent report for the same domain
  const rep2 = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: 'f1d2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6f102',
      reportedDomain: 'repeat-scam-lanka.com',
      rawExcerpt: 'Second citizen reporting lottery scam',
    }),
  })
  const { report: report2 } = await rep2.json()

  // 3. Inspect context: should show corroboration projection
  const ctxRes = await fetch(`http://localhost:${apiPort}/api/moderation/reports/${report2.id}/context`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(ctxRes.status, 200)
  const { context } = await ctxRes.json()
  assert.equal(context.hasActiveIntel, true)
  assert.equal(context.isCorroborating, true)
  assert.equal(context.isConflict, false)
  assert.equal(context.projectedCount, 2)
  assert.ok(context.projectedConfidence > 0.85, 'Projected confidence should be greater than base 0.85')
  assert.ok(context.corroborationSummary.includes('already verified as an active threat'))
})

test('POST /api/moderation/review: Approving corroborating threat updates existing intelligence with incremented report count and Bayesian confidence', async () => {
  // 1. Submit a 2nd report for repeat-scam-lanka.com
  const rep2 = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: 'f1d2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6f103',
      reportedDomain: 'repeat-scam-lanka.com',
      rawExcerpt: 'Third report corroborating lottery scam',
    }),
  })
  const { report: report2 } = await rep2.json()

  // 2. Moderator approves the corroborating report
  const approve2 = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({
      reportId: report2.id,
      action: 'APPROVE',
      category: 'Financial Scam',
      confidence: 0.90,
      notes: 'Corroborated by independent user evidence',
    }),
  })
  assert.equal(approve2.status, 200)

  // 3. Check updated active intelligence via context
  const ctxRes = await fetch(`http://localhost:${apiPort}/api/moderation/reports/${report2.id}/context`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(ctxRes.status, 200)
  const { context } = await ctxRes.json()
  assert.equal(context.hasActiveIntel, true)
  assert.equal(context.activeIntel.report_count, 2)
  assert.ok(context.activeIntel.confidence >= 0.90)
})

test('POST /api/moderation/review: Rejecting a conflicting dispute preserves existing threat intelligence intact and logs rejection', async () => {
  // 1. Submit and approve scam for malware-host-domain.net
  const scamRes = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: '11d2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f61101',
      reportedDomain: 'malware-host-domain.net',
      rawExcerpt: 'Malicious payload dropper',
    }),
  })
  const { report: scamReport } = await scamRes.json()

  const approveRes = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({
      reportId: scamReport.id,
      action: 'APPROVE',
      category: 'Malware Distribution',
      confidence: 0.95,
      notes: 'Confirmed dropper domain',
    }),
  })
  assert.equal(approveRes.status, 200)

  // 2. Someone files a false_positive dispute
  const disputeRes = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'false_positive',
      contentSha256: '11d2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f61102',
      reportedDomain: 'malware-host-domain.net',
      rawExcerpt: 'Unblock request from domain registrant',
    }),
  })
  const { report: disputeReport } = await disputeRes.json()

  // 3. Moderator reviews the dispute and REJECTS it
  const rejectRes = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({
      reportId: disputeReport.id,
      action: 'REJECT',
      notes: 'Dispute investigated and denied. Active ransomware payload still hosted.',
    }),
  })
  assert.equal(rejectRes.status, 200)
  const rejectBody = await rejectRes.json()
  assert.equal(rejectBody.result.status, 'REJECTED')

  // 4. Query context: CONFIRMED_SCAM must remain active, and rejection recorded
  const ctxRes = await fetch(`http://localhost:${apiPort}/api/moderation/reports/${disputeReport.id}/context`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(ctxRes.status, 200)
  const { context } = await ctxRes.json()
  assert.equal(context.hasActiveIntel, true)
  assert.equal(context.activeIntel.risk_level, 'CONFIRMED_SCAM')
  assert.equal(context.priorDecisions.totalRejections, 1)
  assert.equal(context.priorDecisions.totalApprovals, 1)
  assert.equal(context.priorDecisions.latestRejection.notes, 'Dispute investigated and denied. Active ransomware payload still hosted.')
})

test('GET /api/moderation/reports/:id/context: Resolves subdomain variants to parent domain active threat intelligence', async () => {
  // 1. Submit and approve threat on apex domain bank-phish-alert.lk
  const apexRes = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: '22d2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f62201',
      reportedDomain: 'bank-phish-alert.lk',
      rawExcerpt: 'Fake bank portal apex',
    }),
  })
  const { report: apexReport } = await apexRes.json()

  const approveApex = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({
      reportId: apexReport.id,
      action: 'APPROVE',
      category: 'Banking Phishing',
      confidence: 0.95,
      notes: 'Malicious domain targeted at bank users',
    }),
  })
  assert.equal(approveApex.status, 200)

  // 2. Submit report for a subdomain: online.secure.bank-phish-alert.lk
  const subRes = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: '22d2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f62202',
      reportedDomain: 'online.secure.bank-phish-alert.lk',
      rawExcerpt: 'Subdomain phishing lure',
    }),
  })
  const { report: subReport } = await subRes.json()

  // 3. Query context for the subdomain report: should link to apex intelligence
  const ctxRes = await fetch(`http://localhost:${apiPort}/api/moderation/reports/${subReport.id}/context`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(ctxRes.status, 200)
  const { context } = await ctxRes.json()
  assert.equal(context.hasActiveIntel, true)
  assert.equal(context.activeIntel.risk_level, 'CONFIRMED_SCAM')
  assert.equal(context.isCorroborating, true)
})

test('GET /api/moderation/reports/:id/context: Matches and tracks threat intelligence for pure contentSha256 hash without domain', async () => {
  const pureHash = '33d2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f63301'

  // 1. Submit text scam with no domain
  const sms1 = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: pureHash,
      notes: 'SMS claiming prize money, call 0770000000',
    }),
  })
  const { report: report1 } = await sms1.json()

  // 2. Approve with indicatorType content_hash
  const approveHash = await fetch(`http://localhost:${apiPort}/api/moderation/review`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${validModeratorToken}`,
    },
    body: JSON.stringify({
      reportId: report1.id,
      action: 'APPROVE',
      indicatorType: 'content_hash',
      category: 'SMS Scams',
      confidence: 0.90,
      notes: 'Confirmed prize scam SMS template',
    }),
  })
  assert.equal(approveHash.status, 200)

  // 3. Second report with the same hash
  const sms2 = await fetch(`http://localhost:${apiPort}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      reportType: 'suspicious',
      contentSha256: pureHash,
      notes: 'Another recipient of the same scam message',
    }),
  })
  const { report: report2 } = await sms2.json()

  // 4. Query context: should match by contentSha256
  const ctxRes = await fetch(`http://localhost:${apiPort}/api/moderation/reports/${report2.id}/context`, {
    headers: { Authorization: `Bearer ${validModeratorToken}` },
  })
  assert.equal(ctxRes.status, 200)
  const { context } = await ctxRes.json()
  assert.equal(context.hasActiveIntel, true)
  assert.equal(context.activeIntel.risk_level, 'CONFIRMED_SCAM')
  assert.equal(context.targetIndicator, pureHash)
  assert.equal(context.isCorroborating, true)
})




