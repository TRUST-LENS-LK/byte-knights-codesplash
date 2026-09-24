import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'

// config/env.mjs computes SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY as
// module-level constants the first time it is imported in this process, so
// process.env must be set before persistence.mjs (which imports env.mjs
// statically) is imported for the first time, and one mock server is shared
// across both tests below rather than one per test.
const port = 18960 + Math.floor(Math.random() * 500)
const received = []
const mockSupabase = createServer((req, res) => {
  let raw = ''
  req.on('data', (chunk) => (raw += chunk))
  req.on('end', () => {
    received.push({ method: req.method, url: req.url, body: raw ? JSON.parse(raw) : null })
    const responseBody = req.method === 'DELETE' ? [{ id: 'old-1' }, { id: 'old-2' }] : [{ id: 'submission-1' }]
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify(responseBody))
  })
})

let persistIfConsented
let purgeExpiredSubmissions

test.before(async () => {
  await new Promise((resolve) => mockSupabase.listen(port, '127.0.0.1', resolve))
  process.env.SUPABASE_URL = `http://127.0.0.1:${port}`
  process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-service-key'
  ;({ persistIfConsented, purgeExpiredSubmissions } = await import('../src/services/persistence.mjs'))
})

test.after(() => mockSupabase.close())

test('persistIfConsented sets an expires_at roughly 90 days in the future', async () => {
  const decision = { riskBand: 'LOW', recommendation: 'PROCEED_CAUTIOUSLY', policyVersion: 'test-v1', findings: [] }
  await persistIfConsented({ type: 'message', text: 'hello', retentionConsent: true }, decision, [])

  const submissionInsert = received.find((call) => call.method === 'POST' && call.url === '/rest/v1/submissions')
  assert.ok(submissionInsert, 'expected a POST to /rest/v1/submissions')
  assert.ok(submissionInsert.body.expires_at, 'expected expires_at to be set')

  const expiresAt = new Date(submissionInsert.body.expires_at).getTime()
  const expectedRoughly = Date.now() + 90 * 24 * 60 * 60 * 1000
  // Allow a small tolerance for how long the test itself takes to run.
  assert.ok(Math.abs(expiresAt - expectedRoughly) < 60_000, 'expires_at should be about 90 days from now')
})

test('purgeExpiredSubmissions deletes with an expires_at "less than now" filter and reports the count removed', async () => {
  const now = new Date('2026-09-19T00:00:00Z')
  const deletedCount = await purgeExpiredSubmissions(now)

  assert.equal(deletedCount, 2)
  const deleteCall = received.find((call) => call.method === 'DELETE')
  assert.ok(deleteCall, 'expected a DELETE request')
  assert.ok(deleteCall.url.includes('expires_at=lt.2026-09-19'), `expected an expires_at lt filter, got ${deleteCall.url}`)
})
