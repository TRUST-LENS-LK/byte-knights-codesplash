import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'

const port = 18787
let child

function waitForStartup(processChild, port, label = 'API') {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} did not start`)), 5000)
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
  child = spawn(process.execPath, ['src/server.mjs'], { cwd: new URL('..', import.meta.url), env: { ...process.env, PORT: String(port), SUPABASE_URL: '', SUPABASE_SERVICE_ROLE_KEY: '' }, stdio: ['ignore', 'pipe', 'pipe'] })
  await waitForStartup(child, port)
})

test.after(() => child?.kill())

test('health endpoint returns service status and request ID', async () => {
  const response = await fetch(`http://localhost:${port}/health`)
  const body = await response.json()
  assert.equal(response.status, 200)
  assert.equal(body.service, 'trustlens-api')
  assert.match(body.requestId, /^[0-9a-f-]{36}$/)
  assert.equal(response.headers.get('x-request-id'), body.requestId)
  assert.equal(response.headers.get('cache-control'), 'no-store')
  assert.equal(response.headers.get('permissions-policy'), 'camera=(), microphone=(), geolocation=()')
})

test('invalid submission is rejected', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'invalid', text: 'hello' }) })
  const body = await response.json()
  assert.equal(response.status, 400)
  assert.equal(body.code, 'INVALID_SUBMISSION')
})

test('unsupported language hints are rejected', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'message', languageHint: 'xx', text: 'hello' }) })
  const body = await response.json()
  assert.equal(response.status, 400)
  assert.equal(body.code, 'INVALID_SUBMISSION')
  assert.equal(body.message, 'languageHint is not supported.')
})

test('malformed JSON is rejected with a traceable error', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"type":"message"' })
  const body = await response.json()
  assert.equal(response.status, 400)
  assert.equal(body.code, 'INVALID_JSON')
  assert.match(body.requestId, /^[0-9a-f-]{36}$/)
})

test('non-JSON requests are rejected', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: '{}' })
  const body = await response.json()
  assert.equal(response.status, 415)
  assert.equal(body.code, 'UNSUPPORTED_MEDIA_TYPE')
  assert.match(body.requestId, /^[0-9a-f-]{36}$/)
})

test('requests over the byte limit are rejected before parsing', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json', 'content-length': '16000' }, body: '{}'.padEnd(16000, 'x') })
  const body = await response.json()
  assert.equal(response.status, 413)
  assert.equal(body.code, 'PAYLOAD_TOO_LARGE')
})

test('high-risk analysis does not persist without consent', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'message', text: 'Pay Rs. 5000 today and send your OTP.', retentionConsent: false }) })
  const body = await response.json()
  assert.equal(response.status, 200)
  assert.equal(body.decision.riskBand, 'HIGH')
  assert.equal(body.decision.recommendation, 'STOP_AND_AVOID')
  assert.equal(body.submissionId, undefined)
  assert.equal(response.headers.get('ratelimit-limit'), '60')
  assert.match(response.headers.get('ratelimit-remaining'), /^\d+$/)
})

test('repeated entities are returned only once', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'message', text: 'Visit https://example.com twice: https://example.com', retentionConsent: false }) })
  const body = await response.json()
  assert.equal(response.status, 200)
  assert.deepEqual(body.entities.filter((entity) => entity.type === 'url').map((entity) => entity.value), ['https://example.com'])
})

test('rate limiting returns 429 after the configured request budget', async () => {
  const limitedPort = 18788
  const limitedChild = spawn(process.execPath, ['src/server.mjs'], { cwd: new URL('..', import.meta.url), env: { ...process.env, PORT: String(limitedPort), RATE_LIMIT_MAX: '2', RATE_LIMIT_WINDOW_MS: '60000', SUPABASE_URL: '', SUPABASE_SERVICE_ROLE_KEY: '' }, stdio: ['ignore', 'pipe', 'pipe'] })
  await waitForStartup(limitedChild, limitedPort, 'Rate-limited API')
  try {
    const options = { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'message', text: 'hello', retentionConsent: false }) }
    await fetch(`http://localhost:${limitedPort}/api/analyze`, options)
    await fetch(`http://localhost:${limitedPort}/api/analyze`, options)
    const response = await fetch(`http://localhost:${limitedPort}/api/analyze`, options)
    const body = await response.json()
    assert.equal(response.status, 429)
    assert.equal(body.code, 'RATE_LIMITED')
    assert.equal(response.headers.get('ratelimit-remaining'), '0')
    assert.match(response.headers.get('retry-after'), /^\d+$/)
  } finally {
    limitedChild.kill()
  }
})

test('consented analysis persists through the server-only Supabase client', async () => {
  const supabasePort = 18789
  const apiPort = 18790
  const requests = []
  const supabase = createServer(async (req, res) => {
    let raw = ''
    for await (const chunk of req) raw += chunk
    requests.push({ method: req.method, url: req.url, headers: req.headers, body: raw ? JSON.parse(raw) : null })
    res.writeHead(201, { 'content-type': 'application/json' })
    res.end(req.method === 'POST' && req.url === '/rest/v1/submissions' ? JSON.stringify([{ id: 'submission-test-id' }]) : '[]')
  })
  await new Promise((resolve) => supabase.listen(supabasePort, '127.0.0.1', resolve))
  const consentedChild = spawn(process.execPath, ['src/server.mjs'], { cwd: new URL('..', import.meta.url), env: { ...process.env, PORT: String(apiPort), SUPABASE_URL: `http://127.0.0.1:${supabasePort}`, SUPABASE_SERVICE_ROLE_KEY: 'test-service-key', RATE_LIMIT_MAX: '60' }, stdio: ['ignore', 'pipe', 'pipe'] })
  await waitForStartup(consentedChild, apiPort, 'Consented API')
  try {
    const response = await fetch(`http://localhost:${apiPort}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'message', text: 'Pay Rs. 5000 today and send your OTP.', languageHint: 'en', retentionConsent: true }) })
    const body = await response.json()
    assert.equal(response.status, 200)
    assert.equal(body.submissionId, 'submission-test-id')
    assert.deepEqual(requests.map((request) => request.url), ['/rest/v1/submissions', '/rest/v1/extracted_entities', '/rest/v1/findings'])
    assert.equal(requests[0].headers.apikey, 'test-service-key')
    assert.equal(requests[0].body.retention_consent, true)
    assert.equal(requests[0].body.raw_text, 'Pay Rs. 5000 today and send your OTP.')
  } finally {
    consentedChild.kill()
    await new Promise((resolve) => supabase.close(resolve))
  }
})
