import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { validateScannerUrl } from '../src/services/urlSafety.mjs'

const port = 18787
let child

test('scanner URL validation blocks unsafe targets', () => {
  assert.equal(validateScannerUrl('javascript:alert(1)').allowed, false)
  assert.equal(validateScannerUrl('http://localhost:8787').allowed, false)
  assert.equal(validateScannerUrl('http://127.0.0.1/health').allowed, false)
  assert.equal(validateScannerUrl('http://192.168.1.10/admin').allowed, false)
  assert.equal(validateScannerUrl('https://example.com/path').allowed, true)
})

test('scanner preview validates without fetching a URL', async () => {
  const safe = await fetch(`http://localhost:${port}/api/scanner/preview`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'https://example.com/login' }) })
  const safeBody = await safe.json()
  assert.equal(safe.status, 200)
  assert.equal(safeBody.safeToFetch, true)
  const unsafe = await fetch(`http://localhost:${port}/api/scanner/preview`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'http://127.0.0.1/admin' }) })
  const unsafeBody = await unsafe.json()
  assert.equal(unsafe.status, 400)
  assert.equal(unsafeBody.code, 'UNSAFE_URL')
  assert.equal(unsafeBody.safeToFetch, false)
})

test('scanner preview rejects missing URLs', async () => {
  const response = await fetch(`http://localhost:${port}/api/scanner/preview`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: '   ' }) })
  const body = await response.json()
  assert.equal(response.status, 400)
  assert.equal(body.code, 'INVALID_SUBMISSION')
})

test('analysis remains available when approved-domain lookup fails', async () => {
  const supabasePort = 18793
  const apiPort = 18794
  const supabase = createServer((req, res) => {
    res.writeHead(503, { 'content-type': 'application/json' })
    res.end('{}')
  })
  await new Promise((resolve) => supabase.listen(supabasePort, '127.0.0.1', resolve))
  const lookupChild = spawn(process.execPath, ['src/server.mjs'], { cwd: new URL('..', import.meta.url), env: { ...process.env, PORT: String(apiPort), SUPABASE_URL: `http://127.0.0.1:${supabasePort}`, SUPABASE_SERVICE_ROLE_KEY: 'test-service-key' }, stdio: ['ignore', 'pipe', 'pipe'] })
  await waitForStartup(lookupChild, apiPort, 'Lookup API')
  try {
    const response = await fetch(`http://localhost:${apiPort}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'url', text: 'Visit https://example.com', retentionConsent: false }) })
    const body = await response.json()
    assert.equal(response.status, 200)
    assert.equal(body.decision.limitations.includes('Approved-domain verification was unavailable for this request.'), true)
  } finally {
    lookupChild.kill()
    await new Promise((resolve) => supabase.close(resolve))
  }
})

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

test('invalid reports are rejected', async () => {
  const response = await fetch(`http://localhost:${port}/api/reports`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ reportType: 'unknown', text: 'hello' }) })
  const body = await response.json()
  assert.equal(response.status, 400)
  assert.equal(body.code, 'INVALID_SUBMISSION')
})

test('reports clearly indicate unavailable storage without Supabase', async () => {
  const response = await fetch(`http://localhost:${port}/api/reports`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ reportType: 'suspicious', text: 'Suspicious message', reportedDomain: 'Example.COM', notes: 'Please review' }) })
  const body = await response.json()
  assert.equal(response.status, 503)
  assert.equal(body.code, 'REPORTING_UNAVAILABLE')
})

test('consented reports persist a hash and pending status', async () => {
  const supabasePort = 18791
  const apiPort = 18792
  const requests = []
  const supabase = createServer(async (req, res) => {
    let raw = ''
    for await (const chunk of req) raw += chunk
    requests.push({ method: req.method, url: req.url, headers: req.headers, body: raw ? JSON.parse(raw) : null })
    res.writeHead(201, { 'content-type': 'application/json' })
    res.end(JSON.stringify([{ id: 'report-test-id' }]))
  })
  await new Promise((resolve) => supabase.listen(supabasePort, '127.0.0.1', resolve))
  const reportChild = spawn(process.execPath, ['src/server.mjs'], { cwd: new URL('..', import.meta.url), env: { ...process.env, PORT: String(apiPort), SUPABASE_URL: `http://127.0.0.1:${supabasePort}`, SUPABASE_SERVICE_ROLE_KEY: 'test-service-key' }, stdio: ['ignore', 'pipe', 'pipe'] })
  await waitForStartup(reportChild, apiPort, 'Report API')
  try {
    const response = await fetch(`http://localhost:${apiPort}/api/reports`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ reportType: 'suspicious', text: 'Please send money.', reportedDomain: 'Example.COM', notes: 'Review this.' }) })
    const body = await response.json()
    assert.equal(response.status, 201)
    assert.equal(body.reportId, 'report-test-id')
    assert.equal(body.status, 'PENDING')
    assert.equal(requests[0].url, '/rest/v1/user_reports')
    assert.equal(requests[0].headers.apikey, 'test-service-key')
    assert.equal(requests[0].body.report_type, 'suspicious')
    assert.equal(requests[0].body.reported_domain, 'example.com')
    assert.equal(requests[0].body.status, 'PENDING')
    assert.match(requests[0].body.content_sha256, /^[a-f0-9]{64}$/)
  } finally {
    reportChild.kill()
    await new Promise((resolve) => supabase.close(resolve))
  }
})

test('unsupported language hints are rejected', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'message', languageHint: 'xx', text: 'hello' }) })
  const body = await response.json()
  assert.equal(response.status, 400)
  assert.equal(body.code, 'INVALID_SUBMISSION')
  assert.equal(body.message, 'languageHint is not supported.')
})

test('invalid retention consent values are rejected', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'message', text: 'hello', retentionConsent: 'true' }) })
  const body = await response.json()
  assert.equal(response.status, 400)
  assert.equal(body.code, 'INVALID_SUBMISSION')
  assert.equal(body.message, 'retentionConsent must be a boolean.')
})

test('empty or whitespace-only text is rejected', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'message', text: '   ' }) })
  const body = await response.json()
  assert.equal(response.status, 400)
  assert.equal(body.code, 'INVALID_SUBMISSION')
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

test('Sinhala text is accepted and high-risk Sinhala signals are detected', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'message', text: 'ඔබට රැකියාවක් ලැබී ඇත. අදම ගාස්තු ගෙවන්න සහ OTP එවන්න.', languageHint: 'si', retentionConsent: false }) })
  const body = await response.json()
  assert.equal(response.status, 200)
  assert.equal(body.decision.riskBand, 'HIGH')
  assert.equal(body.decision.recommendation, 'STOP_AND_AVOID')
  assert.equal(body.decision.findings.some((finding) => finding.canonicalSignal === 'advance_payment'), true)
  assert.equal(body.decision.findings.some((finding) => finding.canonicalSignal === 'credential_request'), true)
})

test('Sinhala Unicode survives consented persistence', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'message', text: 'මෙය සිංහල පරීක්ෂණ පණිවිඩයකි.', languageHint: 'si', retentionConsent: false }) })
  const body = await response.json()
  assert.equal(response.status, 200)
  assert.equal(body.inputType, 'message')
  assert.equal(body.submissionId, undefined)
})

test('Singlish scam signals are detected', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'message', text: 'Job ekak labuna. Ada pay the fee and OTP eka ewanna.', languageHint: 'singlish', retentionConsent: false }) })
  const body = await response.json()
  assert.equal(response.status, 200)
  assert.equal(body.decision.riskBand, 'HIGH')
  assert.equal(body.decision.recommendation, 'STOP_AND_AVOID')
  assert.deepEqual(body.decision.findings.map((finding) => finding.canonicalSignal).sort(), ['advance_payment', 'credential_request', 'job_offer', 'urgency'])
})

test('repeated entities are returned only once', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'message', text: 'Visit https://example.com twice: https://example.com', retentionConsent: false }) })
  const body = await response.json()
  assert.equal(response.status, 200)
  assert.deepEqual(body.entities.filter((entity) => entity.type === 'url').map((entity) => entity.value), ['https://example.com'])
})

test('URL entities include a normalized domain', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'url', text: 'Visit https://Phishing.Example.com/login.', retentionConsent: false }) })
  const body = await response.json()
  assert.equal(response.status, 200)
  assert.equal(body.entities.find((entity) => entity.type === 'domain')?.normalizedValue, 'phishing.example.com')
})

test('explicit URL submissions preserve their input type', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'url', text: 'example dot com', retentionConsent: false }) })
  const body = await response.json()
  assert.equal(response.status, 200)
  assert.equal(body.inputType, 'url')
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
    if (req.method === 'GET' && req.url.startsWith('/rest/v1/approved_organizations')) return res.end(JSON.stringify([{ name: 'Example Authority', official_domain: 'example.com', category: 'Public service', source_url: 'https://example.com' }]))
    res.end(req.method === 'POST' && req.url === '/rest/v1/submissions' ? JSON.stringify([{ id: 'submission-test-id' }]) : '[]')
  })
  await new Promise((resolve) => supabase.listen(supabasePort, '127.0.0.1', resolve))
  const consentedChild = spawn(process.execPath, ['src/server.mjs'], { cwd: new URL('..', import.meta.url), env: { ...process.env, PORT: String(apiPort), SUPABASE_URL: `http://127.0.0.1:${supabasePort}`, SUPABASE_SERVICE_ROLE_KEY: 'test-service-key', RATE_LIMIT_MAX: '60' }, stdio: ['ignore', 'pipe', 'pipe'] })
  await waitForStartup(consentedChild, apiPort, 'Consented API')
  try {
    const response = await fetch(`http://localhost:${apiPort}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'message', text: 'Visit https://example.com, pay Rs. 5000 today and send your OTP.', languageHint: 'en', retentionConsent: true }) })
    const body = await response.json()
    assert.equal(response.status, 200)
    assert.equal(body.submissionId, 'submission-test-id')
    assert.equal(body.decision.findings.some((finding) => finding.canonicalSignal === 'approved_domain'), true)
    assert.deepEqual(requests.map((request) => request.url), ['/rest/v1/approved_organizations?official_domain=in.%28example.com%29&active=eq.true&select=name%2Cofficial_domain%2Ccategory%2Csource_url', '/rest/v1/submissions', '/rest/v1/extracted_entities', '/rest/v1/findings'])
    assert.equal(requests[0].headers.apikey, 'test-service-key')
    assert.equal(requests[1].body.retention_consent, true)
    assert.equal(requests[1].body.raw_text, 'Visit https://example.com, pay Rs. 5000 today and send your OTP.')
  } finally {
    consentedChild.kill()
    await new Promise((resolve) => supabase.close(resolve))
  }
})
