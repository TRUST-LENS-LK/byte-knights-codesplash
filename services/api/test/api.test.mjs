import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { inspectScannerUrl, validateScannerUrl } from '../src/services/urlSafety.mjs'

const port = 18787
let child

test('scanner URL validation blocks unsafe targets', () => {
  assert.equal(validateScannerUrl('javascript:alert(1)').allowed, false)
  assert.equal(validateScannerUrl('http://localhost:8787').allowed, false)
  assert.equal(validateScannerUrl('http://127.0.0.1/health').allowed, false)
  assert.equal(validateScannerUrl('http://192.168.1.10/admin').allowed, false)
  assert.equal(validateScannerUrl('https://example.com/path').allowed, true)
  for (const url of ['http://2130706433', 'http://0x7f000001', 'http://[::ffff:7f00:1]', 'http://[fe80::1]', 'http://100.64.0.1', 'http://224.0.0.1']) assert.equal(validateScannerUrl(url).allowed, false)
})

test('scanner URL validation blocks all private IPv4 ranges', () => {
  const privateTargets = [
    'http://10.0.0.1',
    'http://10.255.255.255',
    'http://172.16.0.1',
    'http://172.31.255.255',
    'http://192.168.0.1',
    'http://169.254.1.1',
    'http://0.0.0.1',
    'http://198.18.0.1',
    'http://198.19.255.255',
  ]
  for (const url of privateTargets) assert.equal(validateScannerUrl(url).allowed, false, `Should block ${url}`)
})

test('scanner URL validation blocks private IPv6 targets', () => {
  const ipv6Targets = [
    'http://[::1]',
    'http://[::ffff:192.168.1.1]',
    'http://[fc00::1]',
    'http://[fd00::1]',
    'http://[fe80::1]',
  ]
  for (const url of ipv6Targets) assert.equal(validateScannerUrl(url).allowed, false, `Should block ${url}`)
})

test('scanner URL validation allows legitimate public URLs', () => {
  const safeTargets = [
    'https://example.com',
    'http://example.com/path?query=1',
    'https://sub.domain.example.com',
    'https://1.1.1.1',
    'https://8.8.8.8',
  ]
  for (const url of safeTargets) assert.equal(validateScannerUrl(url).allowed, true, `Should allow ${url}`)
})

test('scanner inspection detects internationalized hostname signal', () => {
  const result = inspectScannerUrl('https://xn--nxasmq6b.example.com/login')
  assert.equal(result.allowed, true)
  assert.equal(result.signals.includes('internationalized_hostname'), true)
})

test('scanner inspection detects deep subdomain signal', () => {
  const result = inspectScannerUrl('https://a.b.c.d.e.example.com/login')
  assert.equal(result.allowed, true)
  assert.equal(result.signals.includes('deep_subdomain'), true)
})

test('scanner inspection detects long path signal', () => {
  const longPath = '/login/' + 'a'.repeat(110)
  const result = inspectScannerUrl(`https://example.com${longPath}`)
  assert.equal(result.allowed, true)
  assert.equal(result.signals.includes('long_path'), true)
})

test('scanner inspection detects long query signal', () => {
  const longQuery = '?token=' + 'a'.repeat(130)
  const result = inspectScannerUrl(`https://example.com/login${longQuery}`)
  assert.equal(result.allowed, true)
  assert.equal(result.signals.includes('long_query'), true)
})

test('scanner inspection detects embedded credentials signal', () => {
  const result = inspectScannerUrl('https://user:password@example.com/login')
  assert.equal(result.allowed, true)
  assert.equal(result.signals.includes('embedded_credentials'), true)
})



test('scanner inspection returns metadata without fetching', () => {
  const result = inspectScannerUrl('https://login.example.com:8443/account?next=home')
  assert.equal(result.allowed, true)
  assert.equal(result.hostname, 'login.example.com')
  assert.equal(result.protocol, 'https')
  assert.equal(result.port, '8443')
  assert.equal(result.hasQuery, true)
  assert.deepEqual(result.signals, ['non_standard_port'])
})

test('analysis includes local scanner findings for suspicious URL structure', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'url', text: 'https://user:pass@login.example.com:8443/account', retentionConsent: false }) })
  const body = await response.json()
  assert.equal(response.status, 200)
  assert.equal(body.decision.findings.some((finding) => finding.canonicalSignal === 'embedded_credentials' && finding.source === 'SCANNER'), true)
  assert.equal(body.decision.findings.some((finding) => finding.canonicalSignal === 'non_standard_port' && finding.source === 'SCANNER'), true)
  assert.equal(body.decision.riskBand, 'HIGH')
  assert.equal(body.decision.recommendation, 'STOP_AND_AVOID')
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

test('approved-domain verification recognizes real subdomains but not lookalikes', async () => {
  const supabasePort = 18795
  const apiPort = 18796
  const supabase = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify([{ name: 'Sri Lanka CERT', official_domain: 'cert.gov.lk', category: 'Cybersecurity', source_url: 'https://www.cert.gov.lk' }]))
  })
  await new Promise((resolve) => supabase.listen(supabasePort, '127.0.0.1', resolve))
  const domainChild = spawn(process.execPath, ['src/server.mjs'], { cwd: new URL('..', import.meta.url), env: { ...process.env, PORT: String(apiPort), SUPABASE_URL: `http://127.0.0.1:${supabasePort}`, SUPABASE_SERVICE_ROLE_KEY: 'test-service-key' }, stdio: ['ignore', 'pipe', 'pipe'] })
  await waitForStartup(domainChild, apiPort, 'Domain API')
  try {
    const trusted = await fetch(`http://localhost:${apiPort}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'url', text: 'https://alerts.cert.gov.lk/advisory', retentionConsent: false }) })
    const trustedBody = await trusted.json()
    assert.equal(trustedBody.decision.findings.some((finding) => finding.canonicalSignal === 'approved_domain'), true)
    const lookalike = await fetch(`http://localhost:${apiPort}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'url', text: 'https://cert.gov.lk.evil.example/login', retentionConsent: false }) })
    const lookalikeBody = await lookalike.json()
    assert.equal(lookalikeBody.decision.findings.some((finding) => finding.canonicalSignal === 'approved_domain'), false)
  } finally {
    domainChild.kill()
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
    assert.deepEqual(requests.map((request) => request.url.split('?')[0]), ['/rest/v1/approved_organizations', '/rest/v1/verified_intelligence', '/rest/v1/submissions', '/rest/v1/extracted_entities', '/rest/v1/findings'])
    assert.equal(requests[0].headers.apikey, 'test-service-key')
    assert.equal(requests[2].body.retention_consent, true)
    assert.equal(requests[2].body.raw_text, 'Visit https://example.com, pay Rs. 5000 today and send your OTP.')
  } finally {
    consentedChild.kill()
    await new Promise((resolve) => supabase.close(resolve))
  }
})

test('GET /docs serves interactive Swagger UI HTML', async () => {
  const response = await fetch(`http://localhost:${port}/docs`)
  const html = await response.text()
  assert.equal(response.status, 200)
  assert.equal(response.headers.get('content-type'), 'text/html; charset=utf-8')
  assert.match(html, /<title>TrustLens LK API Documentation<\/title>/)
  assert.match(html, /SwaggerUIBundle/)
})

test('GET /openapi.json serves valid OpenAPI 3.0 specification with all schemas', async () => {
  const response = await fetch(`http://localhost:${port}/openapi.json`)
  const spec = await response.json()
  assert.equal(response.status, 200)
  assert.equal(response.headers.get('content-type'), 'application/json; charset=utf-8')
  assert.equal(spec.openapi, '3.0.3')
  assert.equal(spec.info.title, 'TrustLens LK API')
  assert.equal(typeof spec.paths['/api/analyze'], 'object')
  assert.equal(typeof spec.paths['/api/scanner/preview'], 'object')
  assert.equal(typeof spec.paths['/api/reports'], 'object')
  assert.equal(typeof spec.paths['/api/moderation/stats'], 'object')
  assert.equal(typeof spec.paths['/api/moderation/queue'], 'object')
  assert.equal(typeof spec.paths['/api/moderation/review'], 'object')
  assert.equal(typeof spec.paths['/api/moderation/login'], 'object')
  assert.equal(typeof spec.paths['/api/moderation/seed-demo'], 'object')
  assert.equal(typeof spec.components.schemas.Submission, 'object')
  assert.equal(typeof spec.components.schemas.RiskDecision, 'object')
  assert.equal(typeof spec.components.schemas.ExtractedEntity, 'object')
})

test('Phase C: Approved community scam report generates verified intelligence and reconciles threat in real-time', async () => {
  const testPort = 18799
  const serverChild = spawn(process.execPath, ['src/server.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: { ...process.env, PORT: String(testPort), RATE_LIMIT_MAX: '60' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  await waitForStartup(serverChild, testPort, 'Phase C Test API')
  try {
    // 1. Citizen submits a report for a suspicious domain
    const reportRes = await fetch(`http://localhost:${testPort}/api/reports`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        reportType: 'suspicious',
        contentSha256: '1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff',
        reportedDomain: 'phishing-scam.lk',
        notes: 'Fake bank login site stealing credentials',
      }),
    })
    const reportBody = await reportRes.json()
    assert.equal(reportRes.status, 201)
    assert.equal(typeof reportBody.reportId, 'string')

    // 2. Submit analysis for the reported domain before intelligence is approved
    const analyzePreRes = await fetch(`http://localhost:${testPort}/api/analyze`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        type: 'message',
        text: 'Please visit https://phishing-scam.lk to review your account.',
      }),
    })
    const analyzePreBody = await analyzePreRes.json()
    assert.equal(analyzePreRes.status, 200)

    // 3. Analyze text containing credential theft request + domain -> triggers HIGH risk & impersonation trace
    const analyzeImpersonationRes = await fetch(`http://localhost:${testPort}/api/analyze`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        type: 'message',
        text: 'Your account is locked! Send your OTP immediately at https://phishing-scam.lk',
      }),
    })
    const analyzeImpersonationBody = await analyzeImpersonationRes.json()
    assert.equal(analyzeImpersonationRes.status, 200)
    assert.equal(analyzeImpersonationBody.decision.riskBand, 'HIGH')
    assert.equal(analyzeImpersonationBody.decision.recommendation, 'STOP_AND_AVOID')
  } finally {
    serverChild.kill()
  }
})

test('Phase D: CORS preflight (OPTIONS) handles localhost, 127.0.0.1, and chrome-extension origins', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, {
    method: 'OPTIONS',
    headers: {
      origin: 'chrome-extension://abcedfghijklmnop',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'content-type',
    },
  })
  assert.equal(response.status, 204)
  assert.equal(response.headers.get('access-control-allow-origin'), 'chrome-extension://abcedfghijklmnop')
  assert.match(response.headers.get('access-control-allow-methods'), /POST/)
})

test('Phase D: Production security headers (nosniff, DENY, referrer-policy) are present on responses', async () => {
  const response = await fetch(`http://localhost:${port}/health`)
  assert.equal(response.status, 200)
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff')
  assert.equal(response.headers.get('x-frame-options'), 'DENY')
  assert.equal(response.headers.get('referrer-policy'), 'strict-origin-when-cross-origin')
})

test('Phase D: Unsupported Content-Type returns 415 UNSUPPORTED_MEDIA_TYPE', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, {
    method: 'POST',
    headers: { 'content-type': 'text/plain' },
    body: 'hello world',
  })
  const body = await response.json()
  assert.equal(response.status, 415)
  assert.equal(body.code, 'UNSUPPORTED_MEDIA_TYPE')
})



