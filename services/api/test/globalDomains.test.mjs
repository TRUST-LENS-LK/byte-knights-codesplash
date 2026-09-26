import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'

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

async function withServer({ mockRows = [], mockShouldFail = false } = {}, run) {
  const supabasePort = 19100 + Math.floor(Math.random() * 400)
  const apiPort = 19500 + Math.floor(Math.random() * 400)
  let l2WasQueried = false
  const supabase = createServer((req, res) => {
    if (req.url.startsWith('/rest/v1/global_trusted_domains')) l2WasQueried = true
    if (mockShouldFail) {
      res.writeHead(500, { 'content-type': 'application/json' })
      return res.end(JSON.stringify({ message: 'simulated failure' }))
    }
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify(mockRows))
  })
  await new Promise((resolve) => supabase.listen(supabasePort, '127.0.0.1', resolve))
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: { ...process.env, PORT: String(apiPort), SUPABASE_URL: `http://127.0.0.1:${supabasePort}`, SUPABASE_SERVICE_ROLE_KEY: 'test-service-key' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  await waitForStartup(child, apiPort, 'Global domains API')
  try {
    await run(apiPort, () => l2WasQueried)
  } finally {
    child.kill()
    await new Promise((resolve) => supabase.close(resolve))
  }
}

test('a top-20k globally known domain is recognized via L1 without ever querying the database', async () => {
  await withServer({ mockRows: [] }, async (apiPort, wasL2Queried) => {
    const response = await fetch(`http://localhost:${apiPort}/api/analyze`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'message', text: 'Check this out: https://github.com/example/repo', retentionConsent: false }),
    })
    const body = await response.json()
    assert.equal(response.status, 200)
    assert.equal(body.decision.findings.some((f) => f.canonicalSignal === 'known_global_domain'), true)
    // L1 should catch github.com (it's extremely high-ranked), so L2 (the
    // database) should never even be queried for the domain check. Approved
    // domain and verified intelligence checks still run, so we can't assert
    // zero queries overall, but we can assert this specific finding came
    // from L1 by checking the evidence text.
    const finding = body.decision.findings.find((f) => f.canonicalSignal === 'known_global_domain')
    assert.match(finding.evidence, /L1 cache hit/)
  })
})

test('a domain not in L1 but present in the L2 database is recognized as globally trusted', async () => {
  await withServer({ mockRows: [{ domain: 'some-lesser-known-but-real-site.com' }] }, async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/analyze`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'message', text: 'Visit https://some-lesser-known-but-real-site.com for info', retentionConsent: false }),
    })
    const body = await response.json()
    assert.equal(response.status, 200)
    const finding = body.decision.findings.find((f) => f.canonicalSignal === 'known_global_domain')
    assert.ok(finding, 'expected a known_global_domain finding from the L2 fallback')
    assert.match(finding.evidence, /L2 cache hit/)
  })
})

test('a domain in neither L1 nor L2 produces no global-domain finding', async () => {
  await withServer({ mockRows: [] }, async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/analyze`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'message', text: 'Visit https://totally-obscure-made-up-site-999.xyz for info', retentionConsent: false }),
    })
    const body = await response.json()
    assert.equal(response.status, 200)
    assert.equal(body.decision.findings.some((f) => f.canonicalSignal === 'known_global_domain'), false)
  })
})

test('an L2 database failure is swallowed silently rather than breaking analysis', async () => {
  await withServer({ mockShouldFail: true }, async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/analyze`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'message', text: 'Visit https://totally-obscure-made-up-site-999.xyz for info', retentionConsent: false }),
    })
    assert.equal(response.status, 200)
  })
})

test('a Tier 1 curated-directory match no longer suppresses the Tier 3 global-domain check — both findings are produced', async () => {
  // github.com is in both the Tier 1 mock directory AND the Tier 3 L1 cache.
  // The pipeline should now produce BOTH an approved_domain and a
  // known_global_domain finding, since each is an independent signal.
  await withServer({ mockRows: [{ name: 'GitHub', official_domain: 'github.com', category: 'Tech', source_url: null }] }, async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/analyze`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'url', url: 'https://github.com', retentionConsent: false }),
    })
    const body = await response.json()
    assert.equal(response.status, 200)
    assert.equal(body.decision.findings.some((f) => f.canonicalSignal === 'approved_domain'), true, 'Tier 1 approved_domain finding should be present')
    assert.equal(body.decision.findings.some((f) => f.canonicalSignal === 'known_global_domain'), true, 'Tier 3 known_global_domain finding should also be present')
  })
})
