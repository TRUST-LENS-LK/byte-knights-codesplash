import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'

// Mirrors the mock-Supabase pattern already used in api.test.mjs: a tiny local
// HTTP server stands in for Supabase's REST API, so this test is deterministic
// and never touches the real shared project.
function mockSupabaseReturning(rows) {
  return createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify(rows))
  })
}

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

const VIRTUSA_RECORD = {
  id: 1,
  name: 'Virtusa',
  official_domain: 'virtusa.com',
  category: 'Employer',
  source_url: 'https://www.virtusa.com',
  reviewer: 'Isuru Adikaram',
  verified_at: '2026-09-19T00:00:00Z',
  next_review_date: '2026-12-18',
  status: 'ACTIVE',
  active: true,
}

async function withServer(rows, run) {
  const supabasePort = 18900 + Math.floor(Math.random() * 500)
  const apiPort = 18400 + Math.floor(Math.random() * 500)
  const supabase = mockSupabaseReturning(rows)
  await new Promise((resolve) => supabase.listen(supabasePort, '127.0.0.1', resolve))
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: { ...process.env, PORT: String(apiPort), SUPABASE_URL: `http://127.0.0.1:${supabasePort}`, SUPABASE_SERVICE_ROLE_KEY: 'test-service-key' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  await waitForStartup(child, apiPort, 'Domain mismatch API')
  try {
    await run(apiPort)
  } finally {
    child.kill()
    await new Promise((resolve) => supabase.close(resolve))
  }
}

test('a claimed organization linking to an unrelated domain produces a critical domain_mismatch override', async () => {
  await withServer([VIRTUSA_RECORD], async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/analyze`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        type: 'message',
        text: 'Congratulations! You have been selected for a remote job at Virtusa Pvt Ltd. Please pay Rs. 5000 registration fee today at https://virtusa-careers-login.com to confirm your position.',
        retentionConsent: false,
      }),
    })
    const body = await response.json()
    assert.equal(response.status, 200)
    assert.equal(body.decision.riskBand, 'HIGH')
    assert.equal(body.decision.recommendation, 'STOP_AND_AVOID')
    assert.equal(body.decision.findings.some((f) => f.canonicalSignal === 'domain_mismatch'), true)
    assert.equal(body.decision.overridesApplied?.includes('domain_mismatch_override'), true)
  })
})

test('a claimed organization linking to its own real domain does not produce a mismatch, and is not duplicated', async () => {
  await withServer([VIRTUSA_RECORD], async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/analyze`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        type: 'message',
        text: 'Virtusa Pvt Ltd is hiring! Apply now at https://virtusa.com/careers',
        retentionConsent: false,
      }),
    })
    const body = await response.json()
    assert.equal(response.status, 200)
    // Confirm the organization entity actually extracted, so this test is
    // exercising the MATCHED code path and not passing for the wrong reason.
    assert.equal(body.entities.some((e) => e.type === 'organization'), true)
    assert.equal(body.decision.findings.some((f) => f.canonicalSignal === 'domain_mismatch'), false)
    const approvedDomainFindings = body.decision.findings.filter((f) => f.canonicalSignal === 'approved_domain')
    assert.equal(approvedDomainFindings.length, 1, 'approved_domain should be reported once, not duplicated by the mismatch check')
  })
})

test('an organization not in the directory produces no domain finding at all (unknown is silent)', async () => {
  await withServer([VIRTUSA_RECORD], async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/analyze`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        type: 'message',
        text: 'Greetings from Totally Random Startup Company. Visit https://random-startup.example for details.',
        retentionConsent: false,
      }),
    })
    const body = await response.json()
    assert.equal(response.status, 200)
    assert.equal(body.decision.findings.some((f) => f.canonicalSignal === 'domain_mismatch'), false)
    assert.equal(body.decision.findings.some((f) => f.canonicalSignal === 'approved_domain'), false)
  })
})

test('a stale directory entry is surfaced as a limitation, not treated as a mismatch or a match', async () => {
  await withServer([{ ...VIRTUSA_RECORD, status: 'STALE' }], async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/analyze`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        type: 'message',
        text: 'Virtusa Pvt Ltd is hiring! Apply now at https://virtusa.com/careers',
        retentionConsent: false,
      }),
    })
    const body = await response.json()
    assert.equal(response.status, 200)
    assert.equal(body.entities.some((e) => e.type === 'organization'), true)
    assert.equal(body.decision.findings.some((f) => f.canonicalSignal === 'domain_mismatch'), false)
    assert.equal(body.decision.limitations.some((limitation) => limitation.includes('due for re-review')), true)
  })
})

test('a dedicated URL submission (type: url, no text) is accepted and checked against the directory', async () => {
  await withServer([VIRTUSA_RECORD], async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/analyze`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'url', url: 'https://virtusa.com/careers', retentionConsent: false }),
    })
    const body = await response.json()
    assert.equal(response.status, 200)
    assert.equal(body.inputType, 'url')
    assert.equal(body.decision.findings.some((f) => f.canonicalSignal === 'approved_domain'), true)
  })
})

test('a dedicated URL submission with neither text nor url is rejected', async () => {
  await withServer([VIRTUSA_RECORD], async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/analyze`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'url', retentionConsent: false }),
    })
    const body = await response.json()
    assert.equal(response.status, 400)
    assert.equal(body.code, 'INVALID_SUBMISSION')
  })
})
