import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'

const port = 18787
let child

test.before(async () => {
  child = spawn(process.execPath, ['src/server.mjs'], { cwd: new URL('..', import.meta.url), env: { ...process.env, PORT: String(port), SUPABASE_URL: '', SUPABASE_SERVICE_ROLE_KEY: '' }, stdio: ['ignore', 'pipe', 'pipe'] })
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('API did not start')), 5000)
    child.stdout.on('data', (chunk) => { if (chunk.toString().includes(`:${port}`)) { clearTimeout(timer); resolve() } })
    child.on('error', reject)
  })
})

test.after(() => child?.kill())

test('health endpoint returns service status and request ID', async () => {
  const response = await fetch(`http://localhost:${port}/health`)
  const body = await response.json()
  assert.equal(response.status, 200)
  assert.equal(body.service, 'trustlens-api')
  assert.match(body.requestId, /^[0-9a-f-]{36}$/)
  assert.equal(response.headers.get('x-request-id'), body.requestId)
})

test('invalid submission is rejected', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'invalid', text: 'hello' }) })
  const body = await response.json()
  assert.equal(response.status, 400)
  assert.equal(body.code, 'INVALID_SUBMISSION')
})

test('high-risk analysis does not persist without consent', async () => {
  const response = await fetch(`http://localhost:${port}/api/analyze`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'message', text: 'Pay Rs. 5000 today and send your OTP.', retentionConsent: false }) })
  const body = await response.json()
  assert.equal(response.status, 200)
  assert.equal(body.decision.riskBand, 'HIGH')
  assert.equal(body.decision.recommendation, 'STOP_AND_AVOID')
  assert.equal(body.submissionId, undefined)
})
