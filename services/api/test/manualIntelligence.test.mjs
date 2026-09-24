import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'

const validModeratorToken = 'valid-moderator-jwt-token-xyz'
const regularUserToken = 'regular-citizen-jwt-token-abc'

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

async function withServer(run) {
  const supabasePort = 19200 + Math.floor(Math.random() * 300)
  const apiPort = 19600 + Math.floor(Math.random() * 300)
  const intel = new Map()

  const supabase = createServer(async (req, res) => {
    let raw = ''
    for await (const chunk of req) raw += chunk

    if (req.url === '/auth/v1/user') {
      const auth = req.headers['authorization'] || ''
      if (auth === `Bearer ${validModeratorToken}`) {
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ id: 'mod-1', email: 'moderator@trustlens.lk', app_metadata: { role: 'moderator' } }))
      }
      if (auth === `Bearer ${regularUserToken}`) {
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ id: 'user-1', email: 'citizen@example.lk', app_metadata: { role: 'user' } }))
      }
      res.writeHead(401, { 'content-type': 'application/json' })
      return res.end(JSON.stringify({ error: 'invalid_token' }))
    }

    if (req.method === 'GET' && req.url.startsWith('/rest/v1/verified_intelligence')) {
      const valueMatch = req.url.match(/indicator_value=eq\.([^&]+)/)
      let items = [...intel.values()]
      if (valueMatch) {
        const decoded = decodeURIComponent(valueMatch[1])
        items = items.filter((item) => item.indicator_value === decoded)
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      return res.end(JSON.stringify(items))
    }

    if (req.method === 'POST' && req.url.startsWith('/rest/v1/verified_intelligence')) {
      const data = JSON.parse(raw)
      intel.set(data.id, data)
      res.writeHead(201, { 'content-type': 'application/json' })
      return res.end(JSON.stringify([data]))
    }

    if (req.method === 'POST' && req.url.startsWith('/rest/v1/moderation_audit_logs')) {
      res.writeHead(201, { 'content-type': 'application/json' })
      return res.end(JSON.stringify([JSON.parse(raw)]))
    }

    res.writeHead(404, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ message: 'not found in mock' }))
  })

  await new Promise((resolve) => supabase.listen(supabasePort, '127.0.0.1', resolve))
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: { ...process.env, PORT: String(apiPort), SUPABASE_URL: `http://127.0.0.1:${supabasePort}`, SUPABASE_SERVICE_ROLE_KEY: 'test-service-key' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  await waitForStartup(child, apiPort, 'Manual intelligence API')
  try {
    await run(apiPort, intel)
  } finally {
    child.kill()
    await new Promise((resolve) => supabase.close(resolve))
  }
}

test('POST /api/moderation/intelligence requires a moderator token', async () => {
  await withServer(async (apiPort) => {
    const noAuth = await fetch(`http://localhost:${apiPort}/api/moderation/intelligence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ indicatorValue: 'scam-example.lk' }),
    })
    assert.equal(noAuth.status, 401)

    const wrongRole = await fetch(`http://localhost:${apiPort}/api/moderation/intelligence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${regularUserToken}` },
      body: JSON.stringify({ indicatorValue: 'scam-example.lk' }),
    })
    assert.equal(wrongRole.status, 401)
  })
})

test('POST /api/moderation/intelligence validates indicatorValue and riskLevel', async () => {
  await withServer(async (apiPort) => {
    const missingValue = await fetch(`http://localhost:${apiPort}/api/moderation/intelligence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${validModeratorToken}` },
      body: JSON.stringify({}),
    })
    assert.equal(missingValue.status, 400)
    assert.equal((await missingValue.json()).code, 'INVALID_SUBMISSION')

    const badRiskLevel = await fetch(`http://localhost:${apiPort}/api/moderation/intelligence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${validModeratorToken}` },
      body: JSON.stringify({ indicatorValue: 'scam-example.lk', riskLevel: 'NOT_A_REAL_LEVEL' }),
    })
    assert.equal(badRiskLevel.status, 400)
    assert.equal((await badRiskLevel.json()).code, 'INVALID_SUBMISSION')
  })
})

test('POST /api/moderation/intelligence lets a moderator directly add a scam indicator, and rejects duplicates', async () => {
  await withServer(async (apiPort) => {
    const created = await fetch(`http://localhost:${apiPort}/api/moderation/intelligence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${validModeratorToken}` },
      body: JSON.stringify({ indicatorValue: 'ceb-billpay-scam.lk', category: 'Fake Utility Bill' }),
    })
    assert.equal(created.status, 201)
    const createdBody = await created.json()
    assert.equal(createdBody.success, true)
    assert.equal(createdBody.entry.indicator_value, 'ceb-billpay-scam.lk')
    assert.equal(createdBody.entry.risk_level, 'CONFIRMED_SCAM')
    assert.equal(createdBody.entry.category, 'Fake Utility Bill')
    assert.equal(createdBody.entry.active, true)
    assert.equal(createdBody.entry.source_report_id, null)

    const duplicate = await fetch(`http://localhost:${apiPort}/api/moderation/intelligence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${validModeratorToken}` },
      body: JSON.stringify({ indicatorValue: 'ceb-billpay-scam.lk' }),
    })
    assert.equal(duplicate.status, 409)
    assert.equal((await duplicate.json()).code, 'DUPLICATE_INDICATOR')
  })
})

test('POST /api/moderation/intelligence can also add a verified-safe indicator', async () => {
  await withServer(async (apiPort) => {
    const created = await fetch(`http://localhost:${apiPort}/api/moderation/intelligence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${validModeratorToken}` },
      body: JSON.stringify({ indicatorValue: 'genuinely-safe-example.lk', riskLevel: 'VERIFIED_SAFE' }),
    })
    assert.equal(created.status, 201)
    const createdBody = await created.json()
    assert.equal(createdBody.entry.risk_level, 'VERIFIED_SAFE')
  })
})

test('POST /api/moderation/intelligence defaults confidence to 1.0 and defangs the value', async () => {
  await withServer(async (apiPort) => {
    const created = await fetch(`http://localhost:${apiPort}/api/moderation/intelligence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${validModeratorToken}` },
      body: JSON.stringify({ indicatorValue: 'HTTPS://Fake-Lottery-Win.LK' }),
    })
    assert.equal(created.status, 201)
    const createdBody = await created.json()
    assert.equal(createdBody.entry.indicator_value, 'https://fake-lottery-win.lk')
    assert.equal(createdBody.entry.confidence, 1.0)
    assert.ok(createdBody.entry.defanged_value.includes('[.]'))
  })
})
