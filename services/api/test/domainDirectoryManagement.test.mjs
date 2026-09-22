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
  const supabasePort = 19700 + Math.floor(Math.random() * 300)
  const apiPort = 19300 + Math.floor(Math.random() * 300)
  const directory = new Map([['1', { id: 1, name: 'Bank of Ceylon', official_domain: 'boc.lk', category: 'Banking', status: 'ACTIVE', active: true, reviewer: null }]])
  let nextId = 2

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

    if (req.method === 'POST' && req.url.startsWith('/rest/v1/approved_organizations')) {
      const data = JSON.parse(raw)
      const row = { id: nextId++, active: true, status: 'ACTIVE', ...data }
      directory.set(String(row.id), row)
      res.writeHead(201, { 'content-type': 'application/json' })
      return res.end(JSON.stringify([row]))
    }

    if (req.method === 'PATCH' && req.url.startsWith('/rest/v1/approved_organizations')) {
      const match = req.url.match(/id=eq\.(\d+)/)
      const id = match?.[1]
      const existing = directory.get(id)
      if (!existing) {
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify([]))
      }
      const updated = { ...existing, ...JSON.parse(raw) }
      directory.set(id, updated)
      res.writeHead(200, { 'content-type': 'application/json' })
      return res.end(JSON.stringify([updated]))
    }

    if (req.method === 'GET' && req.url.startsWith('/rest/v1/approved_organizations')) {
      res.writeHead(200, { 'content-type': 'application/json' })
      return res.end(JSON.stringify([...directory.values()]))
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
  await waitForStartup(child, apiPort, 'Domain management API')
  try {
    await run(apiPort, directory)
  } finally {
    child.kill()
    await new Promise((resolve) => supabase.close(resolve))
  }
}

test('GET /api/moderation/domains requires a moderator token', async () => {
  await withServer(async (apiPort) => {
    const noAuth = await fetch(`http://localhost:${apiPort}/api/moderation/domains`)
    assert.equal(noAuth.status, 401)

    const wrongRole = await fetch(`http://localhost:${apiPort}/api/moderation/domains`, {
      headers: { Authorization: `Bearer ${regularUserToken}` },
    })
    assert.equal(wrongRole.status, 401)

    const authorized = await fetch(`http://localhost:${apiPort}/api/moderation/domains`, {
      headers: { Authorization: `Bearer ${validModeratorToken}` },
    })
    assert.equal(authorized.status, 200)
    const body = await authorized.json()
    assert.equal(body.entries.length, 1)
  })
})

test('POST /api/moderation/domains creates a new entry as the acting moderator', async () => {
  await withServer(async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/moderation/domains`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${validModeratorToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Sampath Bank', officialDomain: 'sampath.lk', category: 'Banking' }),
    })
    assert.equal(response.status, 201)
    const body = await response.json()
    assert.equal(body.entry.name, 'Sampath Bank')
    assert.equal(body.entry.officialDomain, 'sampath.lk')
    assert.equal(body.entry.reviewer, 'moderator@trustlens.lk')
    assert.equal(body.entry.status, 'ACTIVE')
  })
})

test('POST /api/moderation/domains rejects a regular (non-moderator) user', async () => {
  await withServer(async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/moderation/domains`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${regularUserToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Fake Entry', officialDomain: 'fake.lk' }),
    })
    assert.equal(response.status, 401)
  })
})

test('POST /api/moderation/domains validates required fields', async () => {
  await withServer(async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/moderation/domains`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${validModeratorToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Missing Domain' }),
    })
    assert.equal(response.status, 400)
    const body = await response.json()
    assert.equal(body.code, 'INVALID_SUBMISSION')
  })
})

test('PATCH /api/moderation/domains/:id retires an entry and stamps the reviewer', async () => {
  await withServer(async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/moderation/domains/1`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${validModeratorToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ status: 'RETIRED', reviewNotes: 'No longer accurate.' }),
    })
    assert.equal(response.status, 200)
    const body = await response.json()
    assert.equal(body.updated.status, 'RETIRED')
    assert.equal(body.updated.reviewer, 'moderator@trustlens.lk')
  })
})

test('PATCH /api/moderation/domains/:id rejects an invalid status value', async () => {
  await withServer(async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/moderation/domains/1`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${validModeratorToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ status: 'NOT_A_REAL_STATUS' }),
    })
    assert.equal(response.status, 400)
  })
})

test('PATCH /api/moderation/domains/:id returns 404 for a nonexistent entry', async () => {
  await withServer(async (apiPort) => {
    const response = await fetch(`http://localhost:${apiPort}/api/moderation/domains/9999`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${validModeratorToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ status: 'RETIRED' }),
    })
    assert.equal(response.status, 404)
  })
})
