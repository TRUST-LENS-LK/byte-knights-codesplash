import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'

// These tests exercise only the HTTP layer (auth gate and body validation),
// never scanUrl() itself, by always sending a request that fails validation
// once past the auth check. That keeps this suite runnable without a real
// Chromium install in the test environment.

function waitForStartup(processChild, label = 'Scanner') {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} did not start`)), 5000)
    processChild.stdout.on('data', (chunk) => {
      if (chunk.toString().includes('listening')) {
        clearTimeout(timer)
        resolve()
      }
    })
    processChild.on('error', reject)
  })
}

async function withScanner(env, run) {
  const port = 18700 + Math.floor(Math.random() * 500)
  const child = spawn(process.execPath, ['src/server.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: { ...process.env, PORT: String(port), ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  await waitForStartup(child)
  try {
    await run(port)
  } finally {
    child.kill()
  }
}

test('with no shared secret configured, /scan is reachable without a header (unchanged behavior)', async () => {
  await withScanner({ SCANNER_SHARED_SECRET: '' }, async (port) => {
    const response = await fetch(`http://localhost:${port}/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    })
    // Passes the auth gate and fails on missing url instead, proving the
    // request was not rejected for lacking a secret header.
    assert.equal(response.status, 400)
    const body = await response.json()
    assert.match(body.error, /Missing or invalid URL/)
  })
})

test('with a shared secret configured, a request without the header is rejected', async () => {
  await withScanner({ SCANNER_SHARED_SECRET: 'test-secret' }, async (port) => {
    const response = await fetch(`http://localhost:${port}/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'https://example.com' }),
    })
    assert.equal(response.status, 401)
  })
})

test('with a shared secret configured, a request with the wrong header value is rejected', async () => {
  await withScanner({ SCANNER_SHARED_SECRET: 'test-secret' }, async (port) => {
    const response = await fetch(`http://localhost:${port}/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-scanner-secret': 'wrong-value' },
      body: JSON.stringify({ url: 'https://example.com' }),
    })
    assert.equal(response.status, 401)
  })
})

test('with a shared secret configured, a request with the correct header passes the auth gate', async () => {
  await withScanner({ SCANNER_SHARED_SECRET: 'test-secret' }, async (port) => {
    const response = await fetch(`http://localhost:${port}/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-scanner-secret': 'test-secret' },
      body: JSON.stringify({}),
    })
    // Passes auth, fails on missing url instead of 401, proving the correct
    // secret was accepted.
    assert.equal(response.status, 400)
    const body = await response.json()
    assert.match(body.error, /Missing or invalid URL/)
  })
})

test('health endpoint is exempt from the shared secret check', async () => {
  await withScanner({ SCANNER_SHARED_SECRET: 'test-secret' }, async (port) => {
    const response = await fetch(`http://localhost:${port}/health`)
    assert.equal(response.status, 200)
  })
})
