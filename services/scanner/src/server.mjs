import { createServer } from 'node:http'
import { scanUrl } from './scanner.mjs'

const PORT = process.env.PORT || 8789
const MAX_BODY_BYTES = 10000
// Optional shared secret between this scanner and the main API. Left unset,
// the endpoint stays open (matches its current behavior, so local
// development is not blocked by a missing secret); set the same value in
// both services' environments to require it. This is a defense-in-depth
// measure against this service being reachable by something other than the
// main API, not a replacement for keeping it off a public network.
const SHARED_SECRET = process.env.SCANNER_SHARED_SECRET || ''

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(body))
}

const server = createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    return send(res, 200, { status: 'ok' })
  }

  if (req.method !== 'POST' || req.url !== '/scan') {
    return send(res, 404, { error: 'Not found' })
  }

  if (SHARED_SECRET && req.headers['x-scanner-secret'] !== SHARED_SECRET) {
    return send(res, 401, { error: 'Unauthorized' })
  }

  let raw = ''
  let bytes = 0
  for await (const chunk of req) {
    bytes += chunk.length
    if (bytes > MAX_BODY_BYTES) {
      return send(res, 413, { error: 'Payload Too Large' })
    }
    raw += chunk
  }

  let body
  try {
    body = JSON.parse(raw)
  } catch {
    return send(res, 400, { error: 'Invalid JSON' })
  }

  if (!body.url || typeof body.url !== 'string') {
    return send(res, 400, { error: 'Missing or invalid URL' })
  }

  try {
    const result = await scanUrl(body.url)
    return send(res, 200, result)
  } catch (error) {
    console.error(`Scanner error for ${body.url}:`, error)
    return send(res, 500, { error: error.message || 'Internal Scanner Error' })
  }
})

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Scanner service listening on port ${PORT}`)
})
