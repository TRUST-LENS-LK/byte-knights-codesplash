import { CORS_ORIGIN } from '../config/env.mjs'

export function send(res, status, body, requestId) {
  const requestOrigin = res.req?.headers?.origin || ''

  // Dynamic CORS: Allow localhost, 127.0.0.1, and chrome-extension origins during development.
  // In production, strictly enforce CORS_ORIGIN from environment variables.
  const isLocalDev = !requestOrigin || requestOrigin.startsWith('http://localhost:') || requestOrigin.startsWith('http://127.0.0.1:') || requestOrigin.startsWith('chrome-extension://')
  const allowedOrigin = isLocalDev ? (requestOrigin || '*') : CORS_ORIGIN

  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'access-control-allow-origin': allowedOrigin,
    'access-control-allow-methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
    'access-control-allow-headers': 'content-type, authorization, x-request-id',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    'referrer-policy': 'strict-origin-when-cross-origin',
    ...(requestId ? { 'x-request-id': requestId } : {}),
  })
  res.end(JSON.stringify(body))
}

