import { CORS_ORIGIN } from '../config/env.mjs'

export function send(res, status, body, requestId) {
  const requestOrigin = res.req?.headers?.origin || ''
  
  // Dynamic CORS: Allow any localhost origin during local development to prevent Vite port-switching errors.
  // In production, strictly enforce the CORS_ORIGIN from environment variables.
  const isLocalDev = requestOrigin.startsWith('http://localhost:')
  const allowedOrigin = isLocalDev ? requestOrigin : CORS_ORIGIN

  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'access-control-allow-origin': allowedOrigin, 'access-control-allow-methods': 'GET,POST,OPTIONS', 'access-control-allow-headers': 'content-type, authorization', 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'permissions-policy': 'camera=(), microphone=(), geolocation=()', 'referrer-policy': 'no-referrer', ...(requestId ? { 'x-request-id': requestId } : {}) })
  res.end(JSON.stringify(body))
}
