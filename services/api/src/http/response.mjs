import { CORS_ORIGIN } from '../config/env.mjs'

export function send(res, status, body, requestId) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'access-control-allow-origin': CORS_ORIGIN, 'access-control-allow-methods': 'GET,POST,OPTIONS', 'access-control-allow-headers': 'content-type', 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'permissions-policy': 'camera=(), microphone=(), geolocation=()', 'referrer-policy': 'no-referrer', ...(requestId ? { 'x-request-id': requestId } : {}) })
  res.end(JSON.stringify(body))
}
