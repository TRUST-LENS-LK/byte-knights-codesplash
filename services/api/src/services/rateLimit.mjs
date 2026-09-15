import { RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS } from '../config/env.mjs'

const rateLimitStore = new Map()

export function consumeRateLimit(req) {
  const now = Date.now()
  const key = req.socket.remoteAddress || 'unknown'
  if (rateLimitStore.size > 1000) {
    for (const [storedKey, storedEntry] of rateLimitStore) {
      if (now - storedEntry.startedAt >= RATE_LIMIT_WINDOW_MS) rateLimitStore.delete(storedKey)
    }
  }
  const current = rateLimitStore.get(key)
  const entry = !current || now - current.startedAt >= RATE_LIMIT_WINDOW_MS ? { startedAt: now, count: 0 } : current
  entry.count += 1
  rateLimitStore.set(key, entry)
  const resetAt = entry.startedAt + RATE_LIMIT_WINDOW_MS
  return { allowed: entry.count <= RATE_LIMIT_MAX, limit: RATE_LIMIT_MAX, remaining: Math.max(0, RATE_LIMIT_MAX - entry.count), resetAt, retryAfter: Math.max(1, Math.ceil((resetAt - now) / 1000)) }
}
