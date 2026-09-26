import { existsSync, readFileSync } from 'node:fs'

function loadEnvFile(path) {
  if (!existsSync(path)) return
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const match = trimmed.match(/^([A-Z0-9_]+)=(.*)$/)
    if (match && !Object.hasOwn(process.env, match[1])) process.env[match[1]] = match[2].trim().replace(/^['"]|['"]$/g, '')
  }
}

// Load unified root .env (and local .env fallback if present)
loadEnvFile(new URL('../../../../.env', import.meta.url))
loadEnvFile(new URL('../../.env', import.meta.url))


function positiveInteger(value, fallback) {
  const parsed = Number(value)
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback
}

export const PORT = positiveInteger(process.env.PORT, 8787)
export const MAX_TEXT = 10_000
export const MAX_BODY_BYTES = 15_000
export const RATE_LIMIT_WINDOW_MS = positiveInteger(process.env.RATE_LIMIT_WINDOW_MS, 60_000)
export const RATE_LIMIT_MAX = positiveInteger(process.env.RATE_LIMIT_MAX, 60)
export const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:5173'
export const SUPABASE_URL = process.env.SUPABASE_URL || ''
export const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || ''
export const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || ''
export const GOOGLE_SAFE_BROWSING_API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY || ''
export const GEMINI_API_KEY = process.env.GEMINI_API_KEY || ''


