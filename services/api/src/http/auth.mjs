import { MODERATOR_SECRET, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } from '../config/env.mjs'

export async function authorizeModerator(req) {
  const secretHeader = req.headers['x-moderator-key']
  if (secretHeader && secretHeader === MODERATOR_SECRET) {
    return { authorized: true, actorRole: 'moderator' }
  }

  const authHeader = req.headers['authorization']
  if (!authHeader) {
    return { authorized: false, error: 'Authorization header or x-moderator-key is required.' }
  }

  const match = authHeader.match(/^Bearer\s+(.*)$/i)
  if (!match) {
    return { authorized: false, error: 'Authorization format must be Bearer <token>.' }
  }

  const token = match[1].trim()
  if (token === MODERATOR_SECRET) {
    return { authorized: true, actorRole: 'moderator' }
  }

  // If Supabase URL is available, verify token via Supabase Auth
  if (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY) {
    try {
      const response = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
        headers: {
          apikey: SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${token}`,
        },
        signal: AbortSignal.timeout(5000),
      })


      if (response.ok) {
        const user = await response.json()
        const role = user?.app_metadata?.role || user?.user_metadata?.role || 'moderator'
        return { authorized: true, actorRole: role, userId: user?.id }
      }
    } catch {
      // Network or timeout failure
    }
  }

  return { authorized: false, error: 'Invalid or expired moderator credentials.' }
}
