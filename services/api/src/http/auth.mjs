import { SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } from '../config/env.mjs'

export async function authorizeModerator(req) {
  const authHeader = req.headers['authorization']
  if (!authHeader) {
    return { authorized: false, error: 'Authorization header is required (Bearer <supabase_token>).' }
  }

  const match = authHeader.match(/^Bearer\s+(.*)$/i)
  if (!match) {
    return { authorized: false, error: 'Authorization format must be Bearer <token>.' }
  }

  const token = match[1].trim()

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return { authorized: false, error: 'Supabase authentication service is not configured.' }
  }

  try {
    const response = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${token}`,
      },
      signal: AbortSignal.timeout(5000),
    })

    if (!response.ok) {
      return { authorized: false, error: 'Invalid or expired moderator session.' }
    }

    const user = await response.json()
    const role = user?.app_metadata?.role || user?.user_metadata?.role

    if (role !== 'moderator' && role !== 'admin') {
      return { authorized: false, error: 'Forbidden: account does not have moderator privileges.' }
    }

    return { authorized: true, actorRole: role, userId: user.id }
  } catch (error) {
    return { authorized: false, error: 'Authentication service temporarily unavailable.' }
  }
}
