import { SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } from '../src/config/env.mjs'

const email = process.argv[2]
const password = process.argv[3]

if (!email || !password) {
  console.log('Usage: node scripts/login_moderator.mjs <email> <password>')
  console.log('Example: node scripts/login_moderator.mjs moderator@trustlens.lk MyPassword123!')
  process.exit(1)
}

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Error: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be configured in .env')
  process.exit(1)
}

async function login() {
  console.log(`Connecting to Supabase Auth (${new URL(SUPABASE_URL).host})...`)
  
  try {
    const response = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
      method: 'POST',
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    })

    const data = await response.json()

    if (!response.ok) {
      console.error('\n❌ Login Failed:', data.error_description || data.msg || data.message || response.statusText)
      process.exit(1)
    }

    console.log('\n✅ Login Successful!')
    console.log('User ID:', data.user.id)
    console.log('User Email:', data.user.email)
    console.log('Role:', data.user.app_metadata?.role || data.user.user_metadata?.role || 'default (no role in metadata)')
    console.log('\n--- YOUR SUPABASE JWT ACCESS TOKEN ---')
    console.log(data.access_token)
    console.log('--------------------------------------')
    console.log('\nTo test in Swagger UI (http://localhost:8787/docs):')
    console.log('1. Click "Authorize"')
    console.log('2. Under "BearerAuth (http, Bearer)", paste the access token above')
    console.log('3. Click "Authorize", then test GET /api/moderation/queue')
  } catch (error) {
    console.error('Network error during login:', error.message)
  }
}

login()
