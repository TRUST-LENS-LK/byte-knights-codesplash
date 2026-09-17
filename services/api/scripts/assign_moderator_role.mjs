import { SUPABASE_SERVICE_ROLE_KEY, SUPABASE_URL } from '../src/config/env.mjs'

const email = process.argv[2]

if (!email) {
  console.log('Usage: node scripts/assign_moderator_role.mjs <email>')
  console.log('Example: node scripts/assign_moderator_role.mjs moderator@trustlens.lk')
  process.exit(1)
}

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Error: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be configured in .env')
  process.exit(1)
}

async function assignRole() {
  console.log(`Looking up user "${email}" in Supabase...`)

  try {
    // 1. Fetch users list
    const listRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users`, {
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      },
    })

    if (!listRes.ok) {
      console.error('Failed to list users:', listRes.statusText)
      return
    }

    const { users } = await listRes.json()
    const target = users.find((u) => u.email?.toLowerCase() === email.toLowerCase())

    if (!target) {
      console.error(`❌ User with email "${email}" was not found in Supabase!`)
      console.log('Available emails:', users.map((u) => u.email).join(', ') || 'No users yet')
      return
    }

    // 2. Update user metadata to add role: moderator
    const updateRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${target.id}`, {
      method: 'PUT',
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        user_metadata: { ...target.user_metadata, role: 'moderator' },
        app_metadata: { ...target.app_metadata, role: 'moderator' },
      }),
    })

    if (!updateRes.ok) {
      const err = await updateRes.text()
      console.error('❌ Failed to assign role:', err)
      return
    }

    console.log(`\n✅ Success! User "${email}" (ID: ${target.id}) is now assigned the "moderator" role!`)
  } catch (error) {
    console.error('Network error:', error.message)
  }
}

assignRole()
