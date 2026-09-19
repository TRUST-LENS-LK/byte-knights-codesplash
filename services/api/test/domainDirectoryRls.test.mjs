import test from 'node:test'
import assert from 'node:assert/strict'
import { SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY } from '../src/config/env.mjs'

// These tests hit the real shared Supabase project, because Row Level
// Security is enforced by Postgres itself and cannot be meaningfully faked
// with a local mock server. They are skipped automatically when the
// credentials are not present, for example on a machine or CI run that has
// not set up services/api/.env, so this file never breaks a build that has
// no Supabase access. Run `npm run test --workspace services/api` with a
// configured .env (see .env.example) to actually exercise them.
const configured = Boolean(SUPABASE_URL && SUPABASE_ANON_KEY && SUPABASE_SERVICE_ROLE_KEY)

// A domain that will never collide with a real seeded organization, used only
// to prove write access, then always deleted again in a finally block so the
// shared directory is never left with test data.
const TEST_DOMAIN = 'rls-test-fixture.invalid'

function headersFor(key) {
  return { apikey: key, Authorization: `Bearer ${key}`, 'content-type': 'application/json' }
}

async function cleanupTestRow() {
  await fetch(`${SUPABASE_URL}/rest/v1/approved_organizations?official_domain=eq.${TEST_DOMAIN}`, {
    method: 'DELETE',
    headers: headersFor(SUPABASE_SERVICE_ROLE_KEY),
  }).catch(() => {})
}

test('anon key can read active organizations from the directory', { skip: !configured }, async () => {
  const response = await fetch(
    `${SUPABASE_URL}/rest/v1/approved_organizations?select=official_domain,active&official_domain=eq.boc.lk`,
    { headers: headersFor(SUPABASE_ANON_KEY) },
  )
  assert.equal(response.ok, true)
  const rows = await response.json()
  assert.equal(rows.length, 1)
  assert.equal(rows[0].active, true)
})

test('anon key cannot insert a new organization into the directory', { skip: !configured }, async () => {
  try {
    const response = await fetch(`${SUPABASE_URL}/rest/v1/approved_organizations`, {
      method: 'POST',
      headers: { ...headersFor(SUPABASE_ANON_KEY), Prefer: 'return=representation' },
      body: JSON.stringify({ name: 'RLS Test Org', official_domain: TEST_DOMAIN }),
    })
    // Supabase's RLS violation surfaces either as a non-2xx status or an
    // empty result set, depending on the policy shape, so check both.
    if (response.ok) {
      const rows = await response.json()
      assert.equal(rows.length, 0, 'anon insert should not have created a visible row')
    } else {
      assert.equal(response.ok, false)
    }
  } finally {
    await cleanupTestRow()
  }
})

test('anon key cannot update an existing organization in the directory', { skip: !configured }, async () => {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/approved_organizations?official_domain=eq.boc.lk`, {
    method: 'PATCH',
    headers: { ...headersFor(SUPABASE_ANON_KEY), Prefer: 'return=representation' },
    body: JSON.stringify({ category: 'Tampered by RLS test' }),
  })
  if (response.ok) {
    const rows = await response.json()
    assert.equal(rows.length, 0, 'anon update should not have affected any row')
  } else {
    assert.equal(response.ok, false)
  }
})

test('service role key can write to and delete from the directory, bypassing RLS', { skip: !configured }, async () => {
  try {
    const insertResponse = await fetch(`${SUPABASE_URL}/rest/v1/approved_organizations`, {
      method: 'POST',
      headers: { ...headersFor(SUPABASE_SERVICE_ROLE_KEY), Prefer: 'return=representation' },
      body: JSON.stringify({ name: 'RLS Test Org', official_domain: TEST_DOMAIN }),
    })
    assert.equal(insertResponse.ok, true)
    const inserted = await insertResponse.json()
    assert.equal(inserted.length, 1)
    assert.equal(inserted[0].official_domain, TEST_DOMAIN)
  } finally {
    await cleanupTestRow()
  }
})
