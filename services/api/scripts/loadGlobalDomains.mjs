#!/usr/bin/env node
// Populates Tier 3's L2 (packages/domain covers L1) with the full Tranco
// top-1M research-oriented domain ranking (tranco-list.eu). Self-contained:
// downloads the current list itself by default, so this can be re-run
// periodically (a weekly cadence is enough; Tranco's own methodology page
// notes the top domains rarely change from day to day) without needing a
// manually downloaded file each time.
//
// Usage:
//   node scripts/loadGlobalDomains.mjs                 fetch live, load all rows
//   node scripts/loadGlobalDomains.mjs --file path.csv  use a local CSV instead
//   node scripts/loadGlobalDomains.mjs --limit 1000     only load the first N rows (testing)

import { readFileSync, existsSync } from 'node:fs'
import AdmZip from 'adm-zip'

const TRANCO_ZIP_URL = 'https://tranco-list.eu/top-1m.csv.zip'
const BATCH_SIZE = 2000
const REQUEST_TIMEOUT_MS = 30_000

function loadEnv() {
  const envPath = new URL('../.env', import.meta.url)
  const env = {}
  if (existsSync(envPath)) {
    for (const line of readFileSync(envPath, 'utf8').split(/\r?\n/)) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith('#')) continue
      const match = trimmed.match(/^([A-Z0-9_]+)=(.*)$/)
      if (match) env[match[1]] = match[2].trim().replace(/^['"]|['"]$/g, '')
    }
  }
  return env
}

function parseArgs(argv) {
  const args = { file: null, limit: null }
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--file') args.file = argv[++i]
    if (argv[i] === '--limit') args.limit = Number(argv[++i])
  }
  return args
}

async function fetchTrancoCsv() {
  console.log(`Downloading Tranco list from ${TRANCO_ZIP_URL} ...`)
  const response = await fetch(TRANCO_ZIP_URL, { signal: AbortSignal.timeout(60_000) })
  if (!response.ok) throw new Error(`Tranco download failed: HTTP ${response.status}`)
  const buffer = Buffer.from(await response.arrayBuffer())
  const zip = new AdmZip(buffer)
  const entry = zip.getEntries().find((e) => e.entryName.endsWith('.csv'))
  if (!entry) throw new Error('No CSV file found inside the downloaded Tranco zip.')
  return entry.getData().toString('utf8')
}

function parseCsv(raw, limit) {
  const lines = raw.split(/\r?\n/).filter(Boolean)
  const rows = []
  for (const line of lines) {
    const [rankStr, domain] = line.split(',')
    const rank = Number(rankStr)
    if (!domain || !Number.isFinite(rank)) continue
    rows.push({ domain: domain.trim().toLowerCase(), rank, source: 'tranco' })
    if (limit && rows.length >= limit) break
  }
  return rows
}

async function upsertBatch(env, batch) {
  const response = await fetch(`${env.SUPABASE_URL}/rest/v1/global_trusted_domains?on_conflict=domain`, {
    method: 'POST',
    headers: {
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      'content-type': 'application/json',
      Prefer: 'resolution=merge-duplicates,return=minimal',
    },
    body: JSON.stringify(batch),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  })
  if (!response.ok) {
    const text = await response.text().catch(() => '')
    throw new Error(`Batch upsert failed: HTTP ${response.status} ${text.slice(0, 300)}`)
  }
}

async function main() {
  const env = loadEnv()
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set in services/api/.env')
    process.exit(1)
  }

  const args = parseArgs(process.argv.slice(2))
  const raw = args.file ? readFileSync(args.file, 'utf8') : await fetchTrancoCsv()
  const rows = parseCsv(raw, args.limit)
  console.log(`Parsed ${rows.length} domains. Uploading in batches of ${BATCH_SIZE}...`)

  let uploaded = 0
  let failedBatches = 0
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const batch = rows.slice(i, i + BATCH_SIZE)
    try {
      await upsertBatch(env, batch)
      uploaded += batch.length
    } catch (error) {
      // One bad batch should not abort the whole 1M-row run; log it and
      // keep going, then report the total failure count at the end.
      failedBatches += 1
      console.error(`Batch starting at row ${i} failed: ${error.message}`)
    }
    if ((i / BATCH_SIZE) % 20 === 0) {
      console.log(`Progress: ${uploaded}/${rows.length} rows uploaded (${failedBatches} failed batches so far)`)
    }
  }

  console.log(`Done. ${uploaded}/${rows.length} rows uploaded, ${failedBatches} batch failures.`)
  if (failedBatches > 0) process.exitCode = 1
}

main().catch((error) => {
  console.error('Load script failed:', error.message)
  process.exit(1)
})
