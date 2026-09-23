import test from 'node:test'
import assert from 'node:assert/strict'
import {
  computeAuditHash,
  canonicalTimestamp,
  GENESIS_PREV_HASH,
  recordAuditLog,
  getModerationAuditLogs,
  verifyAuditChainIntegrity,
  purgeExpiredAuditLogs,
} from '../src/services/reportingService.mjs'

test('Audit Cryptographic Integrity & Tamper-Evidence Tests', async (t) => {
  await t.test('computeAuditHash produces deterministic SHA-256 digests', () => {
    const prev = '0000000000000000000000000000000000000000000000000000000000000000'
    const entry = {
      created_at: '2026-09-23T10:00:00.000Z',
      action: 'APPROVE',
      actor_email: 'mod@trustlens.lk',
      actor_role: 'moderator',
      target_indicator: 'hxxps://scam-bank[.]lk',
      threat_category: 'Banking Phishing',
      moderator_notes: 'Confirmed phishing portal',
      client_ip: '10.0.0.1',
    }
    const hash1 = computeAuditHash(prev, entry)
    const hash2 = computeAuditHash(prev, entry)
    assert.equal(hash1, hash2, 'Identical inputs must yield identical SHA-256 hashes')
    assert.equal(hash1.length, 64, 'SHA-256 hex string must be 64 characters long')

    // Tampering any character must alter the hash
    const tampered = { ...entry, moderator_notes: 'Tampered note' }
    const hashTampered = computeAuditHash(prev, tampered)
    assert.notEqual(hash1, hashTampered, 'Modified entry payload must change the hash')
  })

  await t.test('recordAuditLog chains records sequentially with prev_hash and entry_hash', async () => {
    const entry1 = await recordAuditLog({
      action: 'AUTH_LOGIN',
      actorEmail: 'admin@trustlens.lk',
      actorRole: 'admin',
      targetIndicator: 'auth.login',
      threatCategory: 'Authentication',
      moderatorNotes: 'Admin session started',
      clientIp: '192.168.1.50',
      userAgent: 'TestRunner/1.0',
    })

    assert.ok(entry1.entry_hash, 'Entry 1 must have an entry_hash')
    assert.ok(entry1.prev_hash, 'Entry 1 must have a prev_hash')

    const entry2 = await recordAuditLog({
      action: 'DOMAIN_CREATE',
      actorEmail: 'admin@trustlens.lk',
      actorRole: 'admin',
      targetIndicator: 'cbsl.gov.lk',
      threatCategory: 'Official Whitelist',
      moderatorNotes: 'Whitelisted Central Bank of Sri Lanka',
      clientIp: '192.168.1.50',
      userAgent: 'TestRunner/1.0',
    })

    assert.ok(entry2.entry_hash, 'Entry 2 must have an entry_hash')
    assert.equal(entry2.prev_hash, entry1.entry_hash, 'Entry 2 prev_hash must strictly point to Entry 1 entry_hash')
  })

  await t.test('verifyAuditChainIntegrity validates entire active audit chain', async () => {
    const verification = await verifyAuditChainIntegrity()
    assert.equal(verification.isValid, true, 'Clean chain must report isValid: true')
    assert.ok(verification.verifiedCount > 0, 'Should have verified multiple audit entries')
    assert.ok(verification.latestHash, 'Should return latest chain tip hash')
  })

  await t.test('getModerationAuditLogs supports actor and date range filtering', async () => {
    const now = new Date()
    const yesterday = new Date(now.getTime() - 86400000).toISOString()
    const tomorrow = new Date(now.getTime() + 86400000).toISOString()

    // Query with actor filter
    const actorResult = await getModerationAuditLogs({ actor: 'admin@trustlens.lk' })
    assert.ok(actorResult.auditLogs.length > 0)
    for (const log of actorResult.auditLogs) {
      assert.ok(log.actor_email.toLowerCase().includes('admin@trustlens.lk'))
    }

    // Query with date range
    const dateResult = await getModerationAuditLogs({ fromDate: yesterday, toDate: tomorrow })
    assert.ok(dateResult.auditLogs.length > 0)
    for (const log of dateResult.auditLogs) {
      const createdMs = new Date(log.created_at).getTime()
      assert.ok(createdMs >= new Date(yesterday).getTime() && createdMs <= new Date(tomorrow).getTime())
    }
  })

  await t.test('MANUAL_INTEL action is recorded with proper schema attributes', async () => {
    const intelLog = await recordAuditLog({
      action: 'MANUAL_INTEL',
      targetIndicator: 'hxxps://fake-lottery[.]top',
      threatCategory: 'Lottery Scam',
      actorEmail: 'moderator@trustlens.lk',
      actorRole: 'moderator',
      confidence: 0.98,
      moderatorNotes: '[Manual Entry - CONFIRMED_SCAM]: Bogus lottery winner notification',
      clientIp: '172.16.0.4',
      userAgent: 'Mozilla/5.0',
    })

    assert.equal(intelLog.action, 'MANUAL_INTEL')
    assert.equal(intelLog.client_ip, '172.16.0.4')
    assert.equal(intelLog.user_agent, 'Mozilla/5.0')
    assert.equal(intelLog.confidence, 0.98)
    assert.ok(intelLog.entry_hash)
  })

  // ─────────────────────────────────────────────────────────────────────────────
  // Comprehensive Edge Cases for Cryptographic Hash Chain Verification
  // ─────────────────────────────────────────────────────────────────────────────

  function createMockAuditBlock({
    id = 'block-' + Math.random().toString(36).slice(2, 9),
    prevHash = GENESIS_PREV_HASH,
    action = 'APPROVE',
    actorEmail = 'moderator@trustlens.lk',
    actorRole = 'moderator',
    targetIndicator = 'hxxps://test-scam[.]lk',
    threatCategory = 'Banking Phishing',
    moderatorNotes = 'Verified phishing link',
    clientIp = '192.168.1.1',
    createdAt = new Date().toISOString(),
  } = {}) {
    const block = {
      id,
      action,
      actor_email: actorEmail,
      actor_role: actorRole,
      target_indicator: targetIndicator,
      threat_category: threatCategory,
      moderator_notes: moderatorNotes,
      client_ip: clientIp,
      created_at: createdAt,
      prev_hash: prevHash,
    }
    block.entry_hash = computeAuditHash(prevHash, block)
    return block
  }

  await t.test('canonicalTimestamp normalizes ISO8601 strings and timezones deterministically', () => {
    const tsUtc = '2026-09-23T10:00:00.000Z'
    const tsTz = '2026-09-23T15:30:00.000+05:30'
    const tsNoMs = '2026-09-23T10:00:00Z'

    assert.equal(canonicalTimestamp(tsUtc), canonicalTimestamp(tsTz), 'Identical UTC instant with different timezone offset must produce identical canonical string')
    assert.equal(canonicalTimestamp(tsUtc), canonicalTimestamp(tsNoMs), 'Timestamp without milliseconds must normalize to canonical ISO format')

    const blockUtc = { created_at: tsUtc, action: 'APPROVE', actor_email: 'mod@trustlens.lk' }
    const blockTz = { created_at: tsTz, action: 'APPROVE', actor_email: 'mod@trustlens.lk' }
    assert.equal(computeAuditHash(GENESIS_PREV_HASH, blockUtc), computeAuditHash(GENESIS_PREV_HASH, blockTz), 'Hash must be identical across equivalent timestamps')
  })

  await t.test('verifyAuditChainIntegrity edge case: empty audit chain returns valid 0 count', async () => {
    const res = await verifyAuditChainIntegrity({ records: [] })
    assert.equal(res.isValid, true, 'Empty chain is considered valid with 0 records')
    assert.equal(res.verifiedCount, 0, 'Verified count must be 0')
    assert.equal(res.latestHash, null, 'Latest hash must be null')
    assert.ok(res.message.includes('No audit records to verify'))
  })

  await t.test('verifyAuditChainIntegrity edge case: single genesis block chain verifies cleanly', async () => {
    const b1 = createMockAuditBlock({ id: 'block-001', prevHash: GENESIS_PREV_HASH })
    const res = await verifyAuditChainIntegrity({ records: [b1] })

    assert.equal(res.isValid, true, 'Single valid genesis block must verify successfully')
    assert.equal(res.verifiedCount, 1, 'Verified count must be 1')
    assert.equal(res.latestHash, b1.entry_hash, 'Latest hash must match the genesis block hash')
  })

  await t.test('verifyAuditChainIntegrity edge case: multi-block valid sequential chain verifies all blocks', async () => {
    const b1 = createMockAuditBlock({ id: 'b-1', prevHash: GENESIS_PREV_HASH, action: 'AUTH_LOGIN' })
    const b2 = createMockAuditBlock({ id: 'b-2', prevHash: b1.entry_hash, action: 'APPROVE' })
    const b3 = createMockAuditBlock({ id: 'b-3', prevHash: b2.entry_hash, action: 'UPDATE_SETTINGS' })
    const b4 = createMockAuditBlock({ id: 'b-4', prevHash: b3.entry_hash, action: 'RETIRE' })

    const res = await verifyAuditChainIntegrity({ records: [b1, b2, b3, b4] })
    assert.equal(res.isValid, true, 'All 4 sequential blocks must verify')
    assert.equal(res.verifiedCount, 4, 'Verified count must match total blocks (4)')
    assert.equal(res.latestHash, b4.entry_hash, 'Latest hash must point to the chain tip (b4)')
  })

  await t.test('verifyAuditChainIntegrity edge case: detects payload tampering and identifies brokenAtId', async () => {
    const b1 = createMockAuditBlock({ id: 'block-01', prevHash: GENESIS_PREV_HASH })
    const b2 = createMockAuditBlock({ id: 'block-02', prevHash: b1.entry_hash, moderatorNotes: 'Original note' })
    const b3 = createMockAuditBlock({ id: 'block-03', prevHash: b2.entry_hash })

    // Rogue actor tampers with block 2's note without being able to forge the SHA-256 hash
    const tamperedB2 = { ...b2, moderator_notes: 'Tampered note: actor changed classification illegally' }

    const res = await verifyAuditChainIntegrity({ records: [b1, tamperedB2, b3] })
    assert.equal(res.isValid, false, 'Tampered block must fail cryptographic verification')
    assert.equal(res.brokenAtId, 'block-02', 'Must pinpoint the exact tampered record ID')
    assert.equal(res.verifiedCount, 1, 'Only records prior to the tampered record should be counted')
    assert.ok(res.reason.includes('Cryptographic hash mismatch at record #block-02'), 'Reason must specify hash mismatch')
  })

  await t.test('verifyAuditChainIntegrity edge case: detects deleted block / broken sequence linkage', async () => {
    const b1 = createMockAuditBlock({ id: 'block-A', prevHash: GENESIS_PREV_HASH })
    const b2 = createMockAuditBlock({ id: 'block-B', prevHash: b1.entry_hash })
    const b3 = createMockAuditBlock({ id: 'block-C', prevHash: b2.entry_hash })

    // Attacker removes block-B from the sequence to hide an action: [b1, b3]
    const res = await verifyAuditChainIntegrity({ records: [b1, b3] })
    assert.equal(res.isValid, false, 'Missing sequential block must break chain verification')
    assert.equal(res.brokenAtId, 'block-C', 'Must pinpoint the block whose prev_hash does not match previous block')
    assert.ok(res.reason.includes('Cryptographic chain broken between record #block-A and record #block-C'))
  })

  await t.test('verifyAuditChainIntegrity edge case: detects forged hash replacement attack', async () => {
    const b1 = createMockAuditBlock({ id: 'sec-1', prevHash: GENESIS_PREV_HASH })
    const b2 = createMockAuditBlock({ id: 'sec-2', prevHash: b1.entry_hash })

    // Attacker modifies data AND updates entry_hash to an arbitrary fake digest
    const forgedB2 = {
      ...b2,
      threat_category: 'Benign Whitelist',
      entry_hash: '1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff',
    }

    const res = await verifyAuditChainIntegrity({ records: [b1, forgedB2] })
    assert.equal(res.isValid, false, 'Forged hash must fail computation check against real payload')
    assert.equal(res.brokenAtId, 'sec-2', 'Must identify sec-2 as corrupted')
  })

  await t.test('verifyAuditChainIntegrity edge case: detects scrambled or out-of-order blocks', async () => {
    const b1 = createMockAuditBlock({ id: 'ord-1', prevHash: GENESIS_PREV_HASH })
    const b2 = createMockAuditBlock({ id: 'ord-2', prevHash: b1.entry_hash })
    const b3 = createMockAuditBlock({ id: 'ord-3', prevHash: b2.entry_hash })

    // Reversed order: [b3, b2, b1]
    const res = await verifyAuditChainIntegrity({ records: [b3, b2, b1] })
    assert.equal(res.isValid, false, 'Out-of-order blocks must fail verification')
  })

  await t.test('verifyAuditChainIntegrity edge case: gracefully skips unhashed legacy records while validating chained blocks', async () => {
    const b1 = createMockAuditBlock({ id: 'leg-1', prevHash: GENESIS_PREV_HASH })
    const legacyOld = { id: 'leg-legacy', action: 'APPROVE', moderator_notes: 'Old pre-crypto log', entry_hash: null }
    const b2 = createMockAuditBlock({ id: 'leg-2', prevHash: b1.entry_hash })

    const res = await verifyAuditChainIntegrity({ records: [b1, legacyOld, b2] })
    assert.equal(res.isValid, true, 'Legacy unhashed record must not crash or break valid chain linkage')
    assert.equal(res.verifiedCount, 2, 'Should verify the 2 hashed blocks')
    assert.equal(res.latestHash, b2.entry_hash)
  })

  await t.test('verifyAuditChainIntegrity edge case: handles all-unhashed legacy audit table safely', async () => {
    const old1 = { id: 'old-1', action: 'APPROVE', entry_hash: null }
    const old2 = { id: 'old-2', action: 'REJECT', entry_hash: null }

    const res = await verifyAuditChainIntegrity({ records: [old1, old2] })
    assert.equal(res.isValid, true, 'All-unhashed table should report valid without false tampering alarms')
    assert.equal(res.verifiedCount, 0, 'No cryptographically hashed records counted')
    assert.equal(res.latestHash, null)
  })

  await t.test('verifyAuditChainIntegrity edge case: supports raw vs defanged target indicators without false positives', async () => {
    // Record was originally stored with raw domain, mapped with defanged target for UI
    const rawDomain = 'suspicious-bank-login.com'
    const defanged = 'suspicious-bank-login[.]com'
    const b1 = createMockAuditBlock({
      id: 'ind-1',
      prevHash: GENESIS_PREV_HASH,
      targetIndicator: rawDomain,
    })

    // Mapped view has target_indicator: defanged, raw_target_indicator: rawDomain
    const mappedB1 = {
      ...b1,
      target_indicator: defanged,
      raw_target_indicator: rawDomain,
    }

    const res = await verifyAuditChainIntegrity({ records: [mappedB1] })
    assert.equal(res.isValid, true, 'Must verify when raw_target_indicator matches entry_hash computation')
    assert.equal(res.verifiedCount, 1)
  })

  await t.test('verifyAuditChainIntegrity edge case: latestHash strictly matches chain tip', async () => {
    const b1 = createMockAuditBlock({ id: 'tip-1', prevHash: GENESIS_PREV_HASH })
    const b2 = createMockAuditBlock({ id: 'tip-2', prevHash: b1.entry_hash })
    const b3 = createMockAuditBlock({ id: 'tip-3', prevHash: b2.entry_hash })

    const res = await verifyAuditChainIntegrity({ records: [b1, b2, b3] })
    assert.equal(res.latestHash, b3.entry_hash, 'latestHash must equal the terminal block entry_hash')
  })

  await t.test('verifyAuditChainIntegrity edge case: chain remains cryptographically valid after pruning historical records', async () => {
    // Simulate a timeline:
    // Block 1 (120 days ago) -> Block 2 (100 days ago) -> Block 3 (30 days ago) -> Block 4 (5 days ago)
    const msDay = 86400000
    const now = Date.now()
    const b1 = createMockAuditBlock({ id: 'prune-1', prevHash: GENESIS_PREV_HASH, createdAt: new Date(now - 120 * msDay).toISOString() })
    const b2 = createMockAuditBlock({ id: 'prune-2', prevHash: b1.entry_hash, createdAt: new Date(now - 100 * msDay).toISOString() })
    const b3 = createMockAuditBlock({ id: 'prune-3', prevHash: b2.entry_hash, createdAt: new Date(now - 30 * msDay).toISOString() })
    const b4 = createMockAuditBlock({ id: 'prune-4', prevHash: b3.entry_hash, createdAt: new Date(now - 5 * msDay).toISOString() })

    // When 90-day retention prune executes, b1 and b2 are deleted.
    // The governance prune block is appended to the chain tip (b4).
    const bPurge = createMockAuditBlock({
      id: 'prune-gov',
      action: 'PURGE_EXPIRED',
      targetIndicator: 'policy.retention.90d',
      threatCategory: 'Governance Prune',
      actorEmail: 'system.scheduler@trustlens.lk',
      actorRole: 'system',
      moderatorNotes: 'Automated retention governance pruned 2 expired audit records',
      prevHash: b4.entry_hash,
      createdAt: new Date().toISOString(),
    })

    // Active records surviving in table: [b3, b4, bPurge]
    const survivingActiveChain = [b3, b4, bPurge]
    const res = await verifyAuditChainIntegrity({ records: survivingActiveChain })

    assert.equal(res.isValid, true, 'Surviving active chain must verify cleanly after historical prune')
    assert.equal(res.verifiedCount, 3, 'Must verify all 3 surviving and governance blocks')
    assert.equal(res.latestHash, bPurge.entry_hash, 'Latest chain tip hash must match the governance block')
  })

  await t.test('verifyAuditChainIntegrity edge case: detects illicit middle-deletion or tampering even within a pruned chain', async () => {
    const msDay = 86400000
    const now = Date.now()
    const b1 = createMockAuditBlock({ id: 'mid-1', prevHash: GENESIS_PREV_HASH, createdAt: new Date(now - 120 * msDay).toISOString() })
    const b2 = createMockAuditBlock({ id: 'mid-2', prevHash: b1.entry_hash, createdAt: new Date(now - 100 * msDay).toISOString() })
    const b3 = createMockAuditBlock({ id: 'mid-3', prevHash: b2.entry_hash, createdAt: new Date(now - 30 * msDay).toISOString() })
    const b4 = createMockAuditBlock({ id: 'mid-4', prevHash: b3.entry_hash, createdAt: new Date(now - 5 * msDay).toISOString() })

    // Attack 1: Rogue deletion of b4 in a pruned chain leaving [b3, b5]
    const b5 = createMockAuditBlock({ id: 'mid-5', prevHash: b4.entry_hash, createdAt: new Date().toISOString() })
    const illegalDeletionRes = await verifyAuditChainIntegrity({ records: [b3, b5] })
    assert.equal(illegalDeletionRes.isValid, false, 'Middle block deletion in pruned chain must be caught immediately')
    assert.equal(illegalDeletionRes.brokenAtId, 'mid-5')

    // Attack 2: Tampering with the oldest surviving anchor block (b3)
    const tamperedB3 = { ...b3, moderator_notes: 'Tampered notes inside anchor block' }
    const tamperedAnchorRes = await verifyAuditChainIntegrity({ records: [tamperedB3, b4, b5] })
    assert.equal(tamperedAnchorRes.isValid, false, 'Payload alteration in anchor block must be caught')
    assert.equal(tamperedAnchorRes.brokenAtId, 'mid-3')
  })
})

