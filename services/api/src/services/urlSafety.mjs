import { isIP } from 'node:net'

const PRIVATE_IPV4 = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^0\./,
  /^100\.(?:6[4-9]|[789]\d|1[01]\d|12[0-7])\./,
  /^198\.(?:18|19)\./,
  /^(?:22[4-9]|23\d)\./,
]

function unsafeHostname(hostname) {
  const normalized = hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (normalized === 'localhost' || normalized.endsWith('.localhost')) return 'Localhost targets are not allowed.'
  if (PRIVATE_IPV4.some((pattern) => pattern.test(normalized))) return 'Private or reserved IPv4 targets are not allowed.'
  if (isIP(normalized) === 6 && (normalized === '::' || normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe80:'))) return 'Private IPv6 targets are not allowed.'
  if (normalized.startsWith('::ffff:')) {
    const parts = normalized.slice(7).split(':')
    if (parts.length === 2) {
      const first = Number.parseInt(parts[0], 16)
      const second = Number.parseInt(parts[1], 16)
      const mapped = `${first >> 8}.${first & 255}.${second >> 8}.${second & 255}`
      if (PRIVATE_IPV4.some((pattern) => pattern.test(mapped))) return 'Private or reserved IPv4 targets are not allowed.'
    }
  }
  return null
}

export function validateScannerUrl(value) {
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    return { allowed: false, reason: 'URL is invalid.' }
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) return { allowed: false, reason: 'Only HTTP and HTTPS URLs are allowed.' }
  const hostname = parsed.hostname.toLowerCase()
  const unsafeReason = unsafeHostname(hostname)
  if (unsafeReason) return { allowed: false, reason: unsafeReason }
  return { allowed: true, hostname, url: parsed.toString() }
}

export function inspectScannerUrl(value) {
  const validation = validateScannerUrl(value)
  if (!validation.allowed) return validation
  const parsed = new URL(validation.url)
  const signals = []
  if (parsed.username || parsed.password) signals.push('embedded_credentials')
  if (parsed.port && !['80', '443'].includes(parsed.port)) signals.push('non_standard_port')
  if (parsed.hostname.includes('xn--')) signals.push('internationalized_hostname')
  if (parsed.hostname.split('.').length > 4) signals.push('deep_subdomain')
  if (parsed.pathname.length > 100) signals.push('long_path')
  if (parsed.search.length > 120) signals.push('long_query')
  return { ...validation, protocol: parsed.protocol.slice(0, -1), port: parsed.port || null, path: parsed.pathname, hasQuery: parsed.search.length > 0, signals }
}

export function scannerFindings(entities) {
  const findings = []
  for (const entity of entities.filter((item) => item.type === 'url')) {
    const inspection = inspectScannerUrl(entity.value)
    if (!inspection.allowed) {
      findings.push({ canonicalSignal: 'unsafe_url_target', category: 'URL safety', evidence: inspection.reason, source: 'SCANNER', strength: 0.9, confidence: 0.98, limitation: 'The URL was not fetched.' })
      continue
    }
    for (const signal of inspection.signals) {
      const labels = {
        embedded_credentials: 'The URL contains embedded credentials.',
        non_standard_port: 'The URL uses a non-standard web port.',
        internationalized_hostname: 'The URL uses an internationalized hostname.',
        deep_subdomain: 'The URL has an unusually deep subdomain structure.',
        long_path: 'The URL has an unusually long path.',
        long_query: 'The URL has an unusually long query string.',
      }
      findings.push({ canonicalSignal: signal, category: 'URL structure', evidence: labels[signal], source: 'SCANNER', strength: signal === 'embedded_credentials' ? 0.85 : 0.55, confidence: 0.8, limitation: 'Structural URL signal only; the target was not fetched.' })
    }
  }
  return findings
}
