const PRIVATE_IPV4 = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^0\./,
]

export function validateScannerUrl(value) {
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    return { allowed: false, reason: 'URL is invalid.' }
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) return { allowed: false, reason: 'Only HTTP and HTTPS URLs are allowed.' }
  const hostname = parsed.hostname.toLowerCase()
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname === '::1' || hostname === '[::1]') return { allowed: false, reason: 'Localhost targets are not allowed.' }
  if (PRIVATE_IPV4.some((pattern) => pattern.test(hostname))) return { allowed: false, reason: 'Private or link-local targets are not allowed.' }
  if (hostname.startsWith('fc') || hostname.startsWith('fd') || hostname.startsWith('fe80:')) return { allowed: false, reason: 'Private IPv6 targets are not allowed.' }
  return { allowed: true, hostname, url: parsed.toString() }
}
