const patterns = [
  ['credential_request', 'Sensitive information', /otp|one[- ]time password|pin|password|bank(?:ing)? details?/i, 'OTP, PIN, password, or banking details', 0.98],
  ['advance_payment', 'Financial request', /registration fee|upfront|deposit|send (?:rs\.?|lkr)|payment|pay today|transfer/i, 'Payment or upfront-fee language', 0.95],
  ['urgency', 'Social engineering', /urgent|immediately|today|expires|act now|last chance/i, 'Urgent timing language', 0.55],
  ['job_offer', 'Job scam', /job|salary|vacancy|work from home|hiring|selected/i, 'Recruitment or job-offer language', 0.65],
]

export function extractEntities(text) {
  const entities = []
  for (const match of text.matchAll(/https?:\/\/[^\s<>()]+/gi)) {
    const value = match[0].replace(/[),.!?]+$/, '')
    entities.push({ type: 'url', value, confidence: 0.99 })
    try {
      const hostname = new URL(value).hostname.toLowerCase()
      if (hostname) entities.push({ type: 'domain', value: hostname, normalizedValue: hostname, confidence: 0.98 })
    } catch {
      // Keep the URL entity when the submitted value is not parseable.
    }
  }
  // Extract bare domains (e.g. "scam.lk", "bank-verify.com") not already captured via URL extraction
  for (const match of text.matchAll(/(?:^|[\s,;()\[\]<>])([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)(?=[)\]>.,;:!?\s]|$)/gm)) {
    const domain = match[1].toLowerCase()
    // Skip if this domain was already extracted from a full URL or looks like an email
    const alreadyHas = entities.some((e) => e.type === 'domain' && e.value === domain)
    if (!alreadyHas && !text.includes(`@${domain}`)) {
      entities.push({ type: 'domain', value: domain, normalizedValue: domain, confidence: 0.90 })
    }
  }
  for (const match of text.matchAll(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g)) entities.push({ type: 'email', value: match[0], confidence: 0.99 })
  for (const match of text.matchAll(/(?:\+94|0)\s*\d{2}\s*\d{3}\s*\d{4}/g)) entities.push({ type: 'phone', value: match[0], normalizedValue: match[0].replace(/\s+/g, '').replace(/^0/, '+94'), confidence: 0.95 })
  for (const match of text.matchAll(/(?:Rs\.?|LKR)\s?[\d,]+(?:\.\d{1,2})?/gi)) entities.push({ type: 'amount', value: match[0], confidence: 0.94 })
  return entities.filter((entity, index, all) => all.findIndex((candidate) => candidate.type === entity.type && candidate.value === entity.value) === index)
}

export function analyze(text) {
  const findings = patterns.filter(([, , pattern]) => pattern.test(text)).map(([canonicalSignal, category, , evidence, strength]) => ({ canonicalSignal, category, evidence, source: 'RULE', strength, confidence: strength, limitation: 'Keyword rule; context should be verified independently.' }))
  const critical = findings.some((item) => ['credential_request', 'advance_payment'].includes(item.canonicalSignal))
  const riskBand = critical || findings.length >= 3 ? 'HIGH' : findings.length ? 'MEDIUM' : 'LOW'
  return { riskBand, recommendation: riskBand === 'HIGH' ? 'STOP_AND_AVOID' : riskBand === 'MEDIUM' ? 'VERIFY_INDEPENDENTLY' : 'PROCEED_CAUTIOUSLY', findings, limitations: ['This local prototype uses deterministic rules only.'], safeActions: riskBand === 'HIGH' ? ['Do not click, pay, reply, or share credentials.', "Verify through the organisation's official website."] : ['Verify the sender and organisation independently.'], policyVersion: 'rules-v1' }
}

export function validateSubmission(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return 'Request body must be a JSON object.'
  if (body.type !== undefined && !['message', 'url', 'screenshot'].includes(body.type)) return 'type must be message, url, or screenshot.'
  if (body.languageHint !== undefined && !['en', 'si', 'singlish', 'mixed'].includes(body.languageHint)) return 'languageHint is not supported.'
  if (body.retentionConsent !== undefined && typeof body.retentionConsent !== 'boolean') return 'retentionConsent must be a boolean.'
  return null
}
