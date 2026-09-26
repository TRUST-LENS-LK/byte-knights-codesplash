import { extractEntities } from '@trustlens/extraction'
import { analyzeMessage } from '@trustlens/rules'
import type { ExtractedEntity, RiskDecision } from '@trustlens/contracts'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8787'

export type LocalAnalysis = {
  decision: RiskDecision
  entities: ExtractedEntity[]
  scannerEvidence?: any[]
  inputType: 'message' | 'url' | 'screenshot'
  submissionId?: string
  requestId?: string
}

export type ReportType = 'suspicious' | 'false_positive' | 'false_negative'

export type ReportResult = {
  reportId: string
  status: string
}

export function analyzeSubmission(text: string): LocalAnalysis {
  const trimmed = text.trim()
  const entities = extractEntities(trimmed)
  const decision = analyzeMessage(trimmed)
  return { decision, entities, inputType: entities.some((entity) => entity.type === 'url') ? 'url' : 'message' }
}

// A submission is treated as a dedicated URL submission only when the whole
// trimmed input is a single absolute http(s) URL, not just text that happens
// to contain a link somewhere in it. That distinction matters because a
// dedicated URL submission has no surrounding message context, so it cannot
// trigger keyword-based scam rules or the claimed-organization mismatch
// check, only directory and structural URL checks apply.
export function detectSubmissionType(rawText: string): 'message' | 'url' {
  const trimmed = rawText.trim()
  if (!trimmed || /\s/.test(trimmed)) return 'message'
  try {
    const parsed = new URL(trimmed)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? 'url' : 'message'
  } catch {
    return 'message'
  }
}

// The URL entity extractor (and the `url` submission field itself) only
// recognizes an absolute http(s) URL, so a bare domain like "boc.lk" typed
// into a dedicated URL input would otherwise be silently invisible to the
// whole domain-verification pipeline. Since a "check this URL" input's
// entire context is unambiguous, prepend https:// rather than rejecting it
// or requiring the user to remember to type a scheme.
export function normalizeUrlInput(rawText: string): string {
  const trimmed = rawText.trim()
  if (!trimmed) return trimmed
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
}

export async function analyzeWithApi(
  text: string,
  type: 'message' | 'url' | 'screenshot' = 'message'
): Promise<LocalAnalysis> {
  const trimmed = text.trim()
  // Match the contract's shape (packages/contracts submissionSchema): a url
  // submission sends `url`, everything else sends `text`.
  const body = type === 'url' ? { type, url: trimmed, retentionConsent: false } : { type, text: trimmed, retentionConsent: false }
  const response = await fetch(`${API_URL}/api/analyze`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) throw new Error('Analysis API request failed')
  return (await response.json()) as LocalAnalysis
}

export async function submitReport(
  text: string,
  reportType: ReportType,
  notes?: string,
  reportedDomain?: string,
): Promise<ReportResult> {
  const body: Record<string, string> = { text, reportType }
  if (notes?.trim()) body.notes = notes.trim()
  if (reportedDomain?.trim()) body.reportedDomain = reportedDomain.trim()
  const response = await fetch(`${API_URL}/api/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) throw new Error('Report submission failed')
  return (await response.json()) as ReportResult
}
