import { extractEntities } from '../../../../packages/extraction/src'
import { analyzeMessage } from '../../../../packages/rules/src'
import type { ExtractedEntity, RiskDecision } from '../../../../packages/contracts/src'

const API_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8787'

export type LocalAnalysis = {
  decision: RiskDecision
  entities: ExtractedEntity[]
  inputType: 'message' | 'url'
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

export async function analyzeWithApi(text: string): Promise<LocalAnalysis> {
  const response = await fetch(`${API_URL}/api/analyze`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ type: 'message', text, retentionConsent: false }),
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

