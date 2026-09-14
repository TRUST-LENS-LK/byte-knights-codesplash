import { extractEntities } from '../../../../packages/extraction/src'
import { analyzeMessage } from '../../../../packages/rules/src'
import type { ExtractedEntity, RiskDecision } from '../../../../packages/contracts/src'

export type LocalAnalysis = {
  decision: RiskDecision
  entities: ExtractedEntity[]
  inputType: 'message' | 'url'
}

export function analyzeSubmission(text: string): LocalAnalysis {
  const trimmed = text.trim()
  const entities = extractEntities(trimmed)
  const decision = analyzeMessage(trimmed)
  return { decision, entities, inputType: entities.some((entity) => entity.type === 'url') ? 'url' : 'message' }
}

export async function analyzeWithApi(text: string): Promise<LocalAnalysis> {
  const response = await fetch('http://localhost:8787/api/analyze', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'message', text, retentionConsent: false }) })
  if (!response.ok) throw new Error('Analysis API request failed')
  return (await response.json()) as LocalAnalysis
}
