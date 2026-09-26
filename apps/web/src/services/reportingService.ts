import { createUserReportSchema } from '@trustlens/contracts'

export type ReportType = 'suspicious' | 'false_positive' | 'false_negative'

export interface SubmitReportPayload {
  reportType: ReportType
  threatCategory?: string | null
  contentSha256: string
  reportedDomain?: string | null
  notes?: string | null
  submissionId?: string | null
  rawExcerpt?: string | null
}

export interface CreatedReport {
  id: string
  report_type: ReportType
  threat_category?: string | null
  content_sha256: string
  reported_domain: string | null
  notes: string | null
  status: 'PENDING' | 'REVIEWED' | 'REJECTED' | 'APPROVED'
  created_at: string
}

export interface SubmitReportResult {
  success: boolean
  report?: CreatedReport
  error?: string
}

/**
 * Computes a 64-character lowercase hexadecimal SHA-256 hash
 * entirely on the client using the browser's native Web Crypto API.
 */
export async function computeSha256(text: string): Promise<string> {
  const encoder = new TextEncoder()
  const normalized = text.replace(/\r\n/g, '\n').trim()
  const data = encoder.encode(normalized)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Defangs a URL, domain, or email string to prevent accidental clicks or execution.
 * e.g. "https://scam.lk" -> "hxxps://scam[.]lk"
 * e.g. "scammer@phish.lk" -> "scammer[@]phish[.]lk"
 */
export function defangIndicator(indicator: string): string {
  if (!indicator) return ''
  const clean = indicator
    .replace(/hxxps?:\/\//gi, 'https://')
    .replace(/\[+\]+/g, '.')
    .replace(/\[\.\]/g, '.')
    .replace(/\[@\]/g, '@')

  return clean
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/^ftp:\/\//i, 'fxp://')
    .replace(/\./g, '[.]')
    .replace(/@/g, '[@]')
}

/**
 * Submits a validated community threat report to the TrustLens API.
 * Validates payload runtime structure using shared Zod contracts before dispatch.
 */
export async function submitUserReport(payload: SubmitReportPayload): Promise<SubmitReportResult> {
  // Runtime validation using shared Zod contract
  const validation = createUserReportSchema.safeParse(payload)
  if (!validation.success) {
    const errorMessages = validation.error.issues.map((issue) => issue.message).join('; ')
    return {
      success: false,
      error: `Client validation failed: ${errorMessages}`,
    }
  }

  try {
    const response = await fetch('http://localhost:8787/api/reports', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify(validation.data),
    })

    const data = await response.json()

    if (!response.ok) {
      return {
        success: false,
        error: data.message || `Submission failed with status ${response.status}`,
      }
    }

    return {
      success: true,
      report: data.report,
    }
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Network error: could not connect to TrustLens API.',
    }
  }
}
