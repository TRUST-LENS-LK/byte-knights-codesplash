import { createWorker } from 'tesseract.js'

export interface OcrProgress {
  status: string
  progress: number // 0.0 to 1.0
  message: string
}

export interface OcrResult {
  text: string
  confidence: number // Average confidence percentage (0 - 100)
  language: string
}

export interface PerformOcrOptions {
  languages?: string // Defaults to 'eng+sin' (English + Sinhala)
  onProgress?: (progress: OcrProgress) => void
}

/**
 * Clean and format raw OCR output text.
 * Strips weird non-printable control characters while preserving English,
 * Sinhala Unicode (U+0D80 to U+0DFF), numbers, and standard punctuation.
 */
export function cleanOcrText(rawText: string): string {
  if (!rawText || typeof rawText !== 'string') return ''

  return rawText
    // Standardize newline characters
    .replace(/\r\n/g, '\n')
    // Remove null bytes and non-printable control characters (except newline & tab)
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    // Collapse multiple blank lines into max 2 newlines
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

/**
 * Formats Tesseract logger progress updates into human-readable messages.
 */
function formatProgressMessage(status: string, progress: number): string {
  const pct = Math.round((progress || 0) * 100)
  switch (status) {
    case 'loading tesseract core':
      return 'Loading OCR engine core...'
    case 'initializing tesseract':
      return 'Initializing OCR engine...'
    case 'loading language traineddata':
      return `Downloading language models (English & Sinhala)... ${pct}%`
    case 'initializing api':
      return 'Setting up Sinhala/English OCR API...'
    case 'recognizing text':
      return `Recognizing text in screenshot... ${pct}%`
    default:
      return `${status || 'Processing screenshot'}... ${pct}%`
  }
}

/**
 * Performs client-side OCR on an image file or blob using Tesseract.js.
 * Supports English and Sinhala (eng+sin) language recognition.
 *
 * @param imageInput File, Blob, or image URL string
 * @param options Configuration options including progress callback and language selection
 */
export async function performOcr(
  imageInput: File | Blob | string,
  options: PerformOcrOptions = {}
): Promise<OcrResult> {
  const languages = options.languages || 'eng+sin'

  options.onProgress?.({
    status: 'initializing',
    progress: 0.05,
    message: 'Preparing image for text recognition...',
  })

  let worker: Awaited<ReturnType<typeof createWorker>> | null = null

  try {
    worker = await createWorker(languages, 1, {
      logger: (update: { status: string; progress: number }) => {
        options.onProgress?.({
          status: update.status || 'processing',
          progress: update.progress || 0,
          message: formatProgressMessage(update.status, update.progress || 0),
        })
      },
    })

    const { data } = await worker.recognize(imageInput)

    const rawText = data.text || ''
    const cleanedText = cleanOcrText(rawText)
    const overallConfidence = Math.round(data.confidence || 0)

    options.onProgress?.({
      status: 'completed',
      progress: 1.0,
      message: 'Text recognition completed successfully.',
    })

    return {
      text: cleanedText,
      confidence: overallConfidence,
      language: languages,
    }
  } catch (error) {
    // If combined eng+sin worker fails (e.g. network issue downloading Sinhala traineddata),
    // fallback to English-only OCR worker
    if (languages.includes('+')) {
      options.onProgress?.({
        status: 'fallback',
        progress: 0.1,
        message: 'Multilingual model offline, falling back to English OCR...',
      })

      try {
        return await performOcr(imageInput, { ...options, languages: 'eng' })
      } catch (fallbackError) {
        throw new Error(
          `OCR recognition failed: ${fallbackError instanceof Error ? fallbackError.message : 'Unknown error'}`
        )
      }
    }

    throw new Error(
      `OCR recognition failed: ${error instanceof Error ? error.message : 'Unknown error'}`
    )
  } finally {
    if (worker) {
      await worker.terminate().catch(() => {})
    }
  }
}
