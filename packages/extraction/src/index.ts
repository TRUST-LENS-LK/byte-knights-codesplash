import { extractedEntitySchema, type ExtractedEntity } from '../../../packages/contracts/src/index'

const patterns = {
  url: /https?:\/\/[^\s<>()]+/gi,
  email: /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/gi,
  phone: /(?:\+94|0)\s?\d{2}\s?\d{3}\s?\d{4}/g,
  amount: /(?:rs\.?|lkr)\s?[\d,]+(?:\.\d{2})?/gi,
}

function entitiesFor(type: keyof typeof patterns, text: string): ExtractedEntity[] {
  return [...text.matchAll(patterns[type])].map((match) => {
    const value = match[0]
    const normalizedValue = type === 'phone' ? value.replace(/\s/g, '').replace(/^0/, '+94') : type === 'url' ? value.replace(/[.,!?]+$/, '') : value
    return extractedEntitySchema.parse({ type, value, normalizedValue, sourceSpan: value, confidence: 0.95 })
  })
}

export function extractEntities(text: string): ExtractedEntity[] {
  return (Object.keys(patterns) as Array<keyof typeof patterns>).flatMap((type) => entitiesFor(type, text))
}
