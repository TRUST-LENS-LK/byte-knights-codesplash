import { extractedEntitySchema, type ExtractedEntity } from '@trustlens/contracts'

const patterns = {
  url: /https?:\/\/[^\s<>()]+/gi,
  email: /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/gi,
  phone: /(?:\+94|0)\s?\d{2}\s?\d{3}\s?\d{4}/g,
  amount: /(?:rs\.?|lkr)\s?[\d,]+(?:\.\d{2})?/gi,
}

function entitiesFor(type: keyof typeof patterns, text: string): ExtractedEntity[] {
  return [...text.matchAll(patterns[type])].map((match) => {
    const value = type === 'url' ? match[0].replace(/[),.!?]+$/, '') : match[0]
    const normalizedValue = type === 'phone' ? value.replace(/\s/g, '').replace(/^0/, '+94') : value
    return extractedEntitySchema.parse({ type, value, normalizedValue, sourceSpan: match[0], confidence: 0.95 })
  })
}

export function extractEntities(text: string): ExtractedEntity[] {
  const allEntities = (Object.keys(patterns) as Array<keyof typeof patterns>).flatMap((type) => entitiesFor(type, text))
  return allEntities.filter((entity, index, arr) => 
    arr.findIndex((c) => c.type === entity.type && c.value === entity.value) === index
  )
}
