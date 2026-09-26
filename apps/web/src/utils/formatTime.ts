/**
 * Lightweight relative time formatting utility leveraging native browser Intl APIs.
 * Zero external dependencies.
 */

const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto', style: 'short' })

export function formatRelativeTime(dateInput: string | number | Date): string {
  try {
    const date = new Date(dateInput)
    const now = Date.now()
    const diffInSeconds = Math.round((date.getTime() - now) / 1000)

    if (Math.abs(diffInSeconds) < 45) {
      return 'just now'
    }

    const diffInMinutes = Math.round(diffInSeconds / 60)
    if (Math.abs(diffInMinutes) < 60) {
      return rtf.format(diffInMinutes, 'minute')
    }

    const diffInHours = Math.round(diffInMinutes / 60)
    if (Math.abs(diffInHours) < 24) {
      return rtf.format(diffInHours, 'hour')
    }

    const diffInDays = Math.round(diffInHours / 24)
    if (Math.abs(diffInDays) < 7) {
      return rtf.format(diffInDays, 'day')
    }

    return date.toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return String(dateInput)
  }
}
