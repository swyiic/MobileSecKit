/**
 * Human-readable time helpers for values crossing the UI boundary.
 *
 * Runtime data in Me uses both Date.now()-style milliseconds and a few
 * backend epoch-second fields. Normalize here instead of changing the
 * machine-readable values used for sorting, deadlines, IDs, and correlation.
 */
export type ReadableTimestamp = number | string | Date | null | undefined

function toDate(value: ReadableTimestamp): Date | null {
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return null
    // Epoch seconds are currently used by the AI context pack; all larger
    // values produced by Date.now() and the Rust signal bridge are millis.
    const milliseconds = Math.abs(value) < 100_000_000_000 ? value * 1000 : value
    const date = new Date(milliseconds)
    return Number.isNaN(date.getTime()) ? null : date
  }
  if (typeof value === 'string') {
    const trimmed = value.trim()
    if (!trimmed) return null
    const numeric = Number(trimmed)
    if (Number.isFinite(numeric)) return toDate(numeric)
    const date = new Date(trimmed)
    return Number.isNaN(date.getTime()) ? null : date
  }
  return null
}

const dateTimeFormatter = new Intl.DateTimeFormat('zh-CN', {
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
})

function replaceDateSeparators(value: string): string {
  return value.replace(/\//g, '-').replace(',', '')
}

export function formatDateTime(value: ReadableTimestamp): string {
  const date = toDate(value)
  return date ? replaceDateSeparators(dateTimeFormatter.format(date)) : '—'
}
