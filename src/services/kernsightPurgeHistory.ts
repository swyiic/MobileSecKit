import type { KernSightGroupPurgeReport } from '@/types/monitoring'
export const purgeHistoryKey = (r: KernSightGroupPurgeReport): string => `${r.id}:${r.updatedUnixMs}:${r.state}:${r.localState}:${r.deviceState}`
// Display preferences only: never mutates a report or authorizes cleanup.
export function updateHiddenPurgeKeys(keys: readonly string[], report: KernSightGroupPurgeReport, hide: boolean): string[] {
  const key = purgeHistoryKey(report)
  const next = keys.filter(k => k !== key)
  if (hide && report.state !== 'running') next.push(key)
  return next.slice(-1024)
}
