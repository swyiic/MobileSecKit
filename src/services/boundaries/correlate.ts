import type { AppAnalysis, DataBoundaryObservation } from '@/types'
import { parseRuntimeBoundaries } from './runtimeParser'

function endpointKey(value?: string) {
  if (!value) return ''
  try {
    const url = new URL(value)
    return `${url.hostname.toLowerCase()}${url.pathname.replace(/\/+$/, '').toLowerCase()}`
  } catch {
    return value.toLowerCase().replace(/[?#].*$/, '').replace(/\/+$/, '')
  }
}

function key(item: DataBoundaryObservation) {
  const endpoint = endpointKey(item.endpoint)
  if (endpoint) return `${item.boundary}|endpoint|${endpoint}`
  const target = item.runtimeTarget || item.operation || item.framework || item.sourceLocation || item.title
  return `${item.boundary}|target|${target.toLowerCase().replace(/\s+/g, ' ').trim()}`
}

function merge(staticItem: DataBoundaryObservation, runtimeItem: DataBoundaryObservation): DataBoundaryObservation {
  return {
    ...staticItem,
    id: staticItem.id,
    sourceType: 'static-correlated',
    confidence: 'runtime-confirmed',
    summary: '静态线索与运行时事件已关联；仍应结合请求参数、响应和调用栈复核数据是否真实跨越该边界。',
    endpoint: staticItem.endpoint || runtimeItem.endpoint,
    runtimeTarget: runtimeItem.runtimeTarget || staticItem.runtimeTarget,
    sourceLocation: [staticItem.sourceLocation, runtimeItem.sourceLocation].filter(Boolean).join(' · '),
    evidence: [...new Set([...staticItem.evidence, ...runtimeItem.evidence])].slice(0, 30),
    dataTypes: [...new Set([...staticItem.dataTypes, ...runtimeItem.dataTypes])],
    observedAt: runtimeItem.observedAt,
  }
}

export function correlateBoundaries(
  analysis: AppAnalysis | null,
  history: import('@/types').TerminalEntry[],
  platform: 'android' | 'ios' | 'unknown' = 'unknown',
  deviceId?: string,
) {
  const staticItems = analysis?.dataBoundaries || []
  // An imported artifact without a resolved package/bundle identifier cannot
  // safely own process output. Keep it static-only instead of attaching every
  // unscoped log from the session.
  const runtimeItems = analysis && !analysis.packageId
    ? []
    : parseRuntimeBoundaries(history, platform, analysis?.packageId || undefined, deviceId)
  const byKey = new Map<string, DataBoundaryObservation>()
  staticItems.forEach((item) => byKey.set(key(item), item))
  const result = [...staticItems]
  for (const runtimeItem of runtimeItems) {
    const match = byKey.get(key(runtimeItem))
    if (match) {
      const merged = merge(match, runtimeItem)
      const index = result.findIndex((item) => item.id === match.id)
      if (index >= 0) result[index] = merged
      byKey.set(key(merged), merged)
    } else {
      result.push(runtimeItem)
    }
  }
  return { items: result, runtimeItems, staticItems }
}
