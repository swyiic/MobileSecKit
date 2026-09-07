import type { DataBoundaryFlow, DataBoundaryObservation, DataFlowValidationState } from '@/types'

const STATE_PRIORITY: Record<DataFlowValidationState, number> = {
  'static-candidate': 0,
  blocked: 1,
  'runtime-observed': 2,
  correlated: 3,
  'manual-confirmed': 4,
}

const SEVERITY_PRIORITY: Record<string, number> = { info: 0, review: 1, medium: 1, high: 2, critical: 3 }

function normalize(value?: string) {
  return value?.trim().toLowerCase().replace(/[?#].*$/, '').replace(/\/+$/, '').replace(/\s+/g, ' ') || ''
}

function validationState(item: DataBoundaryObservation): DataFlowValidationState {
  if (item.confidence === 'manual-confirmed') return 'manual-confirmed'
  if (item.confidence === 'blocked' || item.sourceType === 'runtime-blocked') return 'blocked'
  if (item.sourceType === 'static-correlated' || item.confidence === 'runtime-confirmed') return 'correlated'
  if (item.sourceType === 'runtime' || item.sourceType === 'runtime-observed' || item.observedAt) return 'runtime-observed'
  return 'static-candidate'
}

function flowKey(item: DataBoundaryObservation) {
  const endpoint = normalize(item.endpoint)
  if (endpoint) return `${item.boundary}|endpoint|${endpoint}`
  const target = normalize(item.operation || item.runtimeTarget || item.consumer || item.producer || item.framework || item.title)
  return `${item.boundary}|target|${target}`
}

function stableFlowId(value: string) {
  let hash = 2166136261
  for (const char of value) {
    hash ^= char.charCodeAt(0)
    hash = Math.imul(hash, 16777619)
  }
  return `flow-${(hash >>> 0).toString(16)}`
}

function preferredValue(items: DataBoundaryObservation[], selector: (item: DataBoundaryObservation) => string | undefined) {
  return items.map(selector).find((value) => value?.trim())
}

export function buildBoundaryFlows(items: DataBoundaryObservation[]): DataBoundaryFlow[] {
  const groups = new Map<string, DataBoundaryObservation[]>()
  for (const item of items) {
    const key = flowKey(item)
    groups.set(key, [...(groups.get(key) || []), item])
  }

  return [...groups.entries()].map(([key, observations]) => {
    const states = observations.map(validationState)
    const validationStateValue = states.sort((left, right) => STATE_PRIORITY[right] - STATE_PRIORITY[left])[0]
    const severity = observations.map((item) => item.severity || 'info')
      .sort((left, right) => (SEVERITY_PRIORITY[right] || 0) - (SEVERITY_PRIORITY[left] || 0))[0]
    const observedAt = Math.max(...observations.map((item) => item.observedAt || 0)) || undefined
    return {
      id: stableFlowId(key),
      boundary: observations[0].boundary,
      title: observations.find((item) => item.severity === severity)?.title || observations[0].title,
      direction: observations[0].direction,
      producer: preferredValue(observations, (item) => item.producer),
      consumer: preferredValue(observations, (item) => item.consumer),
      endpoint: preferredValue(observations, (item) => item.endpoint),
      operation: preferredValue(observations, (item) => item.operation || item.runtimeTarget),
      frameworks: [...new Set(observations.map((item) => item.framework).filter((value): value is string => Boolean(value)))],
      dataTypes: [...new Set(observations.flatMap((item) => item.dataTypes))],
      severity,
      validationState: validationStateValue,
      evidenceIds: [...new Set(observations.map((item) => item.id))],
      sourceTypes: [...new Set(observations.map((item) => item.sourceType))],
      sourceLocations: [...new Set(observations.map((item) => item.sourceLocation).filter((value): value is string => Boolean(value)))],
      observedAt,
      observations,
    }
  }).sort((left, right) => {
    const state = STATE_PRIORITY[right.validationState] - STATE_PRIORITY[left.validationState]
    if (state) return state
    const severity = (SEVERITY_PRIORITY[right.severity] || 0) - (SEVERITY_PRIORITY[left.severity] || 0)
    return severity || (right.observedAt || 0) - (left.observedAt || 0)
  })
}
