import type { KernSightCaptureGroup, KernSightCaptureResult, KernSightGroupStageResult } from '../types/monitoring'

type Backend = {
  runKernSightGroupStage(id: string, key: string): Promise<KernSightGroupStageResult>
  runKernSightUnifiedGroup(id: string): Promise<KernSightGroupStageResult>
}
type Hooks = {
  group(group: KernSightCaptureGroup): void
  phase(key: string): void
  result(result: KernSightCaptureResult, key: string, group: KernSightCaptureGroup): void
  unified(active: boolean): void
}

/** One durable parent owns all attempts. Only the backend can authorize a
 * settled partial to continue; a missing/failed lifecycle is never success. */
export async function runCaptureGroupPlan(initial: KernSightCaptureGroup, backend: Backend, hooks: Hooks): Promise<KernSightCaptureGroup> {
  let group = initial
  hooks.group(group)
  const accept = (reply: KernSightGroupStageResult, key: string) => {
    if (reply.group.id !== initial.id) throw new Error('采集返回了不同的主会话，停止后续阶段')
    group = reply.group
    hooks.group(group)
    if (reply.result) hooks.result(reply.result, key, group)
    if (group.cancelRequested) return
    const latest = group.stages.find(stage => stage.key === key)
    const state = latest?.attempts[latest.attempts.length - 1]?.state
    const next = group.stages[group.stages.findIndex(stage => stage.key === key) + 1]
    const allowedPartial = key !== 'session' && (state === 'partial' || state === 'unavailable') && reply.continueAfterPartial === true
      && ((next?.key === 'dump' && reply.continuationPolicy === 'sealed_partial_snapshot')
        || (next?.launchAfterAttach === true && (state !== 'unavailable' || reply.continuationPolicy === 'source_absent_independent_start')))
    if (reply.error && !allowedPartial) throw new Error(reply.error)
    if (key !== 'session' && state !== 'succeeded' && !allowedPartial) {
      throw new Error(`${captureStageLabel(key)}执行状态未确认成功，停止后续阶段并保留已返回证据`)
    }
  }
  if (group.cancelRequested) return group
  if (group.unified && group.stages.filter(stage => stage.key !== 'dump').some(stage => stage.attempts[stage.attempts.length - 1]?.state !== 'succeeded')) {
    hooks.phase('session')
    hooks.unified(true)
    try { accept(await backend.runKernSightUnifiedGroup(group.id), 'session') }
    finally { hooks.unified(false) }
    if (group.cancelRequested) return group
  }
  // Read each stage from the newest receipt, including updates from unified capture.
  for (const key of group.stages.map(stage => stage.key)) {
    if (group.cancelRequested) break
    const stage = group.stages.find(item => item.key === key)!
    if (stage.attempts[stage.attempts.length - 1]?.state === 'succeeded') continue
    if (group.unified && key !== 'dump') throw new Error('统一采集未确认所有阶段成功，保留已有证据并停止快照')
    hooks.phase(key)
    accept(await backend.runKernSightGroupStage(group.id, key), key)
  }
  return group
}

/** Dump has no session ID: preserve the most recent actual child, never erase it. */
export function mergeCaptureResults(parts: KernSightCaptureResult[]): KernSightCaptureResult | null {
  if (!parts.length) return null
  const last = parts[parts.length - 1]!
  return {
    ...last,
    sessionId: [...parts].reverse().find(part => part.sessionId)?.sessionId,
    startedUnixMs: parts[0]!.startedUnixMs,
    commandPreview: parts.map(part => part.commandPreview).filter(Boolean).join('\n\n'),
    stdout: parts.map(part => part.stdout).filter(Boolean).join('\n\n'),
    stderr: parts.map(part => part.stderr).filter(Boolean).join('\n\n'),
  }
}

export function latestGroupSession(group: KernSightCaptureGroup): string | undefined {
  return [...group.stages].reverse().flatMap(stage => [...stage.attempts].reverse()).find(attempt => attempt.sessionId)?.sessionId || undefined
}
export function captureStageLabel(key: string): string {
  return ({ l0: 'L0 内核观察', l1: 'L1 TLS / JNI / Binder', dump: 'L2 代码快照', linker: 'Linker 加载观察', session: '统一阶段会话' } as Record<string, string>)[key] || key
}
export function captureStateLabel(state: string): string {
  return ({ planned: '待执行', running: '采集中', succeeded: '执行结束', partial: '覆盖不足（partial）', failed: '采集失败', interrupted: '已中断', unavailable: '来源不可用（未启动）', cancelled: '已取消', canceled: '已取消' } as Record<string, string>)[state] || state
}

const exportReservation = new Set(['transfer', 'archive', 'import', 'terminal'])

/** Stage success is not a coverage gap. A later save reservation can still be open. */
export function captureGroupStateLabel(group: KernSightCaptureGroup): string {
  const required = group.stages.filter(stage => stage.required)
  const stagesDone = required.length > 0 && required.every(stage => stage.attempts[stage.attempts.length - 1]?.state === 'succeeded')
  const reservations = group.budget?.reservations ?? []
  const capturePartial = reservations.some(item => item.status === 'partial' && !exportReservation.has(item.kind))
  if (group.state === 'partial' && stagesDone && !capturePartial) {
    const saveOpen = ['transfer', 'archive', 'import'].some(kind => {
      const rows = reservations.filter(item => item.kind === kind)
      return rows.some(item => item.status === 'partial') && !rows.some(item => item.status === 'admitted_plus_terminal_reserve')
    })
    return saveOpen ? '采集已结束，保存未完成' : '执行结束'
  }
  return captureStateLabel(group.state)
}

/** Display durable stage facts without inferring whether later stages ran. */
export function captureReceiptStateLabel(group: KernSightCaptureGroup, key: string): string {
  const stages = key === 'session' ? group.stages.filter(stage => stage.key !== 'dump')
    : group.stages.filter(stage => stage.key === key)
  if (!stages.length) return '状态未知'
  return stages.map(stage => {
    const state = stage.attempts[stage.attempts.length - 1]?.state
    const label = state ? captureStateLabel(state) : '状态未知'
    return key === 'session' ? `${captureStageLabel(stage.key)}：${label}` : label
  }).join(' · ')
}

/** Saved evidence is usable independently of the source coverage; no state upgrade. */
export function captureSavedOutcome(group: KernSightCaptureGroup, root: string): string {
  return `本次主会话证据已保存并导入：${root}；${captureGroupStateLabel(group)}`
}
