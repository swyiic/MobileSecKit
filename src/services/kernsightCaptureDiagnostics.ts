import type { KernSightCaptureAttempt, KernSightCaptureGroup, KernSightCaptureRelation } from '../types/monitoring'

type JsonRecord = Record<string, unknown>
type FailureReceipt = { record: JsonRecord; failure: JsonRecord; source: 'remote_lifecycle' | 'stderr' | 'stdout'; trusted: boolean }
export interface CaptureDiagnosticView {
  visible: boolean
  cause: string | null
  primary: 'structured' | 'excerpt' | 'missing'
  sourceLabel: string
  scopeLabel: string
  kind: string | null
  errno: string | null
  expected: string | null
  observed: string | null
  producerExitLabel: string
  targetExitLabel: string
  warnings: string[]
  byteLabel: string | null
  rawTail: string | null
}

function object(value: unknown): JsonRecord | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as JsonRecord : null
}
function text(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null
}
function display(value: unknown): string | null {
  return value == null ? null : typeof value === 'string' ? value : JSON.stringify(value, null, 2)
}
function relation(value: unknown): KernSightCaptureRelation | null {
  const r = object(value)
  if (!r || !text(r.parent_id) || !text(r.stage_id) || !text(r.attempt_id) || !text(r.stage_key)
    || !Number.isInteger(r.attempt) || Number(r.attempt) < 1) return null
  return { parentId: String(r.parent_id), stageId: String(r.stage_id), attemptId: String(r.attempt_id), stageKey: String(r.stage_key), attempt: Number(r.attempt) }
}
function sameRelation(a: KernSightCaptureRelation | null, b: KernSightCaptureRelation | null): boolean {
  return Boolean(a && b && a.parentId === b.parentId && a.stageId === b.stageId
    && a.attemptId === b.attemptId && a.stageKey === b.stageKey && a.attempt === b.attempt)
}

function validLifecycleToken(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
    && value !== '00000000-0000-0000-0000-000000000000'
}

/** A unified lifecycle describes its L0 controller, not each individual stage. */
function lifecycleScope(group: KernSightCaptureGroup, attempt: KernSightCaptureAttempt): 'attempt' | 'controller' | null {
  const note = object(attempt.remoteLifecycle), controller = relation(note?.relation)
  if (note?.schema !== 'kernsight.capture-lifecycle/v1' || !validLifecycleToken(note.token)
    || !controller || controller.parentId !== group.id || attempt.relation.parentId !== group.id) return null
  if (sameRelation(controller, attempt.relation)) return group.unified === true && controller.stageKey === 'l0' ? 'controller' : 'attempt'
  if (group.unified === true && controller.stageKey === 'l0' && ['l1', 'linker'].includes(attempt.relation.stageKey)
    && controller.attempt === attempt.relation.attempt
    && group.stages.some(stage => stage.key === 'l0' && stage.attempts.some(a => sameRelation(controller, a.relation)))) return 'controller'
  return null
}
function failureRecord(value: unknown): { record: JsonRecord; failure: JsonRecord } | null {
  const record = object(value), failure = object(record?.failure)
  return record?.schema === 'kernsight.qualified-source-failure/v1' && failure
    && typeof failure.kind === 'string' && typeof failure.cause === 'string' ? { record, failure } : null
}
function sameJson(a: unknown, b: unknown): boolean {
  if (a === b) return true
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((value, index) => sameJson(value, b[index]))
  const left = object(a), right = object(b)
  return Boolean(left && right && Object.keys(left).length === Object.keys(right).length
    && Object.keys(left).every(key => Object.prototype.hasOwnProperty.call(right, key) && sameJson(left[key], right[key])))
}
function matchingReceipt(value: unknown, note: JsonRecord | null, scope: string | null): ReturnType<typeof failureRecord> {
  const receipt = failureRecord(value)
  return receipt && scope && validLifecycleToken(receipt.record.token) && receipt.record.token === note?.token
    && sameRelation(relation(receipt.record.relation), relation(note?.relation))
    && sameJson(receipt.record.relation, note?.relation) ? receipt : null
}
function boolLabel(value: unknown): string {
  return value === true ? '已确认退出' : value === false ? '未确认退出（false）' : '未知（缺少确认）'
}

/** Presentation only: diagnostics never authorize continuation or upgrade capture state. */
export function captureAttemptDiagnostics(group: KernSightCaptureGroup, attempt: KernSightCaptureAttempt): CaptureDiagnosticView {
  const note = object(attempt.remoteLifecycle)
  const diagnostic = attempt.captureDiagnostic?.schema === 'mobilee.capture-diagnostic/v1' ? attempt.captureDiagnostic : null
  const scope = lifecycleScope(group, attempt)
  const savedReceipt = matchingReceipt(note?.qualification_failure, note, scope)
  const retainedReceipt = diagnostic?.source === 'remote_lifecycle' ? matchingReceipt(diagnostic.record, note, scope) : null
  let receipt: FailureReceipt | null = retainedReceipt ? { ...retainedReceipt, source: 'remote_lifecycle', trusted: true }
    : savedReceipt ? { ...savedReceipt, source: 'remote_lifecycle', trusted: true } : null
  if (!receipt && (diagnostic?.source === 'stderr' || diagnostic?.source === 'stdout')) {
    const outputReceipt = failureRecord(diagnostic.record)
    if (outputReceipt) receipt = { ...outputReceipt, source: diagnostic.source, trusted: false }
  }
  const excerpt = text(diagnostic?.errorExcerpt)
  const cause = text(receipt?.failure.cause) || excerpt
  const primary = text(receipt?.failure.cause) ? 'structured' : excerpt ? 'excerpt' : 'missing'
  const warnings: string[] = []
  const rawTail = text(attempt.diagnosticTail)
  const rawTailTruncated = diagnostic?.rawTailTruncated === true || /\[(?:stderr|stdout) tail; earlier output omitted\]/.test(rawTail || '')
  if ((note?.qualification_failure != null && !savedReceipt) || (diagnostic?.source === 'remote_lifecycle' && diagnostic.record != null && !retainedReceipt)) {
    warnings.push('结构化失败回执格式无效，或身份未匹配当前生命周期、token 与父会话；未将其用作本次失败原因，原记录保留在诊断 JSON 中。')
  }
  if (receipt && !receipt.trusted) warnings.push(`${receipt.source} 中的结构化记录仅作诊断输出；未核验为生命周期回执，不能确认目标退出或继续采集。`)
  if (receipt?.record.cause_truncated === true || receipt?.failure.cause_truncated === true) warnings.push('结构化失败原因已截断；这里只展示已留存部分。')
  if (diagnostic?.structuredRecordOmitted === true) warnings.push('部分结构化候选未被选作摘要（可能超出大小限制、格式无效或生命周期身份不匹配）；请检查错误摘要、原始尾部及已留存诊断 JSON。')
  if (diagnostic?.errorExcerptTruncated === true) warnings.push('错误摘要已截断；这里只展示已留存部分。')
  if (rawTailTruncated) warnings.push('原始输出尾部已截断，较早输出已省略；复制诊断 JSON 也无法恢复未留存内容。')
  if (!diagnostic) {
    warnings.push(receipt ? '本记录未保存独立错误摘要或输出字节数；以下仅为当前已留存信息。'
      : '本记录未保存可核验的结构化原因或独立错误摘要。可检查已留存尾部；缺失原因无法从本记录恢复，需在后续采集中重新记录。')
  } else if (!cause) warnings.push('本次记录没有可用的结构化原因或错误摘要；请检查原始输出尾部与已留存诊断 JSON。')
  const hasDiagnostic = Boolean(diagnostic || rawTail || note?.qualification_failure || attempt.error
    || ['failed', 'partial', 'interrupted', 'cancelled'].includes(attempt.state))
  const sourceLabel = primary === 'structured' ? receipt?.trusted ? '已匹配生命周期失败回执' : `${receipt?.source} 结构化诊断输出`
    : primary === 'excerpt' ? '错误摘要（诊断输出）' : '失败原因未留存 / 未确认'
  const bytes = (value: unknown) => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? `${value} B` : '未知'
  const byteLabel = diagnostic ? `原始输出计数：stdout ${bytes(diagnostic.stdoutBytes)} · stderr ${bytes(diagnostic.stderrBytes)}（不代表全部输出已留存）` : null
  return {
    visible: hasDiagnostic, cause, primary, sourceLabel,
    scopeLabel: scope === 'controller' ? `统一采集控制器回执 · ${relation(note?.relation)?.stageKey} · attempt ${relation(note?.relation)?.attempt}；不是本阶段独立回执` : '',
    kind: display(receipt?.failure.kind), errno: display(receipt?.failure.errno),
    expected: display(receipt?.failure.expected), observed: display(receipt?.failure.observed),
    producerExitLabel: `采集生产者：${boolLabel(scope ? note?.agent_exited_confirmed : null)}`,
    targetExitLabel: `目标进程：${boolLabel(receipt?.trusted ? receipt.failure.target_exit_confirmed : null)}`,
    warnings, byteLabel, rawTail,
  }
}

/** Serialize every retained attempt field. This is not the original stdout/stderr. */
export function retainedStageDiagnosticsJson(group: KernSightCaptureGroup, attempt: KernSightCaptureAttempt): string {
  const stage = group.stages.find(stage => stage.id === attempt.relation.stageId)
  return JSON.stringify({
    schema: 'mobilee.retained-stage-diagnostics/v1',
    retentionScope: 'Complete retained attempt diagnostics; not complete original stdout/stderr. Missing or truncated content cannot be recovered from this JSON.',
    group: { id: group.id, serial: group.serial, package: group.package, state: group.state, unified: group.unified ?? false },
    stage: stage ? { id: stage.id, key: stage.key, mode: stage.mode, durationSeconds: stage.durationSeconds, launchAfterAttach: stage.launchAfterAttach, required: stage.required } : null,
    attempt: { ...attempt, captureDiagnostic: attempt.captureDiagnostic ?? null, remoteLifecycle: attempt.remoteLifecycle ?? null, diagnosticTail: attempt.diagnosticTail ?? null },
  }, null, 2)
}

export async function copyRetainedStageDiagnostics(json: string, clipboard?: Pick<Clipboard, 'writeText'> | null): Promise<{ ok: boolean; message: string }> {
  try {
    const target = clipboard === undefined ? globalThis.navigator?.clipboard : clipboard
    if (!target?.writeText) throw new Error('剪贴板不可用')
    await target.writeText(json)
    return { ok: true, message: '已复制全部已留存阶段诊断 JSON（不含未留存输出）' }
  } catch {
    return { ok: false, message: '复制失败，剪贴板不可用或访问被拒绝。请展开“已留存诊断 JSON”手动复制。' }
  }
}
