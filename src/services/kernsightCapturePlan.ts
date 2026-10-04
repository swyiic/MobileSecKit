import type { KernSightCaptureRequest, KernSightCaptureResult } from '../types/monitoring'

export interface AutoCaptureStage {
  key: 'l0' | 'l1' | 'linker' | 'dump' | 'session'
  label: string
  durationSeconds?: number
  launchAfterAttach: boolean
}

export interface AutoStageReceipt {
  stage: AutoCaptureStage
  result: KernSightCaptureResult
  succeeded: boolean
}

export function buildAutoCaptureStages(l0: number, l1: number, linker: number, startupReplay = false): AutoCaptureStage[] {
  if (![l0, l1, linker].every(n => Number.isInteger(n) && n >= 1 && n <= 300)) {
    throw new Error('每阶段时长必须是 1–300 秒的整数')
  }
  if (startupReplay) return [
    { key: 'l0', label: `L0 ${l0}s · 启动重采 1/3`, durationSeconds: l0, launchAfterAttach: true },
    { key: 'l1', label: `L1 ${l1}s · 启动重采 2/3`, durationSeconds: l1, launchAfterAttach: true },
    { key: 'dump', label: 'L1 进程驻留快照（后续 Linker 会重启）', launchAfterAttach: false },
    { key: 'linker', label: `Linker ${linker}s · 启动重采 3/3`, durationSeconds: linker, launchAfterAttach: true },
  ]
  return [
    { key: 'l0', label: `L0 主干 ${l0}s · 首次冷启动`, durationSeconds: l0, launchAfterAttach: true },
    { key: 'l1', label: `L0+L1 ${l1}s · 继续当前 App`, durationSeconds: l1, launchAfterAttach: false },
    { key: 'linker', label: `Linker ${linker}s · 观察后续加载`, durationSeconds: linker, launchAfterAttach: false },
    { key: 'dump', label: 'L2 dump · 最终驻留快照', launchAfterAttach: false },
  ]
}

interface Backend {
  startKernSightCapture(request: KernSightCaptureRequest): Promise<KernSightCaptureResult>
  dumpKernSightPackage(serial: string, packageName: string, hideDebug: boolean, preferLive: boolean, requireLive: boolean): Promise<KernSightCaptureResult>
}

/** Sequential production orchestration, also exercised with an offline backend.
 * Warm stages preserve accumulated loaded code. They do not attest one process
 * instance across stages, or recover a module that already unloaded.
 */
export async function runAutoCapturePlan(
  base: KernSightCaptureRequest,
  durations: { l0: number; l1: number; linker: number },
  backend: Backend,
  onStart: (stage: AutoCaptureStage) => void,
  onResult: (receipt: AutoStageReceipt) => void,
  startupReplay = false,
): Promise<AutoStageReceipt[]> {
  const stages = buildAutoCaptureStages(durations.l0, durations.l1, durations.linker, startupReplay)
  const packageName = base.package?.trim()
  if (!packageName || !/^[A-Za-z0-9._]+$/.test(packageName)) throw new Error('连续采集必须选择有效包名')
  if (!base.serial.trim()) throw new Error('连续采集缺少设备标识')
  const receipts: AutoStageReceipt[] = []
  for (const stage of stages) {
    onStart(stage)
    const result = stage.key === 'dump'
      ? await backend.dumpKernSightPackage(base.serial, packageName, base.hideDebug, true, true)
      : await backend.startKernSightCapture({
        ...base,
        package: packageName,
        durationSeconds: stage.durationSeconds!,
        launchAfterAttach: stage.launchAfterAttach,
        inspectTls: stage.key === 'l1',
        inspectJni: stage.key === 'l1',
        inspectLinker: stage.key === 'linker',
        inspectAdapter: stage.key === 'l1' ? 'binder_userspace' : null,
      })
    const receipt = { stage, result, succeeded: result.exitCode === 0 }
    receipts.push(receipt)
    onResult(receipt)
    if (!receipt.succeeded) {
      throw new Error(`${stage.label}未确认成功（退出码 ${result.exitCode ?? '未知'}）；停止后续阶段，已返回的会话与日志保留供核对`)
    }
  }
  return receipts
}

export function buildUnifiedStageSpec(durations: { l0: number; l1: number; linker: number }): string {
  return buildAutoCaptureStages(durations.l0, durations.l1, durations.linker).filter(s => s.key !== 'dump')
    .map(s => `${s.key}:${s.durationSeconds}`).join(',')
}

/** Agent-reported boundaries are evidence, not an assertion of complete capture. */
export async function runUnifiedCapturePlan(
  base: KernSightCaptureRequest,
  durations: { l0: number; l1: number; linker: number },
  backend: Backend,
  onStart: (stage: AutoCaptureStage) => void,
  onResult: (receipt: AutoStageReceipt) => void,
  _startupReplay?: boolean,
): Promise<void> {
  const spec = buildUnifiedStageSpec(durations)
  const packageName = base.package?.trim()
  if (!packageName || !/^[A-Za-z0-9._]+$/.test(packageName) || !base.serial.trim()) throw new Error('统一阶段必须选择有效设备和包名')
  const overall: AutoCaptureStage = { key: 'session', label: '统一 session · 实际阶段以 agent 记录为准', launchAfterAttach: true }
  onStart(overall)
  const result = await backend.startKernSightCapture({ ...base, package: packageName,
    durationSeconds: durations.l0 + durations.l1 + durations.linker, launchAfterAttach: true,
    inspectTls: false, inspectJni: false, inspectLinker: false, inspectAdapter: null, inspectStages: spec })
  onResult({ stage: overall, result, succeeded: result.exitCode === 0 })
  const records = [result.stdout, result.stderr].join('\n').split('\n').flatMap(line => {
    try { const value = JSON.parse(line); return value.schema === 'kernsight.capture-stage/v1' ? [value] : [] } catch { return [] }
  })
  const phases = buildAutoCaptureStages(durations.l0, durations.l1, durations.linker).filter(s => s.key !== 'dump')
  let complete = result.exitCode === 0 && Boolean(result.sessionId)
  let identity: string | undefined
  for (const [index, stage] of phases.entries()) {
    const rows = records.filter(row => row.index === index && row.stage === stage.key && row.session === result.sessionId)
    const end = rows.filter(row => row.state !== 'started')
    const terminal = end[0]
    const currentIdentity = terminal && Number.isInteger(terminal.pid) && terminal.pid > 0
      && typeof terminal.process_start_ticks === 'string' && /^[1-9][0-9]*$/.test(terminal.process_start_ticks)
      ? `${terminal.pid}:${terminal.process_start_ticks}` : undefined
    const succeeded = rows.length === 2 && rows[0]?.state === 'started' && end.length === 1
      && terminal?.state === 'window_elapsed' && terminal.planned_seconds === stage.durationSeconds
      && currentIdentity !== undefined && (!identity || identity === currentIdentity)
    if (!identity && currentIdentity) identity = currentIdentity
    complete &&= succeeded
    onResult({ stage: { ...stage, label: `${stage.label} · agent=${terminal?.state || 'missing'} · ${terminal?.observation_state || '观测状态未知'} · ${terminal?.stage_elapsed_ms ?? '未知'}ms`, launchAfterAttach: false }, result: { ...result,
      stdout: rows.map(row => JSON.stringify(row)).join('\n'), stderr: '', commandPreview: `${stage.key} (one session; no restart)` }, succeeded })
  }
  if (!complete) throw new Error('统一采集未确认全部阶段完成或同一主进程；保留 session 与阶段证据，停止最终快照，不降级重启')
  const dump: AutoCaptureStage = { key: 'dump', label: '统一采集后的驻留快照', launchAfterAttach: false }
  onStart(dump)
  const snapshot = await backend.dumpKernSightPackage(base.serial, packageName, base.hideDebug, true, true)
  onResult({ stage: dump, result: snapshot, succeeded: snapshot.exitCode === 0 })
  if (snapshot.exitCode !== 0) throw new Error('最终快照失败/未知，采集 session 保留')
}

export function captureIPCCommand(request: KernSightCaptureRequest): string {
  return request.inspectStages ? "start_kernsight_staged_capture" : "start_kernsight_capture"
}
