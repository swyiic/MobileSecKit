import type { KernSightGroupPurgePlan, KernSightGroupPurgeReport, KernSightLocalEvidenceBundle } from '../types/monitoring'

export interface PurgeTarget {
  parentId: string
  serial: string
  package: string
  importedRoots: string[]
  retryPlanId?: string
}

export function purgeTargetKey(target: PurgeTarget): string {
  return JSON.stringify([target.parentId, target.serial, target.package, [...target.importedRoots].sort(), target.retryPlanId || ''])
}

export function purgePlanMatches(plan: KernSightGroupPurgePlan, target: PurgeTarget): boolean {
  return plan.parentId === target.parentId && plan.serial === target.serial && plan.package === target.package
}

/** UI defense in depth. The backend independently validates the stored plan and its token. */
export function canConfirmPurge(plan: KernSightGroupPurgePlan | null, target: PurgeTarget | null, now: number, busy = false): boolean {
  return Boolean(plan && target && !busy
    && purgePlanMatches(plan, target) && plan.confirmationToken
    && Number.isFinite(plan.createdUnixMs) && Number.isFinite(plan.expiresUnixMs)
    && plan.createdUnixMs <= now && now < plan.expiresUnixMs
    && plan.expiresUnixMs - plan.createdUnixMs <= 300_000
    && (plan.localOnly || plan.device?.status === 'ready' || plan.device?.status === 'not_required'))
}

/** Invalidate every pending preview when its selection is cancelled or superseded. */
export function createPurgeRequestGate() {
  let generation = 0
  let executing = false
  return {
    begin: () => ++generation,
    invalidate: () => { generation += 1 },
    current: (ticket: number) => ticket === generation,
    startExecution: () => { if (executing) return false; executing = true; return true },
    finishExecution: () => { executing = false },
    executing: () => executing,
  }
}

export function purgeReportLabel(report: KernSightGroupPurgeReport): string {
  if (report.state === 'completed' && report.localState === 'completed' && ['completed', 'not_required'].includes(report.deviceState)) return '本地与设备清理已核验完成'
  if (report.localState === 'completed' && !['completed', 'not_required'].includes(report.deviceState)) return '本地清理已核验；设备待清理'
  if (report.deviceState === 'completed' && report.localState !== 'completed') return '设备清理已核验；本地待清理'
  if (report.state === 'prepared') return '仅预览，尚未执行'
  return '清理未完成；请核对两端状态'
}

/** Never remove all copies or another capture just because the package name matches. */
export function bundleRemovedByPurge(bundle: KernSightLocalEvidenceBundle, plan: KernSightGroupPurgePlan, report: KernSightGroupPurgeReport): boolean {
  const group = bundle.sessionReport?.mobilee_capture_group as {id?: string; serial?: string; package?: string} | undefined
  return report.localState === 'completed' && report.parentId === plan.parentId && report.serial === plan.serial && report.package === plan.package
    && group?.id === plan.parentId && group.serial === plan.serial && group.package === plan.package
    && report.importedRoots.includes(bundle.root)
}
