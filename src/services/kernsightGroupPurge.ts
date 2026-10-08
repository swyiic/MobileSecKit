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

/** Explain every disabled confirmation without replacing backend authorization. */
export function purgeConfirmationBlockReason(plan: KernSightGroupPurgePlan | null, target: PurgeTarget | null, now: number, state: { active: boolean; busy: boolean; preparing: boolean; executing: boolean }): string {
  if (state.executing) return '正在执行清理并核验结果，请勿重复操作。'
  if (!state.active) return '当前页面未激活；返回此页面后会自动核对清理范围。'
  if (state.busy) return '采集、拉取、导入或归属核对尚未结束；结束后自动核对清理范围。'
  if (state.preparing) return '正在自动核对文件、设备身份与会话归属；大会话可能需要约 2 分钟，完成后才可确认删除。'
  if (!plan) return '尚无有效清理范围；请点击“重新核对并重试”。'
  if (!target || !purgePlanMatches(plan, target)) return '预览身份与此主会话不一致；未执行删除，请重新核对。'
  if (!plan.confirmationToken) return '此次确认凭证已失效；未执行删除，请重新核对。'
  if (!Number.isFinite(plan.createdUnixMs) || !Number.isFinite(plan.expiresUnixMs) || plan.expiresUnixMs <= plan.createdUnixMs || plan.expiresUnixMs - plan.createdUnixMs > 300_000) return '清理预览期限无效；未执行删除，请重新核对。'
  if (now < plan.createdUnixMs) return '清理预览时间晚于本机时钟；未执行删除，请核对系统时间后重试。'
  if (now >= plan.expiresUnixMs) return '清理预览已失效；未执行删除，请重新核对。'
  if (!plan.localOnly && !['ready', 'not_required'].includes(plan.device?.status || '')) return `手机范围未通过安全核对（${plan.device?.status || '未知状态'}）；未执行删除。${plan.device?.warnings?.join('；') || '请连接原设备后重新核对。'}`
  return ''
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
