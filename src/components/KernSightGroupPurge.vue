<template>
  <section ref="dialog" class="ks-purge-dialog" role="dialog" tabindex="-1" aria-labelledby="ks-purge-title" aria-describedby="ks-purge-warning" @keydown.esc.prevent="close">
    <header><div><h3 id="ks-purge-title">{{ target.retryPlanId ? '重新预览未完成的永久清理' : '永久清理主会话' }}</h3><p id="ks-purge-warning">删除后无法恢复，不进入回收站。系统自动核验会话归属、活跃依赖与手机配对。</p></div></header>
    <dl class="ks-purge-identity"><dt>父会话 ID</dt><dd>{{ target.parentId }}</dd><dt>设备序列号</dt><dd>{{ target.serial }}</dd><dt>目标包</dt><dd>{{ target.package }}</dd></dl>
    <p class="ks-purge-warning">是否永久删除此主会话在本机和配对手机上的所属证据？删除无法恢复，不进入回收站。系统自动核对范围；共享文件与其他会话不纳入删除。</p>
    <p v-if="resumeAuthorized" class="ks-purge-warning">此清理已确认；继续仅处理原授权清单的剩余路径，不扩展范围。</p>
    <div class="ks-purge-confirm"><button class="ghost-button danger-button" :disabled="!canExecute" :title="blockedReason || '确认永久删除该会话本地与手机所属证据'" aria-describedby="ks-purge-block-reason" @click="execute">{{ executing ? '正在清理并核验…' : preparing ? '正在核对，完成后可确认' : resumeAuthorized ? '继续已确认清理' : '是，永久删除本地与手机' }}</button><button class="ghost-button" :disabled="executing" @click="close">否</button></div>
    <button v-if="preparing || executing" class="ghost-button" :disabled="cancelling" @click="stopCurrent">{{ cancelling ? '正在停止并核对…' : executing ? '停止清理并保留记录' : '取消范围核对' }}</button>
    <p v-if="blockedReason" id="ks-purge-block-reason" class="ks-purge-error" role="status" data-testid="purge-block-reason">{{ blockedReason }}</p>
    <button class="ghost-button" :disabled="preparing || executing || cancelling || busy || !active" @click="prepare">{{ preparing ? '正在核对…' : '重新核对并重试' }}</button>
    <div v-if="error" class="ks-purge-error" role="alert"><p>{{ error }}</p><details><summary>可复制错误详情</summary><textarea readonly :value="error" aria-label="清理错误详情" /></details></div>
    <div v-if="plan" class="ks-purge-preview" data-testid="purge-preview">
      <p v-if="!resumeAuthorized">预览时间 {{ formatTime(plan.createdUnixMs) }} · 失效时间 {{ formatTime(plan.expiresUnixMs) }}（5 分钟内有效）</p>
      <p v-if="expired && !resumeAuthorized" class="ks-purge-error" role="alert">预览已失效。请重新核对范围，之前的确认已作废。</p>
      <p><strong>本地：{{ plan.localEntries.length }} 条精确路径 · {{ countFiles(plan.localEntries) }} 个文件</strong></p>
      <details><summary>查看系统核验的路径</summary><ul class="ks-purge-paths"><li v-for="entry in plan.localEntries" :key="entry.path"><code>{{ entry.path }}</code><span>{{ entry.kind }} · {{ entry.files }} 文件 · 逻辑大小 {{ bytes(entry.logicalBytes) }} · 实际分配 {{ bytes(entry.allocatedBytes) }}</span></li></ul></details>
      <p v-if="!plan.localEntries.length">本次没有待删除的本地路径。</p>
      <p><strong>手机：{{ deviceLabel }} · {{ plan.device?.entries.length ?? 0 }} 条精确路径 · {{ countFiles(plan.device?.entries || []) }} 个文件</strong></p>
      <details><summary>查看系统核验的路径</summary><ul class="ks-purge-paths"><li v-for="entry in plan.device?.entries || []" :key="entry.path"><code>{{ entry.path }}</code><span>{{ entry.kind }} · {{ entry.files }} 文件 · 逻辑大小 {{ bytes(entry.logicalBytes) }} · 实际分配 {{ bytes(entry.allocatedBytes) }}</span></li></ul></details>
      <p v-if="!deviceReady && !resumeAuthorized" class="ks-purge-error" role="alert">手机离线或安全核对未通过，未执行删除。请重连原设备后点击“重新核对并重试”。</p>
      <ul v-if="warnings.length" class="ks-purge-warning"><li v-for="warning in warnings" :key="warning">{{ warning }}</li></ul>
      <p>以上是待删除文件的占用统计，不是已释放空间。删除结果以执行后的逐端核验为准。</p>
      <p v-if="executing" role="status">已提交本次确认，正在清理并分别核验。请勿重复操作；结果会保留在清理记录中。</p>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import { monitoringBackend, readableError } from '@/services/backend'
import { canConfirmPurge, createPurgeRequestGate, purgePlanMatches, purgeTargetKey, purgeConfirmationBlockReason, createPurgeOperation, type PurgeTarget } from '@/services/kernsightGroupPurge'
import type { KernSightGroupPurgeEntry, KernSightGroupPurgePlan, KernSightGroupPurgeReport } from '@/types/monitoring'
const props = defineProps<{ target: PurgeTarget; busy: boolean; active: boolean; operationTimeouts?: { prepareMs: number; executeMs: number; stopMs: number } }>()
const emit = defineEmits<{ close: []; uncertain: []; executing: [value: boolean]; complete: [report: KernSightGroupPurgeReport, plan: KernSightGroupPurgePlan] }>()
const dialog = ref<HTMLElement | null>(null)
onMounted(() => { void nextTick(() => { dialog.value?.focus(); dialog.value?.scrollIntoView({ block: 'start' }) }) })
const plan = shallowRef<KernSightGroupPurgePlan | null>(null)
const failedPlanId = ref('')
const preparing = ref(false)
const executing = ref(false)
const error = ref('')
const cancelling = ref(false)
const resumeAuthorized = ref(false)
let mounted = true
let preparation: ReturnType<typeof createPurgeOperation<KernSightGroupPurgePlan | null>> | null = null
let execution: ReturnType<typeof createPurgeOperation<KernSightGroupPurgeReport>> | null = null
const timeouts = () => props.operationTimeouts || { prepareMs: 30_000, executeMs: 40_000, stopMs: 10_000 }
const now = ref(Date.now())
const gate = createPurgeRequestGate()
const clock = setInterval(() => { now.value = Date.now() }, 250)
const expired = computed(() => Boolean(plan.value && now.value >= plan.value.expiresUnixMs))
const deviceReady = computed(() => ['ready', 'not_required'].includes(plan.value?.device?.status || ''))
const blockedReason = computed(() => {
  if (cancelling.value) return '正在请求后台停止并核对持久结果，请勿重复操作。'
  const state = { active: props.active, busy: props.busy, preparing: preparing.value, executing: executing.value }
  if (resumeAuthorized.value && plan.value && purgePlanMatches(plan.value, props.target)) {
    if (state.executing) return '正在继续原授权清理，请勿重复操作。'
    if (!state.active) return '当前页面未激活。'
    if (state.busy || state.preparing) return '正在核对原清理状态，请稍候。'
    return ''
  }
  return purgeConfirmationBlockReason(plan.value, props.target, now.value, state)
})
const canExecute = computed(() => props.active && !props.busy && !preparing.value && !executing.value && !cancelling.value
  && (resumeAuthorized.value ? Boolean(plan.value && purgePlanMatches(plan.value, props.target)) : canConfirmPurge(plan.value, props.target, now.value)))
const warnings = computed(() => [...new Set([...(plan.value?.warnings || []), ...(plan.value?.device?.warnings || [])])])
const deviceLabel = computed(() => ({ ready: '范围已核验', offline: '离线 / 不可达', blocked: '范围核验被阻止', not_required: '无待清理路径' })[plan.value?.device?.status || 'offline'])
const formatTime = (value: number) => new Date(value).toLocaleString()
const countFiles = (entries: KernSightGroupPurgeEntry[]) => entries.reduce((sum, entry) => sum + entry.files, 0)
function bytes(value: number | null) { return value == null ? '未知' : `${value.toLocaleString()} B` }
function invalidatePlan() {
  gate.invalidate()
  plan.value = null
  preparing.value = false
  error.value = ''
}
function close() { if (executing.value || cancelling.value) return; void preparation?.cancel('user').catch(() => {}); invalidatePlan(); emit('close') }
watch(() => purgeTargetKey(props.target), () => {
  // The parent may persist retryPlanId while reconciling this same owned execution.
  if (executing.value && plan.value && purgePlanMatches(plan.value, props.target)) return
  invalidatePlan()
  failedPlanId.value = ''
  resumeAuthorized.value = false
  if (preparation) void preparation.cancel('superseded').catch(() => {}).finally(() => { if (mounted) { preparing.value = false; void nextTick(prepare) } })
  else void nextTick(prepare)
}, { immediate: true, flush: 'sync' })
watch(() => [props.active, props.busy] as const, ([active, busy]) => {
  if (executing.value) return
  if (!active || busy) {
    // Invalidate an in-flight preview without silently dismissing its confirmation.
    gate.invalidate()
    plan.value = null
    void preparation?.cancel('superseded').catch(() => {})
    preparing.value = false
  } else if (!plan.value) {
    void nextTick(prepare)
  }
}, { flush: 'sync' })

async function boundedStop<T>(work: Promise<T>, deadline = Date.now() + timeouts().stopMs): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try { return await new Promise<T>((resolve, reject) => {
    timer = setTimeout(() => reject(new Error('停止确认超过期限；后台状态未知，原清理日志保留，请刷新核对后重试')), Math.max(0, deadline - Date.now()))
    work.then(resolve, reject)
  }) } finally { clearTimeout(timer) }
}
async function prepare() {
  if (!mounted || !props.active || props.busy || preparing.value || executing.value || cancelling.value) return
  invalidatePlan()
  const ticket = gate.begin()
  const target = { ...props.target, importedRoots: [...props.target.importedRoots] }
  const selectedRoots = [...target.importedRoots]
  const requestedLocalOnly = false
  const requestId = crypto.randomUUID()
  preparing.value = true
  const retryPlanId = failedPlanId.value || target.retryPlanId
  const operation = createPurgeOperation<KernSightGroupPurgePlan | null>(async () => {
    if (operation.cancelled()) return null
    if (retryPlanId) {
      const reports = await monitoringBackend.listKernSightGroupPurges()
      const prior = reports.find(report => report.id === retryPlanId && report.parentId === target.parentId && report.serial === target.serial && report.package === target.package)
      if (mounted && gate.current(ticket)) {
        resumeAuthorized.value = Boolean(prior && prior.state !== 'prepared')
        if (resumeAuthorized.value && prior?.error) error.value = `原清理未完成：${prior.error}。继续仅处理原授权剩余范围。`
      }
      if (operation.cancelled()) return null
      if (prior && prior.state !== 'prepared') return monitoringBackend.kernSightGroupPurgePlan(retryPlanId)
    }
    return retryPlanId
      ? monitoringBackend.prepareKernSightGroupPurgeRetry(retryPlanId, requestedLocalOnly, requestId)
      : monitoringBackend.prepareKernSightGroupPurge(target.parentId, selectedRoots, requestedLocalOnly, requestId)
  }, async reason => {
    await boundedStop(monitoringBackend.cancelKernSightGroupPurgePreparation(requestId))
    if (mounted && gate.current(ticket)) error.value = reason === 'timeout' ? '范围核对超过30秒，已请求后台停止并确认；未执行删除，可重新核对。' : '范围核对已取消；未执行删除。'
    return null
  }, timeouts().prepareMs)
  preparation = operation
  try {
    const result = await operation.result
    if (!result || !mounted || !gate.current(ticket) || !props.active || purgeTargetKey(target) !== purgeTargetKey(props.target)) return
    if (!purgePlanMatches(result, target) || result.localOnly !== requestedLocalOnly) throw new Error('返回预览与当前父会话、设备、包或清理模式不一致；未执行删除')
    plan.value = result
    now.value = Date.now()
  } catch (cause) {
    if (mounted && gate.current(ticket)) error.value = `无法生成清理预览：${readableError(cause)}`
  } finally {
    if (preparation === operation) preparation = null
    if (mounted && gate.current(ticket)) preparing.value = false
  }
}
async function cancelExecution(planId: string): Promise<KernSightGroupPurgeReport> {
  const until = Date.now() + timeouts().stopMs
  let report = await boundedStop(monitoringBackend.cancelKernSightGroupPurge(planId), until)
  while (report.state === 'running') {
    if (Date.now() >= until) throw new Error('已请求停止，但执行退出尚未确认；后台状态未知，保留原日志并等待重新核对')
    await new Promise(resolve => setTimeout(resolve, 250))
    const reports = await boundedStop(monitoringBackend.listKernSightGroupPurges(), until)
    const found = reports.find(item => item.id === planId)
    if (!found) throw new Error('停止后找不到原清理日志；状态未知，不视为完成')
    report = found
  }
  return report
}
async function stopCurrent() {
  if (cancelling.value || (!preparation && !execution)) return
  cancelling.value = true
  try {
    if (execution) await execution.cancel('user')
    else await preparation?.cancel('user')
  } catch (cause) { if (mounted) error.value = `停止结果未确认：${readableError(cause)}` }
  finally { if (mounted) cancelling.value = false }
}
async function execute() {
  now.value = Date.now()
  if (!canExecute.value || !plan.value || !gate.startExecution()) return
  const approvedPlan = plan.value
  const continuing = resumeAuthorized.value
  executing.value = true
  emit('executing', true)
  error.value = ''
  try {
    const operation = createPurgeOperation(
      () => continuing ? monitoringBackend.resumeKernSightGroupPurge(approvedPlan.id) : monitoringBackend.executeKernSightGroupPurge(approvedPlan.id, approvedPlan.confirmationToken),
      () => cancelExecution(approvedPlan.id), timeouts().executeMs)
    execution = operation
    const report = await operation.result
    if (!mounted || !purgePlanMatches(approvedPlan, props.target)) return
    if (report.id !== approvedPlan.id || report.parentId !== approvedPlan.parentId || report.serial !== approvedPlan.serial || report.package !== approvedPlan.package) throw new Error('后台清理报告与原授权会话身份不一致；状态未知，未据此标记完成')
    resumeAuthorized.value = report.state !== 'prepared'
    // Execution is already committed; always reconcile its durable result even if the page changed.
    if (report.state !== 'completed' || report.localState !== 'completed' || !['completed', 'not_required'].includes(report.deviceState)) {
      failedPlanId.value = report.id
      error.value = `清理未完成：本地 ${report.localState} / 手机 ${report.deviceState}。${report.error || report.warnings.join('；')}。原清理记录保留，请重新核对剩余范围后重试。`
      plan.value = { ...approvedPlan, confirmationToken: '' }
    }
    emit('complete', report, approvedPlan)
  } catch (cause) {
    if (!mounted || !purgePlanMatches(approvedPlan, props.target)) return
    failedPlanId.value = approvedPlan.id
    emit('uncertain')
    error.value = `清理结果未确认：${readableError(cause)}。请刷新清理记录并重新预览剩余范围，不要假定已完成。`
    plan.value = null
  } finally {
    execution = null
    gate.finishExecution()
    if (mounted) {
      executing.value = false
      emit('executing', false)
      if (!purgePlanMatches(approvedPlan, props.target)) void nextTick(prepare)
    }
  }
}
onBeforeUnmount(() => {
  mounted = false
  gate.invalidate()
  clearInterval(clock)
  void preparation?.cancel('unmount').catch(() => {})
  void execution?.cancel('unmount').catch(() => {})
  // Backend ownership locks and durable started journal continue to guard writes.
  emit('executing', false)
})
</script>

<style scoped>
.ks-purge-dialog{scroll-margin-top:90px;border:1px solid #a84c51;background:var(--surface);border-radius:10px;padding:16px;margin:12px 0;min-width:0;font-size:13px;line-height:1.6;overflow-wrap:anywhere}
.ks-purge-dialog header{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;flex-wrap:wrap}.ks-purge-dialog h3{margin:0}.ks-purge-dialog p{margin:8px 0}.ks-purge-dialog button{max-width:100%;white-space:normal}
.ks-purge-identity{display:grid;grid-template-columns:110px minmax(0,1fr);gap:4px 12px}.ks-purge-identity dd{margin:0;overflow-wrap:anywhere}.ks-purge-dialog.ks-purge-dialog .ks-purge-identity dt{color:var(--muted)}
.ks-purge-confirm{display:flex;gap:8px;flex-wrap:wrap}.ks-purge-error textarea{width:100%;min-height:80px;box-sizing:border-box;background:var(--surface);color:inherit}
.ks-purge-paths{padding-left:18px}.ks-purge-paths li{margin:8px 0}.ks-purge-paths code{display:block;white-space:pre-wrap;overflow-wrap:anywhere}.ks-purge-paths span{display:block;color:var(--muted)}.ks-purge-dialog.ks-purge-dialog .ks-purge-warning{color:var(--amber)}.ks-purge-dialog.ks-purge-dialog .ks-purge-error{color:var(--red)}.ks-purge-dialog.ks-purge-dialog .danger-button{color:var(--red);border-color:var(--red)}.ks-purge-dialog.ks-purge-dialog .danger-button:enabled:hover{background:var(--surface-soft)}.ks-purge-dialog :disabled{opacity:.5;cursor:not-allowed}
@media(max-width:520px){.ks-purge-dialog{padding:12px}.ks-purge-identity{grid-template-columns:1fr;gap:0}.ks-purge-identity dd{margin-bottom:8px}}
</style>
