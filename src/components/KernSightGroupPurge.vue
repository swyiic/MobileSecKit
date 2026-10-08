<template>
  <section ref="dialog" class="ks-purge-dialog" role="dialog" tabindex="-1" aria-labelledby="ks-purge-title" aria-describedby="ks-purge-warning" @keydown.esc.prevent="close">
    <header><div><h3 id="ks-purge-title">{{ target.retryPlanId ? '重新预览未完成的永久清理' : '永久清理主会话' }}</h3><p id="ks-purge-warning">删除后无法恢复，不进入回收站。系统自动核验会话归属、活跃依赖与手机配对。</p></div><button class="ghost-button" :disabled="executing" @click="close">{{ executing ? '清理执行中…' : '取消永久清理' }}</button></header>
    <dl class="ks-purge-identity"><dt>父会话 ID</dt><dd>{{ target.parentId }}</dd><dt>设备序列号</dt><dd>{{ target.serial }}</dd><dt>目标包</dt><dd>{{ target.package }}</dd></dl>
    <template v-if="!target.retryPlanId">
      <fieldset :disabled="preparing || executing"><legend>本地导入目录（仅勾选的副本会纳入预览）</legend><label v-for="root in target.importedRoots" :key="root" class="ks-purge-choice"><input v-model="roots" type="checkbox" :value="root" @change="prepare"><span>{{ root }}</span></label><p v-if="!target.importedRoots.length">没有已打开的同次导入目录；本地主会话记录仍由后端核对。</p></fieldset>
    </template>
    <p v-else>本次只预览持久化记录中尚未完成的范围，已完成的路径不会重复执行。</p>
    <fieldset :disabled="preparing || executing"><legend>本次清理模式</legend><label class="ks-purge-choice"><input v-model="localOnly" type="checkbox" @change="prepare"><span>仅永久清理本地，手机端保留并记为待清理</span></label></fieldset>
    <p v-if="localOnly" class="ks-purge-warning">本次不会删除手机文件。设备清理必须之后重新预览并单独确认。</p>
    <button class="ghost-button" :disabled="preparing || executing || busy" @click="prepare">{{ preparing ? '正在只读核对路径…' : plan ? '重新核对并生成预览' : '核对清理范围' }}</button>
    <p v-if="error" class="ks-purge-error" role="alert">{{ error }}</p>
    <div v-if="plan" class="ks-purge-preview" data-testid="purge-preview">
      <p>预览时间 {{ formatTime(plan.createdUnixMs) }} · 失效时间 {{ formatTime(plan.expiresUnixMs) }}（5 分钟内有效）</p>
      <p v-if="expired" class="ks-purge-error" role="alert">预览已失效。请重新核对范围，之前的确认已作废。</p>
      <p><strong>本地：{{ plan.localEntries.length }} 条精确路径 · {{ countFiles(plan.localEntries) }} 个文件</strong></p>
      <details><summary>查看系统核验的路径</summary><ul class="ks-purge-paths"><li v-for="entry in plan.localEntries" :key="entry.path"><code>{{ entry.path }}</code><span>{{ entry.kind }} · {{ entry.files }} 文件 · 逻辑大小 {{ bytes(entry.logicalBytes) }} · 实际分配 {{ bytes(entry.allocatedBytes) }}</span></li></ul></details>
      <p v-if="!plan.localEntries.length">本次没有待删除的本地路径。</p>
      <p><strong>手机：{{ deviceLabel }} · {{ plan.device?.entries.length ?? 0 }} 条精确路径 · {{ countFiles(plan.device?.entries || []) }} 个文件</strong></p>
      <details><summary>查看系统核验的路径</summary><ul class="ks-purge-paths"><li v-for="entry in plan.device?.entries || []" :key="entry.path"><code>{{ entry.path }}</code><span>{{ entry.kind }} · {{ entry.files }} 文件 · 逻辑大小 {{ bytes(entry.logicalBytes) }} · 实际分配 {{ bytes(entry.allocatedBytes) }}</span></li></ul></details>
      <p v-if="plan.localOnly" class="ks-purge-warning">仅本地模式：以上手机范围不会在本次执行；手机清理仍待完成。</p>
      <p v-else-if="!deviceReady" class="ks-purge-warning">手机范围尚未核验，本次不能执行双端清理。可取消后重连设备，或明确选择仅本地后重新预览。</p>
      <ul v-if="warnings.length" class="ks-purge-warning"><li v-for="warning in warnings" :key="warning">{{ warning }}</li></ul>
      <p>以上是待删除文件的占用统计，不是已释放空间。删除结果以执行后的逐端核验为准。</p>
      <p>系统已核验所选会话的归属与活跃依赖。点击下方按钮确认删除；不需要输入文字。</p>
      <button class="ghost-button danger-button" :disabled="!canExecute" @click="execute">{{ executing ? '正在清理并核验…' : plan.localOnly ? '确认永久清理本地（手机待清理）' : '确认永久清理本地与手机' }}</button>
      <p v-if="executing" role="status">已提交本次确认，正在清理并分别核验。请勿重复操作；结果会保留在清理记录中。</p>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'
import { monitoringBackend, readableError } from '@/services/backend'
import { canConfirmPurge, createPurgeRequestGate, purgePlanMatches, purgeTargetKey, type PurgeTarget } from '@/services/kernsightGroupPurge'
import type { KernSightGroupPurgeEntry, KernSightGroupPurgePlan, KernSightGroupPurgeReport } from '@/types/monitoring'
const props = defineProps<{ target: PurgeTarget; busy: boolean; active: boolean }>()
const emit = defineEmits<{ close: []; uncertain: []; executing: [value: boolean]; complete: [report: KernSightGroupPurgeReport, plan: KernSightGroupPurgePlan] }>()
const dialog = ref<HTMLElement | null>(null)
onMounted(() => { void nextTick(() => { dialog.value?.focus(); dialog.value?.scrollIntoView({ block: 'start' }) }) })
const plan = shallowRef<KernSightGroupPurgePlan | null>(null)
const roots = ref<string[]>([])
const localOnly = ref(false)
const preparing = ref(false)
const executing = ref(false)
const error = ref('')
const now = ref(Date.now())
const gate = createPurgeRequestGate()
const clock = setInterval(() => { now.value = Date.now() }, 250)
const expired = computed(() => Boolean(plan.value && now.value >= plan.value.expiresUnixMs))
const deviceReady = computed(() => ['ready', 'not_required'].includes(plan.value?.device?.status || ''))
const canExecute = computed(() => props.active && canConfirmPurge(plan.value, props.target, now.value, props.busy || preparing.value || executing.value))
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
function close() { if (executing.value) return; invalidatePlan(); emit('close') }
watch(() => purgeTargetKey(props.target), () => {
  invalidatePlan()
  roots.value = [...props.target.importedRoots]
  localOnly.value = false
  void nextTick(prepare)
}, { immediate: true, flush: 'sync' })
watch(() => props.busy, busy => { if (busy && !executing.value) close() }, { flush: 'sync' })
watch(() => props.active, active => { if (!active && !executing.value) close() }, { flush: 'sync' })

async function prepare() {
  if (!props.active || props.busy || preparing.value || executing.value) return
  invalidatePlan()
  const ticket = gate.begin()
  const target = { ...props.target, importedRoots: [...props.target.importedRoots] }
  const selectedRoots = [...roots.value]
  const requestedLocalOnly = localOnly.value
  preparing.value = true
  try {
    const result = target.retryPlanId
      ? await monitoringBackend.prepareKernSightGroupPurgeRetry(target.retryPlanId, requestedLocalOnly)
      : await monitoringBackend.prepareKernSightGroupPurge(target.parentId, selectedRoots, requestedLocalOnly)
    if (!gate.current(ticket) || !props.active || purgeTargetKey(target) !== purgeTargetKey(props.target)) return
    if (!purgePlanMatches(result, target) || result.localOnly !== requestedLocalOnly) throw new Error('返回预览与当前父会话、设备、包或清理模式不一致；未执行删除')
    plan.value = result
    now.value = Date.now()
  } catch (cause) {
    if (gate.current(ticket)) error.value = `无法生成清理预览：${readableError(cause)}`
  } finally { if (gate.current(ticket)) preparing.value = false }
}
async function execute() {
  now.value = Date.now()
  if (!canExecute.value || !plan.value || !gate.startExecution()) return
  const approvedPlan = plan.value
  executing.value = true
  emit('executing', true)
  error.value = ''
  try {
    const report = await monitoringBackend.executeKernSightGroupPurge(approvedPlan.id, approvedPlan.confirmationToken)
    // Execution is already committed; always reconcile its durable result even if the page changed.
    emit('complete', report, approvedPlan)
  } catch (cause) {
    emit('uncertain')
    error.value = `清理结果未确认：${readableError(cause)}。请刷新清理记录并重新预览剩余范围，不要假定已完成。`
    plan.value = null
      } finally {
    gate.finishExecution()
    executing.value = false
    emit('executing', false)
  }
}
onBeforeUnmount(() => { gate.invalidate(); clearInterval(clock) })
</script>

<style scoped>
.ks-purge-dialog{scroll-margin-top:90px;border:1px solid #a84c51;background:var(--panel,#101924);border-radius:10px;padding:16px;margin:12px 0;min-width:0;font-size:13px;line-height:1.6;overflow-wrap:anywhere}
.ks-purge-dialog header{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;flex-wrap:wrap}.ks-purge-dialog h3{margin:0}.ks-purge-dialog p{margin:8px 0}.ks-purge-dialog button{max-width:100%;white-space:normal}
.ks-purge-identity{display:grid;grid-template-columns:110px minmax(0,1fr);gap:4px 12px}.ks-purge-identity dd{margin:0;overflow-wrap:anywhere}.ks-purge-identity dt{color:#a0aebb}
.ks-purge-dialog fieldset{min-width:0;padding:12px;border:1px solid var(--line,#354252);border-radius:8px;margin:12px 0}.ks-purge-dialog legend{padding:0 5px}.ks-purge-choice{display:flex;align-items:flex-start;gap:8px;margin:8px 0}.ks-purge-choice input{flex:none;margin-top:5px}.ks-purge-choice span{min-width:0}.ks-purge-dialog input[type=text]{box-sizing:border-box;width:100%;margin-top:8px;padding:9px;border:1px solid var(--line,#354252);background:var(--surface,#101924);border-radius:6px;color:inherit;font:inherit}
.ks-purge-paths{padding-left:18px}.ks-purge-paths li{margin:8px 0}.ks-purge-paths code{display:block;white-space:pre-wrap;overflow-wrap:anywhere}.ks-purge-paths span{display:block;color:#a0aebb}.ks-purge-warning{color:#edc38f}.ks-purge-error{color:#f7a9ad}.danger-button{color:#ffb5b9;border-color:#a84c51}.danger-button:enabled:hover{background:#73383d}.ks-purge-dialog :disabled{opacity:.5;cursor:not-allowed}
@media(max-width:520px){.ks-purge-dialog{padding:12px}.ks-purge-identity{grid-template-columns:1fr;gap:0}.ks-purge-identity dd{margin-bottom:8px}}
</style>
