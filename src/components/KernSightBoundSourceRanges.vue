<template>
  <details :key="revision" class="ks-bound-source-pages" @toggle="toggle">
    <summary>原始范围记录 · {{ sources.length ? `${sources.length} 份来源报告` : '来源未提供' }}</summary>
    <p>按原始顺序分页读取范围元数据，不读取代码文件。生产者记录、本地 hash 验证与代码检查分别展示；原始记录可见不代表已完成分析。</p>
    <p v-if="!sources.length">当前记录未提供可定位的来源报告；原始范围数量未知。</p>
    <label v-else-if="sources.length > 1">来源报告<select v-model="sourceReport"><option v-for="source in sources" :key="source" :value="source">{{ source }}</option></select></label>
    <p v-else class="ks-bound-source-path">{{ sourceReport }}</p>
    <p v-if="loading" role="status">正在读取原始范围页…</p>
    <div v-if="error" class="ks-bound-source-error" role="alert"><p>{{ error }}</p><p v-if="page">当前仍展示上次成功读取的页，未混入本次失败回执。</p><button v-if="!unsupported" type="button" @click="loadPage(retryOffset, retryBackwards)">重试读取</button></div>
    <template v-if="page">
      <section class="ks-candidate-coverage" aria-label="初始候选采集覆盖" :data-coverage-status="coverage.status">
        <header><strong>初始候选采集覆盖</strong><b v-if="page.producerStatus?.partial === true">覆盖不足（partial）</b></header>
        <template v-if="coverage.status === 'available'">
          <p v-if="coverage.sourceShardCount > 1">跨 {{ coverage.sourceShardCount }} 份同源报告汇总；当前来源报告 {{ coverage.currentSourceRecords.toLocaleString() }} 条记录，分页只显示本份报告。</p>
          <dl>
            <div><dt>初始候选</dt><dd>{{ coverage.eligibleRanges.toLocaleString() }} 范围 <small :title="`${coverage.eligibleBytes} B`">{{ formatBytes(coverage.eligibleBytes) }}</small></dd></div>
            <div><dt>生产者已保留</dt><dd>{{ coverage.admittedRanges.toLocaleString() }} 范围 <small :title="`${coverage.admittedBytes} B`">{{ formatBytes(coverage.admittedBytes) }}</small></dd></div>
            <div><dt>未尝试</dt><dd>{{ coverage.unattemptedRanges.toLocaleString() }} 范围 <small :title="`${coverage.unattemptedBytes} B`">{{ formatBytes(coverage.unattemptedBytes) }}</small></dd></div>
            <div><dt>到时排除</dt><dd>{{ coverage.excludedRanges.toLocaleString() }} 范围</dd></div>
            <div><dt>其他未收</dt><dd>{{ coverage.rejectedRanges.toLocaleString() }} 范围</dd></div>
            <div><dt>剩余未保留字节</dt><dd :title="`${coverage.remainingBytes} B`">{{ formatBytes(coverage.remainingBytes) }}</dd></div>
          </dl>
          <p v-if="coverage.appInstall">安装目录候选：已保留 {{ coverage.appInstall.admittedRanges.toLocaleString() }} / {{ coverage.appInstall.eligibleRanges.toLocaleString() }} 范围；未保留 {{ coverage.appInstall.remainingRanges.toLocaleString() }} 范围，剩余 <span :title="`${coverage.appInstall.remainingBytes} B`">{{ formatBytes(coverage.appInstall.remainingBytes) }}</span>。</p>
          <p v-else>安装目录候选归类未知，不能按 0 个缺口理解。</p>
        </template>
        <p v-else>初始候选覆盖未知：{{ coverage.reason }}。已显示的原始记录仍可单独查看；缺失统计不按 0 处理。</p>
        <small>仅统计本次主进程的初始候选快照，不包含之后新增的映射，也不代表整个 App。生产者已保留不等于本地 hash 已验证，原始范围不是已重建的完整 DEX / SO；流程结束不会将 partial 改成完整。</small>
      </section>
      <p class="ks-bound-source-page-count">原始记录共 {{ page.totalRecords }} 条 · 当前 {{ page.records.length ? `${page.offset}–${page.offset + page.records.length - 1}` : '无记录' }} · 序号从 0 开始</p>
      <p v-if="stopScope === 'local_copy_window'" role="status">内存复制窗口已耗尽，生产者尝试了 {{ coverage.status === 'available' ? coverage.attemptedRanges : page.producerStatus?.attemptedRanges ?? '未知' }} 个范围。已保留文件可以分析，未读范围仍是采集缺口。</p>
      <p v-else-if="stopScope === 'runtime_metadata_reserve'" role="status">运行时数据额度已触及元数据预留，生产者停止继续读取；尚未保留的范围仍列为缺口。</p>
      <small v-if="typeof page.producerStatus?.grantedWindowMs === 'number'">复制窗口 {{ page.producerStatus.grantedWindowMs }} ms · 前置准备 {{ page.producerStatus.setupElapsedMs ?? '未知' }} ms</small>
      <p class="ks-bound-source-digest">来源 SHA-256：{{ page.sourceSha256 }}</p>
      <form v-if="page.totalRecords" class="ks-bound-source-jump" @submit.prevent="jump"><label>转到记录序号<input v-model="targetIndex" type="number" min="0" :max="page.totalRecords - 1" step="1" :disabled="loading" /></label><button type="submit" :disabled="loading || !canJump">转到记录</button></form>
      <div v-if="page.totalRecords" class="ks-bound-source-navigation"><button type="button" :disabled="loading || !history.length" @click="previous">上一页范围</button><button type="button" :disabled="loading || page.nextOffset === null" @click="loadPage(page.nextOffset ?? 0)">下一页范围</button></div>
      <p v-if="!page.records.length">该来源明确列示 0 条原始记录；不证明原进程不存在代码范围。</p>
      <div :key="`${page.sourceSha256}:${page.offset}`" class="ks-bound-source-rows">
        <details v-for="entry in entries" :key="entry.row.sourceRecordIndex" :data-source-record-index="entry.row.sourceRecordIndex">
          <summary>序号 {{ entry.row.sourceRecordIndex }} · {{ producerPath(entry.row.producerRecord) }} · {{ boundSourceAnalysisLabel(entry.local) }}</summary>
          <p v-if="entry.local">代码检查：{{ entry.local.inspection_status || '未知（未记录检查状态）' }}<span v-if="entry.local.inspection_ref != null"> · 按已验证内容关联共享检查结果</span></p>
          <p v-else>本地结果未按来源 SHA、原始序号、路径与完整来源精确关联；此条不能算作已验证或已检查。</p>
          <p v-if="entry.local?.content_verification_failure_reason">验证原因：{{ entry.local.content_verification_failure_reason }}</p>
          <details v-if="entry.local"><summary>本地范围状态与检查依据</summary><pre>{{ pretty(entry.local) }}</pre></details>
          <details v-if="entry.inspection"><summary>关联的代码检查详情</summary><pre>{{ pretty(entry.inspection) }}</pre></details>
          <details><summary>原始生产者记录</summary><pre>{{ pretty(entry.row.producerRecord) }}</pre></details>
        </details>
      </div>
    </template>
  </details>
</template>

<script setup lang="ts">
import { computed, ref, shallowRef, watch } from 'vue'
import { monitoringBackend, readableError } from '@/services/backend'
import { boundSourceAnalysisLabel, boundSourceInspection, boundSourceLocalAnalysis, boundSourceReports, candidateCoverageSummary, validateBoundSourcePage } from '@/services/kernsightBoundSourcePage'
import type { KernSightBoundSourcePage } from '@/types/monitoring'

const props = defineProps<{ root: string; packageName: string; ledger?: Record<string, any> }>()
const sources = computed(() => boundSourceReports(props.ledger))
const sourceReport = ref(sources.value[0] || '')
const page = shallowRef<KernSightBoundSourcePage | null>(null)
const loading = ref(false)
const error = ref('')
const unsupported = ref(false)
const targetIndex = ref<number | string>(0)
const retryOffset = ref(0)
const retryBackwards = ref(false)
const revision = ref(0)
const opened = ref(false)
let requestRevision = 0
let pinnedSha: string | null = null
const history = ref<number[]>([])
const coverage = computed(() => candidateCoverageSummary(page.value?.candidateCoverage))
const stopScope = computed(() => coverage.value.status === 'available'
  ? coverage.value.terminalStopScope ?? page.value?.producerStatus?.stopScope
  : page.value?.producerStatus?.stopScope)
const entries = computed(() => page.value?.records.map(row => {
  const local = boundSourceLocalAnalysis(props.ledger, page.value!, row)
  return { row, local, inspection: boundSourceInspection(props.ledger, local) }
}) || [])
const canJump = computed(() => page.value && Number.isSafeInteger(Number(targetIndex.value)) && Number(targetIndex.value) >= 0 && Number(targetIndex.value) < page.value.totalRecords && String(targetIndex.value).trim() !== '')
const pretty = (value: unknown) => JSON.stringify(value, null, 2)
const producerPath = (value: any) => value?.raw_evidence || value?.mapping?.path || '范围路径未提供'
function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes.toLocaleString()} B`
  const units = ['KiB', 'MiB', 'GiB']
  const power = Math.min(3, Math.floor(Math.log(bytes) / Math.log(1024)))
  return `${(bytes / 1024 ** power).toFixed(2)} ${units[power - 1]}`
}

function resetPage() { requestRevision++; page.value = null; pinnedSha = null; loading.value = false; error.value = ''; unsupported.value = false; targetIndex.value = 0; retryOffset.value = 0; history.value = [] }
watch(() => [props.root, props.packageName, props.ledger], () => { resetPage(); opened.value = false; sourceReport.value = sources.value[0] || ''; revision.value++ }, { flush: 'sync' })
watch(sourceReport, () => { resetPage(); if (opened.value && sourceReport.value) void loadPage(0) })
function toggle(event: Event) {
  opened.value = (event.target as HTMLDetailsElement).open
  if (opened.value && sourceReport.value && !page.value && !loading.value && !unsupported.value) void loadPage(0)
  if (!opened.value && loading.value) { requestRevision++; loading.value = false }
}
async function loadPage(offset: number, backwards = false) {
  if (!sourceReport.value || !Number.isSafeInteger(offset) || offset < 0 || (offset > 0 && !pinnedSha)) return
  const ticket = ++requestRevision
  const root = props.root, packageName = props.packageName, source = sourceReport.value
  retryOffset.value = offset; retryBackwards.value = backwards; error.value = ''; unsupported.value = false; loading.value = true
  try {
    const result = await monitoringBackend.localKernSightBoundSourcePage(root, packageName, source, offset, 100, pinnedSha)
    if (ticket !== requestRevision) return
    const valid = validateBoundSourcePage(result, source, offset, pinnedSha)
    if (backwards) history.value.pop()
    else if (page.value && valid.offset > page.value.offset) history.value.push(page.value.offset)
    else if (page.value && valid.offset < page.value.offset) history.value = history.value.filter(previous => previous < valid.offset)
    page.value = valid; pinnedSha = valid.sourceSha256; targetIndex.value = valid.offset
  } catch (failure) {
    if (ticket !== requestRevision) return
    const detail = readableError(failure)
    unsupported.value = /unknown.?command|command.*(?:not found|not supported|does not exist)|未(?:找到|知).*(?:命令|command)/i.test(detail)
    error.value = unsupported.value ? '当前安装不支持原始范围分页；此报告尚未通过分页读取。' : `原始范围页读取失败：${detail}`
  } finally { if (ticket === requestRevision) loading.value = false }
}
function previous() { const offset = history.value[history.value.length - 1]; if (offset !== undefined) void loadPage(offset, true) }
function jump() { if (canJump.value) void loadPage(Number(targetIndex.value)) }
</script>

<style scoped>
.ks-bound-source-pages { min-width:0; margin:12px 0; padding:10px; border:1px solid var(--line); border-radius:8px; }
summary { cursor:pointer; line-height:1.6; overflow-wrap:anywhere; }
p { line-height:1.6; overflow-wrap:anywhere; }
label { display:grid; min-width:0; gap:6px; }
select, input { min-width:0; max-width:100%; color:var(--text); background:var(--surface-soft); border:1px solid var(--line-strong); border-radius:6px; padding:6px; }
select { width:100%; }
.ks-bound-source-jump { display:flex; flex-wrap:wrap; align-items:end; gap:8px; margin:10px 0; }
.ks-bound-source-jump label { flex:1 1 160px; }
.ks-bound-source-navigation { display:flex; gap:8px; margin:10px 0; }
button { padding:6px 10px; border:1px solid var(--line-strong); border-radius:6px; color:var(--text); background:var(--surface-soft); }
button:disabled { opacity:.5; }
.ks-bound-source-error { color:var(--danger); }
.ks-candidate-coverage { min-width:0; margin:12px 0; padding:10px; border:1px solid var(--line); border-radius:7px; background:var(--surface-soft); }
.ks-candidate-coverage header { display:flex; flex-wrap:wrap; justify-content:space-between; gap:8px; }
.ks-candidate-coverage header b { color:var(--muted); font-size:12px; }
.ks-candidate-coverage dl { display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%,165px),1fr)); gap:10px; margin:12px 0; }
.ks-candidate-coverage dl > div { min-width:0; }
.ks-candidate-coverage dt { color:var(--muted); font-size:12px; }
.ks-candidate-coverage dd { margin:3px 0 0; font-variant-numeric:tabular-nums; overflow-wrap:anywhere; }
.ks-candidate-coverage dd small { display:block; }
.ks-candidate-coverage > small { display:block; color:var(--muted); line-height:1.6; }
.ks-bound-source-rows { max-height:60vh; overflow:auto; }
.ks-bound-source-rows > details { min-width:0; padding:8px 0; border-top:1px solid var(--line); }
pre { max-width:100%; max-height:320px; overflow:auto; white-space:pre-wrap; overflow-wrap:anywhere; font-size:11px; }
</style>
