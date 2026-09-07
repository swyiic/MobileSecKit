<template>
  <section class="flow-view">
    <ScrollAnchorNav :anchors="flowAnchors" />
    <header class="section-title flow-hero">
      <div><div class="eyebrow">DATA FLOW / RUNTIME CORRELATION</div><h2>数据流与运行时关联</h2><p>这里不重复展示 Analyzer 的原始字符串和代码全文，而是把静态入口、运行事件和数据出口归并为“来源 → 处理 → 去向”。点击 Source ID 可回到 App Analyzer 对应证据区域。</p></div>
      <div class="flow-hero-side"><button v-if="analysis" class="ghost-button compact-button" @click="emit('openAi')"><span class="material-symbols-outlined">neurology</span>用 AI 复核数据流</button><div class="flow-scope"><small>APP SCOPE</small><strong>{{ analysis?.packageId || '未解析包名' }}</strong><span>{{ runtimeCount ? `${runtimeCount} 条运行时观察` : '当前只有静态候选' }}</span></div></div>
    </header>

    <div v-if="!analysis && !history.length" class="empty-state"><span class="material-symbols-outlined">account_tree</span><h3>还没有数据流证据</h3><p>先在 App Analyzer 导入 APK / IPA，再运行 Frida / ADB 观察脚本。</p></div>

    <template v-else>
      <section v-if="!runtimeCount" class="static-preview-notice"><span class="material-symbols-outlined">hourglass_top</span><div><strong>当前是静态数据流预览</strong><p>这些流程是由 Manifest、二进制、代码入口和敏感线索归并出的候选，不代表已经观察到真实调用。产生同包名运行日志后，MobileE 会更新现有流程状态。</p></div></section>

      <section class="flow-overview">
        <article><span>归并后流程</span><strong>{{ flows.length }}</strong><small>来自 {{ items.length }} 条观察</small></article>
        <article class="high"><span>高风险候选</span><strong>{{ highCount }}</strong><small>优先人工验证</small></article>
        <article class="runtime"><span>运行时已观察</span><strong>{{ runtimeFlowCount }}</strong><small>包含 correlated</small></article>
        <article class="correlated"><span>静态 + 运行时</span><strong>{{ correlatedCount }}</strong><small>已建立关联</small></article>
      </section>

      <div class="flow-boundary-tabs">
        <button v-for="summary in summaries" :key="summary.boundary" :class="{ active: boundaryFilter === summary.boundary }" @click="boundaryFilter = boundaryFilter === summary.boundary ? '' : summary.boundary"><span class="material-symbols-outlined">{{ summary.icon }}</span><strong>{{ summary.label }}</strong><b>{{ summary.count }}</b></button>
      </div>

      <section class="flow-toolbar">
        <label><span class="material-symbols-outlined">search</span><input v-model="query" placeholder="搜索来源、去向、Endpoint、Operation、Framework…" /></label>
        <select v-model="stateFilter"><option value="">全部验证状态</option><option value="correlated">静态 + 运行时</option><option value="runtime-observed">运行时已观察</option><option value="static-candidate">静态候选</option><option value="manual-confirmed">人工确认</option><option value="blocked">验证受阻</option></select>
        <button class="ghost-button compact-button" :class="{ active: focusOnly }" @click="focusOnly = !focusOnly">{{ focusOnly ? '重点视图' : '完整视图' }}</button>
        <button v-if="hasFilters" class="ghost-button compact-button" @click="resetFilters">清除筛选</button>
      </section>
      <div class="flow-toolbar-note"><span>{{ filteredFlows.length }} / {{ flows.length }} 条流程</span><span>重点视图只保留高风险、运行时观察和已关联流程</span></div>

      <section v-if="filteredFlows.length" class="flow-list">
        <article v-for="flow in filteredFlows" :id="firstFlowIds.get(flow.boundary) === flow.id ? `flow-anchor-${flow.boundary}` : undefined" :key="flow.id" class="flow-card" :class="[`severity-${flow.severity}`, `state-${flow.validationState}`]">
          <header><div class="flow-title"><span class="flow-severity">{{ flow.severity }}</span><span class="flow-boundary">{{ boundaryLabel(flow.boundary) }}</span><strong>{{ flow.title }}</strong></div><span class="flow-state">{{ stateLabel(flow.validationState) }}</span></header>
          <div class="flow-path">
            <div><small>SOURCE / PRODUCER</small><strong>{{ flow.producer || producerFallback(flow) }}</strong></div>
            <span class="material-symbols-outlined">arrow_forward</span>
            <div><small>SINK / CONSUMER</small><strong>{{ flow.consumer || consumerFallback(flow) }}</strong></div>
          </div>
          <dl class="flow-meta">
            <div v-if="flow.endpoint"><dt>Endpoint</dt><dd><code>{{ flow.endpoint }}</code></dd></div>
            <div v-if="flow.operation"><dt>Operation</dt><dd><code>{{ flow.operation }}</code></dd></div>
            <div v-if="flow.frameworks.length"><dt>Framework</dt><dd>{{ flow.frameworks.join(' · ') }}</dd></div>
            <div><dt>Data</dt><dd><span v-for="type in flow.dataTypes" :key="type" class="flow-chip">{{ type }}</span></dd></div>
          </dl>
          <div class="flow-assessment"><span class="material-symbols-outlined">{{ flow.validationState === 'correlated' ? 'join_inner' : flow.validationState === 'runtime-observed' ? 'visibility' : 'science' }}</span><p>{{ nextStep(flow) }}</p></div>
          <footer>
            <div class="flow-source-ids"><span>Source IDs</span><button v-for="observation in flow.observations.slice(0, 6)" :key="observation.id" :title="observation.sourceLocation || observation.sourceType" @click="emit('openAnalyzer', { id: observation.id, sourceType: observation.sourceType, sourceLocation: observation.sourceLocation })">{{ observation.id }}</button><small v-if="flow.observations.length > 6">+{{ flow.observations.length - 6 }}</small></div>
            <time v-if="flow.observedAt" :datetime="new Date(flow.observedAt).toISOString()">{{ formatDateTime(flow.observedAt) }}</time>
          </footer>
          <details v-if="flow.observations.length > 1" class="flow-observations"><summary>查看 {{ flow.observations.length }} 条关联观察</summary><ul><li v-for="observation in flow.observations" :key="observation.id"><code>{{ observation.id }}</code><span>{{ sourceLabel(observation.sourceType) }}</span><small>{{ observation.sourceLocation || '未提供源位置' }}</small></li></ul></details>
        </article>
      </section>
      <div v-else class="empty-state flow-empty"><span class="material-symbols-outlined">filter_alt_off</span><h3>重点视图中没有符合条件的流程</h3><p>可以切换到完整视图或清除筛选查看全部静态候选。</p><button v-if="focusOnly" class="primary-button" @click="focusOnly = false">显示完整视图</button></div>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import ScrollAnchorNav from '@/components/ScrollAnchorNav.vue'
import { buildBoundaryFlows, correlateBoundaries } from '@/services/boundaries'
import type { AppAnalysis, DataBoundaryFlow, DataFlowValidationState, DeviceSummary, TerminalEntry } from '@/types'
import { formatDateTime } from '@/utils/time'

const props = defineProps<{ analysis: AppAnalysis | null; history: TerminalEntry[]; device?: DeviceSummary | null }>()
const emit = defineEmits<{ openAi: []; openAnalyzer: [request: { id: string; sourceType: string; sourceLocation?: string }] }>()
const query = ref('')
const boundaryFilter = ref('')
const stateFilter = ref('')
const focusOnly = ref(true)

const correlated = computed(() => correlateBoundaries(props.analysis, props.history, props.analysis?.platform || props.device?.platform || 'unknown', props.device?.serial))
const items = computed(() => correlated.value.items)
const flows = computed(() => buildBoundaryFlows(items.value))
const runtimeCount = computed(() => correlated.value.runtimeItems.length)
const highCount = computed(() => flows.value.filter((flow) => ['high', 'critical'].includes(flow.severity)).length)
const runtimeFlowCount = computed(() => flows.value.filter((flow) => ['runtime-observed', 'correlated', 'manual-confirmed'].includes(flow.validationState)).length)
const correlatedCount = computed(() => flows.value.filter((flow) => flow.validationState === 'correlated' || flow.validationState === 'manual-confirmed').length)
const hasFilters = computed(() => Boolean(query.value || boundaryFilter.value || stateFilter.value || !focusOnly.value))
const filteredFlows = computed(() => {
  const needle = query.value.trim().toLowerCase()
  return flows.value.filter((flow) => {
    const searchable = [flow.title, flow.boundary, flow.producer, flow.consumer, flow.endpoint, flow.operation, ...flow.frameworks, ...flow.dataTypes, ...flow.sourceLocations].filter(Boolean).join(' ').toLowerCase()
    const important = ['high', 'critical'].includes(flow.severity) || flow.validationState !== 'static-candidate'
    return (!focusOnly.value || important) && (!needle || searchable.includes(needle)) && (!boundaryFilter.value || flow.boundary === boundaryFilter.value) && (!stateFilter.value || flow.validationState === stateFilter.value)
  })
})
const firstFlowIds = computed(() => new Map(filteredFlows.value.map((flow) => [flow.boundary, filteredFlows.value.find((candidate) => candidate.boundary === flow.boundary)!.id])))

const boundaryDefinitions: Array<[string, string, string]> = [
  ['network', '网络出口', 'lan'], ['tls', 'TLS / 信任', 'verified_user'], ['identity', '身份 / 会话', 'badge'], ['storage', '本地存储', 'database'], ['webview', 'WebView / 桥接', 'language'], ['crypto', '密码学', 'key'], ['ipc', 'IPC / 输入', 'input'], ['dynamic-code', '动态代码', 'deployed_code'], ['runtime-code', '运行时代码', 'memory'], ['runtime-integrity', '运行时保护', 'shield'], ['anti-instrumentation', '注入保护', 'security'],
]
const summaries = computed(() => boundaryDefinitions.map(([boundary, label, icon]) => ({ boundary, label, icon, count: flows.value.filter((flow) => flow.boundary === boundary).length })).filter((item) => item.count))
const flowAnchors = computed(() => summaries.value.filter((summary) => firstFlowIds.value.has(summary.boundary)).map((summary) => ({ id: `flow-anchor-${summary.boundary}`, label: summary.label })))

const stateLabels: Record<DataFlowValidationState, string> = { 'static-candidate': 'STATIC CANDIDATE', 'runtime-observed': 'RUNTIME OBSERVED', correlated: 'STATIC + RUNTIME', 'manual-confirmed': 'MANUALLY CONFIRMED', blocked: 'VALIDATION BLOCKED' }
const stateLabel = (state: DataFlowValidationState) => stateLabels[state]
const boundaryLabel = (boundary: string) => boundaryDefinitions.find(([key]) => key === boundary)?.[1] || boundary
const sourceLabel = (source: string) => ({ 'static-code': '静态代码', binary: '二进制', sensitive: '敏感线索', manifest: 'Manifest / Plist', protection: '保护线索', runtime: '运行时事件', 'static-correlated': '静态 + 运行时' } as Record<string, string>)[source] || source

function producerFallback(flow: DataBoundaryFlow) {
  if (flow.direction === 'ingress' || flow.direction === 'bidirectional') return '外部输入 / Web 内容'
  return 'App 内部数据或调用方'
}
function consumerFallback(flow: DataBoundaryFlow) {
  if (flow.endpoint) return '远程服务'
  if (flow.boundary === 'storage') return '本地存储'
  if (flow.boundary === 'tls') return '系统信任决策'
  return '待运行时确认的处理点'
}
function nextStep(flow: DataBoundaryFlow) {
  if (flow.validationState === 'manual-confirmed') return '已经人工确认；建议保存快照并把可复用检测步骤加入知识库。'
  if (flow.validationState === 'correlated') return '静态入口与运行事件已经关联；下一步核对真实参数、响应、权限校验和调用栈。'
  if (flow.validationState === 'runtime-observed') return '已观察到运行事件，但尚未关联静态入口；可补充调用栈或同 Endpoint 的代码位置。'
  if (flow.validationState === 'blocked') return '运行时验证受阻；先处理注入通道、权限或目标保护，再重新采集。'
  return '当前仅为静态候选；选择同一包名进程运行对应 Frida 观察脚本后再判断。'
}
function resetFilters() { query.value = ''; boundaryFilter.value = ''; stateFilter.value = ''; focusOnly.value = true }
</script>

<style scoped>
.flow-view{display:grid;gap:13px}.flow-hero{align-items:flex-start}.flow-hero p{max-width:850px;margin:5px 0 0;color:var(--muted);font-size:9px;line-height:1.65}.flow-hero-side{display:grid;justify-items:end;gap:7px}.flow-hero-side button{display:flex;align-items:center;gap:4px}.flow-scope{display:grid;min-width:190px;gap:2px;padding:9px 11px;border:1px solid var(--line);border-radius:9px;background:rgba(57,125,246,.045);text-align:right}.flow-scope small{color:#65758d;font-size:7px}.flow-scope strong{overflow:hidden;max-width:250px;color:#a9c8f8;font-size:9px;text-overflow:ellipsis}.flow-scope span{color:#728198;font-size:7px}.static-preview-notice{display:flex;align-items:flex-start;gap:9px;padding:10px 12px;border:1px solid rgba(225,161,68,.24);border-radius:10px;background:rgba(225,161,68,.045)}.static-preview-notice>span{color:#dfa952}.static-preview-notice strong{font-size:9px}.static-preview-notice p{margin:3px 0 0;color:#917f66;font-size:8px;line-height:1.5}.flow-overview{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:7px}.flow-overview article{padding:10px;border:1px solid var(--line);border-radius:9px;background:rgba(255,255,255,.018)}.flow-overview span,.flow-overview strong,.flow-overview small{display:block}.flow-overview span{color:#708097;font-size:7px;text-transform:uppercase}.flow-overview strong{margin:2px 0;color:#c8d5e9;font-size:16px}.flow-overview small{color:#66758a;font-size:7px}.flow-overview .high strong{color:#ed9299}.flow-overview .runtime strong{color:#7abde8}.flow-overview .correlated strong{color:#75d5a7}.flow-boundary-tabs{display:flex;gap:5px;padding-bottom:2px;overflow:auto}.flow-boundary-tabs button{display:flex;align-items:center;gap:5px;min-width:max-content;padding:6px 8px;border:1px solid var(--line);border-radius:8px;color:#7f8ea3;background:rgba(255,255,255,.018);cursor:pointer}.flow-boundary-tabs button.active,.flow-boundary-tabs button:hover{border-color:rgba(57,125,246,.45);color:#b8cef1;background:rgba(57,125,246,.1)}.flow-boundary-tabs span{font-size:14px}.flow-boundary-tabs strong{font-size:8px}.flow-boundary-tabs b{color:#608acb;font-size:8px}.flow-toolbar{display:grid;grid-template-columns:minmax(260px,1fr) 160px auto auto;gap:7px;padding:9px;border:1px solid var(--line);border-radius:10px;background:rgba(8,12,18,.55)}.flow-toolbar label{display:flex;align-items:center;gap:5px;padding:0 8px;border:1px solid var(--line);border-radius:8px;background:#090e15}.flow-toolbar label span{color:#63728a;font-size:14px}.flow-toolbar input{width:100%;border:0;outline:0;color:#afbdd1;background:transparent;font-size:8px}.flow-toolbar select{padding:0 8px;border:1px solid var(--line);border-radius:8px;color:#a5b3c7;background:#090e15;font-size:8px}.flow-toolbar button.active{border-color:rgba(57,125,246,.5);color:#b8d0f7;background:rgba(57,125,246,.1)}.flow-toolbar-note{display:flex;gap:12px;margin-top:-7px;color:#66758a;font-size:7px}.flow-list{display:grid;gap:9px}.flow-card{padding:11px;border:1px solid var(--line);border-left:3px solid #506786;border-radius:10px;background:linear-gradient(180deg,rgba(17,25,37,.84),rgba(8,13,20,.9));scroll-margin-top:18px}.flow-card.severity-high,.flow-card.severity-critical{border-left-color:#e96872}.flow-card.state-correlated,.flow-card.state-manual-confirmed{box-shadow:inset 0 0 0 1px rgba(64,198,139,.09)}.flow-card>header,.flow-title,.flow-card>footer{display:flex;align-items:center;justify-content:space-between;gap:7px}.flow-title{justify-content:flex-start;min-width:0;flex-wrap:wrap}.flow-title strong{font-size:9px;overflow-wrap:anywhere}.flow-severity,.flow-boundary,.flow-state{padding:2px 5px;border-radius:999px;font-size:7px}.flow-severity{color:#dda96b;background:rgba(225,161,68,.1);text-transform:uppercase}.severity-high .flow-severity,.severity-critical .flow-severity{color:#ff9ba4;background:rgba(233,82,93,.12)}.flow-boundary{color:#8db5ed;background:rgba(57,125,246,.1)}.flow-state{color:#8e9db2;background:rgba(255,255,255,.05);white-space:nowrap}.state-correlated .flow-state,.state-manual-confirmed .flow-state{color:#7cdbad;background:rgba(61,194,132,.1)}.state-runtime-observed .flow-state{color:#83c7ed;background:rgba(63,157,217,.1)}.flow-path{display:grid;grid-template-columns:minmax(0,1fr) 28px minmax(0,1fr);align-items:center;gap:7px;margin:8px 0;padding:8px;border:1px solid rgba(57,125,246,.14);border-radius:8px;background:rgba(57,125,246,.035)}.flow-path>span{color:#5586ce;text-align:center}.flow-path small,.flow-path strong{display:block}.flow-path small{color:#607087;font-size:7px}.flow-path strong{margin-top:3px;color:#b6c5d9;font:8px ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}.flow-meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:5px 12px;margin:0}.flow-meta>div{display:grid;grid-template-columns:68px minmax(0,1fr);gap:6px}.flow-meta dt{color:#637188;font-size:7px}.flow-meta dd{margin:0;color:#9dabbe;font-size:8px;overflow-wrap:anywhere}.flow-meta code{color:#a9c7f5;font:7px ui-monospace,SFMono-Regular,Menlo,monospace}.flow-chip{display:inline-block;margin:0 3px 2px 0;padding:2px 5px;border-radius:5px;color:#84c6e3;background:rgba(73,175,218,.07);font-size:7px}.flow-assessment{display:flex;align-items:center;gap:7px;margin-top:8px;padding:6px 8px;border-radius:7px;background:rgba(255,255,255,.025)}.flow-assessment span{color:#718eb8;font-size:14px}.flow-assessment p{margin:0;color:#7e8da1;font-size:7px;line-height:1.45}.flow-card>footer{align-items:flex-end;margin-top:8px}.flow-source-ids{display:flex;min-width:0;flex-wrap:wrap;align-items:center;gap:4px}.flow-source-ids>span{color:#607087;font-size:7px}.flow-source-ids button{max-width:170px;padding:2px 5px;overflow:hidden;border:1px solid rgba(57,125,246,.18);border-radius:5px;color:#82a9e7;background:rgba(57,125,246,.05);font:7px ui-monospace,SFMono-Regular,Menlo,monospace;text-overflow:ellipsis;white-space:nowrap;cursor:pointer}.flow-source-ids button:hover{border-color:#4b83d6;color:#bfd4f7}.flow-source-ids small,.flow-card time{color:#617087;font-size:7px}.flow-observations{margin-top:7px}.flow-observations summary{color:#7188aa;font-size:7px;cursor:pointer}.flow-observations ul{display:grid;gap:3px;margin:6px 0 0;padding:0;list-style:none}.flow-observations li{display:grid;grid-template-columns:180px 100px minmax(0,1fr);gap:7px;padding:5px 7px;border-radius:6px;background:#070c12}.flow-observations code,.flow-observations span,.flow-observations small{overflow:hidden;font-size:7px;text-overflow:ellipsis;white-space:nowrap}.flow-observations code{color:#799fd9}.flow-observations span{color:#91a0b4}.flow-observations small{color:#637188}.flow-empty{margin:0}@media(max-width:850px){.flow-overview{grid-template-columns:1fr 1fr}.flow-toolbar{grid-template-columns:1fr 1fr}.flow-toolbar label{grid-column:1/-1}.flow-meta{grid-template-columns:1fr}}@media(max-width:620px){.flow-hero-side{display:none}.flow-overview,.flow-toolbar{grid-template-columns:1fr}.flow-toolbar label{grid-column:auto}.flow-path{grid-template-columns:1fr}.flow-path>span{transform:rotate(90deg)}.flow-card>footer{align-items:flex-start;flex-direction:column}.flow-observations li{grid-template-columns:1fr}}
</style>
