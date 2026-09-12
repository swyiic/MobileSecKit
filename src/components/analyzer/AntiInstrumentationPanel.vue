<template>
  <details class="anti-panel" :open="assessment.candidates.length > 0 || Boolean(kernSightJoin)">
    <summary>
      <div class="anti-summary-copy">
        <span class="eyebrow">RUNTIME EVIDENCE</span>
        <div class="anti-summary-title-row">
          <strong>{{ platform === 'android' ? 'KernSight 运行时证据' : '运行时证据流程' }}</strong>
          <small>{{ candidateGroups.length }} 类 · {{ activeCandidates.length }} 条有效候选<span v-if="filteredCandidates.length"> · {{ filteredCandidates.length }} 条已过滤</span></small>
        </div>
      </div>
      <b :class="`anti-status status-${panelStatus}`">{{ panelStatusLabel }}</b>
    </summary>
    <p v-if="platform === 'ios'" class="anti-intro">iOS 运行时流程按同一 Bundle ID 关联证据；绿色步骤只表示观察完成，不代表漏洞已证实。</p>
    <section v-if="platform === 'android'" class="ks-runtime-join">
      <header>
        <div class="ks-runtime-source">
          <div class="ks-runtime-title">
            <strong>KernSight session / dump <b v-if="kernSightJoin" class="ks-evidence-source">{{ kernSightJoin.sourceLabel }}</b></strong>
            <details class="ks-runtime-help">
              <summary aria-label="查看 KernSight 证据关联说明" title="查看说明">?</summary>
              <div>
                <strong>证据关联说明</strong>
                <p>Android 主证据链只接入 KernSight session / dump，并按包名与内容身份关联 L0、L1、L2。confirmed / correlated / inferred 只描述证据强度，不会被界面升级成 MASVS 风险结论。</p>
                <p>{{ kernSightJoin?.disclaimer || '接入后可检查 SNI、TLS 明文、Binder token，以及 dump 的 DEX、data-private 与堆明文。' }}</p>
                <dl v-if="kernSightJoin">
                  <dt>证据目录</dt><dd><code>{{ kernSightJoin.root }}</code></dd>
                  <dt>归属方式</dt><dd>{{ kernSightJoin.dexOwnershipMode === 'class-index' ? '类级归属索引' : '旧版路径降级' }}</dd>
                </dl>
              </div>
            </details>
          </div>
          <small>{{ kernSightJoin ? `${kernSightJoin.package} · ${kernSightJoin.fileCount.toLocaleString()} 个文件 · Agent ${kernSightJoin.agentVersion || 'unknown'}` : '尚未接入本地证据' }}</small>
        </div>
        <div class="ks-runtime-join-actions">
          <button class="ghost-button compact-button" :disabled="importingKernSight" @click="emit('importKernSight')">{{ importingKernSight ? '正在接入…' : kernSightJoin ? '重新接入' : '接入本机证据目录' }}</button>
          <button class="ghost-button compact-button" :disabled="importingKernSight" @click="emit('importKernSightArchive')">打开 .mee</button>
          <button class="ghost-button compact-button" @click="emit('openKernSight')">{{ kernSightJoin ? '打开 KernSight 证据链' : '可选：使用 ksightd 采集' }}</button>
        </div>
      </header>
      <div class="ks-runtime-metrics">
        <span><b>{{ kernSightJoin ? presentFactCount : 0 }}</b> 类运行时证据</span>
        <span><b>{{ ownershipRuleHits.length }}</b> 条本地归属规则</span>
        <span><b>{{ activeCandidates.length }}</b> 条静态候选</span>
      </div>
      <details v-if="kernSightJoin" class="ks-evidence-details">
        <summary><span>查看 L0 / L1 / L2 证据详情</span><span class="material-symbols-outlined">expand_more</span></summary>
        <section class="ownership-rule-summary">
          <header><strong>本地归属规则</strong><b>{{ ownershipRuleHits.length }} 命中</b></header>
          <p v-if="!ownershipRuleHits.length">尚未命中已确认的 DEX / SO 归属规则，可在 DEX / SO 归属区发起 AI 复核。</p>
          <div v-else><span v-for="pattern in ownershipRuleHits.slice(0, 8)" :key="pattern.patternId" :title="pattern.triggerSignals.join(' · ')">{{ pattern.title }}</span></div>
        </section>
        <div class="anti-workflow ks-runtime-workflow">
        <span :class="{ done: factPresent('sni') }"><b>L0</b>SNI / DNS</span><i></i>
        <span :class="{ done: factPresent('tls') }"><b>L1</b>TLS 明文</span><i></i>
        <span :class="{ done: factPresent('binder') }"><b>L0</b>Binder</span><i></i>
        <span :class="{ done: factPresent('dex') || factPresent('private') || factPresent('heap') }"><b>L2</b>Dump</span>
        </div>
        <div class="ks-runtime-facts">
        <article v-for="item in kernSightJoin.facts" :key="item.key" :class="`strength-${item.strength}`">
          <header><b>{{ item.layer }}</b><strong>{{ item.title }}</strong><em>{{ strengthLabel(item.strength) }}</em></header>
          <p>{{ item.summary }}</p>
          <code v-for="line in item.items.slice(0, 3)" :key="line">{{ line }}</code>
          <details v-if="item.items.length > 3" class="ks-fact-more">
            <summary>查看其余 {{ item.items.length - 3 }} 条证据</summary>
            <code v-for="line in item.items.slice(3)" :key="line">{{ line }}</code>
          </details>
        </article>
        </div>
      </details>
    </section>
    <div v-if="platform === 'ios' && activeCandidates.length" class="anti-workflow">
      <span :class="{ done: true }"><b>1</b>静态候选</span><i></i>
      <span :class="{ done: injectionStep?.status === 'complete' || assessment.status === 'blocked' }"><b>2</b>注入基线</span><i></i>
      <span :class="{ done: hasSubstantiveRuntime }"><b>3</b>专项运行证据</span><i></i>
      <span :class="{ done: hasSubstantiveRuntime }"><b>4</b>整体分析</span>
    </div>
    <div v-if="platform === 'ios' && activeCandidates.length" class="anti-actions">
      <button v-if="assessment.status === 'pending'" class="primary-button compact-button" @click="emit('openRuntime')">
        <span class="material-symbols-outlined">play_circle</span>
        {{ platform === 'ios' ? '用 iOS 零 Hook 探针确认' : '用 Android 零 Hook 探针确认' }}
      </button>
      <button v-else class="ghost-button compact-button" @click="emit('openRuntime')">重新运行确认</button>
      <button class="ghost-button compact-button" :disabled="!hasSubstantiveRuntime" @click="emit('openAi')">
        <span class="material-symbols-outlined">neurology</span>携带静态 + 运行证据整体分析
      </button>
    </div>
    <div v-if="platform === 'ios'" class="runtime-coverage">
      <span v-for="step in runtimeSteps" :key="step.key" :class="{ done: step.status === 'complete', blocked: step.status === 'blocked' }" :title="step.detail || step.description">
        {{ step.label }} {{ step.status === 'complete' ? '✓' : step.status === 'blocked' ? 'BLOCKED' : '—' }}
      </span>
    </div>
    <p v-if="platform === 'ios' && injectionStep?.status === 'complete' && !hasSubstantiveRuntime" class="anti-intro">注入基线只证明脚本可以进入进程；请前往 Frida Toolbox 继续采集语言运行时、网络、WebView 与存储证据。</p>
    <ul v-if="recommendations.length" class="anti-recommendations">
      <li v-for="item in recommendations" :key="item">{{ item }}</li>
    </ul>
    <div v-if="!assessment.candidates.length" class="anti-empty">{{ platform === 'android' ? '本轮未发现专项静态信号；如需运行时证据，可使用 KernSight 新建采集并拉回证据包。' : '本轮未发现专项静态信号；仍可运行零 Hook 探针形成运行时基线。' }}</div>
    <div v-else-if="!activeCandidates.length" class="anti-empty">静态命中已全部由低噪声排除规则降级；原始候选仍保留在下方，后续出现 P_TRACED、ptrace 或明确终止证据时会自动恢复为有效候选。</div>
    <details v-for="group in candidateGroups" :key="group.label" class="anti-candidate-group">
      <summary>
        <div><strong>{{ group.label }}</strong><small>{{ group.items.length }} 个文件 / 位置 · {{ group.signalCount }} 个信号</small></div>
        <span class="material-symbols-outlined">expand_more</span>
      </summary>
      <details v-for="(candidate, index) in group.items" :key="`${candidate.signal}-${candidate.location}-${index}`" class="anti-candidate" :class="{ 'filtered-candidate': candidate.filtered }">
        <summary>
          <code>{{ candidate.location || '—' }}</code>
          <code class="candidate-signal">{{ candidate.signal }}</code>
          <span v-if="candidate.filtered" class="runtime-badge runtime-filtered">FILTERED</span>
          <span v-else :class="`runtime-badge runtime-${candidate.runtime}`">{{ runtimeLabel(candidate.runtime) }}</span>
          <span class="material-symbols-outlined candidate-chevron">chevron_right</span>
        </summary>
        <div class="anti-candidate-detail">
          <dl><dt>来源</dt><dd><b>{{ candidate.source }}</b></dd><dt>信号</dt><dd><code>{{ candidate.signal }}</code></dd></dl>
          <p v-if="candidate.filterReason" class="filtered-reason">{{ candidate.filterReason }}</p>
          <div v-if="candidate.evidence.length" class="anti-evidence">
            <strong>详细证据 {{ candidate.evidence.length }}</strong>
            <pre v-for="(evidence, evidenceIndex) in candidate.evidence" :key="evidenceIndex">{{ evidence }}</pre>
          </div>
        </div>
      </details>
    </details>
  </details>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { AntiInstrumentationAssessment } from '@/types/analysis'
import type { RuntimeEvidenceStepStatus } from '@/types/common'
import type { KernSightAnalyzerJoin } from '@/types/monitoring'
import type { KnowledgePattern } from '@/types/knowledge'

const props = defineProps<{
  assessment: AntiInstrumentationAssessment
  platform: 'android' | 'ios'
  runtimeSteps: RuntimeEvidenceStepStatus[]
  kernSightJoin?: KernSightAnalyzerJoin | null
  ownershipRuleHits: KnowledgePattern[]
  importingKernSight?: boolean
}>()
const emit = defineEmits<{ openRuntime: []; openAi: []; openKernSight: []; importKernSight: []; importKernSightArchive: [] }>()
const injectionStep = computed(() => props.runtimeSteps.find((step) => step.key === 'injection'))
const activeCandidates = computed(() => props.assessment.candidates.filter((candidate) => !candidate.filtered))
const filteredCandidates = computed(() => props.assessment.candidates.filter((candidate) => candidate.filtered))
const hasKernSightFacts = computed(() => Boolean(props.kernSightJoin?.facts.some(item => item.strength !== 'absent')))
const presentFactCount = computed(() => props.kernSightJoin?.facts.filter(item => item.strength !== 'absent').length || 0)
const hasSubstantiveRuntime = computed(() => hasKernSightFacts.value || props.runtimeSteps.some((step) => step.key !== 'injection' && step.status === 'complete'))
const panelStatus = computed(() => props.platform === 'android' ? (hasKernSightFacts.value ? 'passed' : 'pending') : props.assessment.status)
const panelStatusLabel = computed(() => props.platform === 'android' ? (hasKernSightFacts.value ? '已关联证据' : '待 KernSight 证据') : statusLabel(props.assessment.status))
function factPresent(key: string) {
  return props.kernSightJoin?.facts.some(item => item.key === key && item.strength !== 'absent') || false
}
function strengthLabel(strength: string) {
  return ({
    confirmed: '证据强度 · confirmed',
    correlated: '证据强度 · correlated',
    inferred: '证据强度 · inferred',
    absent: '本层无证据',
  } as Record<string, string>)[strength] || strength
}
const candidateGroups = computed(() => {
  const groups = new Map<string, typeof props.assessment.candidates>()
  for (const candidate of props.assessment.candidates) {
    groups.set(candidate.label, [...(groups.get(candidate.label) || []), candidate])
  }
  return [...groups.entries()].map(([label, items]) => ({
    label,
    items,
    signalCount: new Set(items.map((item) => item.signal)).size,
  }))
})

const recommendations = computed(() => {
  const haystack = activeCandidates.value.map((item) => `${item.label} ${item.signal}`).join(' ').toLowerCase()
  const items: string[] = []
  if (/frida|gum-js|27042|27043|\/proc\/self|tracerpid/.test(haystack)) items.push(props.platform === 'android' ? '先完成 KernSight L0/L1 采集，确认相关文件、进程或内存检查是否在本轮实际出现。' : '先执行零 Hook 通道探针，确认脚本是否能进入进程并保持存活。')
  if (/ptrace|sysctl|exception_ports|dyld|syscall|fishhook|jmcode/.test(haystack)) items.push(props.platform === 'ios' ? '探针通过后，可继续运行“异常 / 终止追踪”或“观察 JMProtection / FishHook”定位实际触发点。' : '探针通过后，再结合运行日志确认检测代码是否真正执行，避免仅凭字符串定性。')
  if (/dobby|substrate|xposed|lsposed/.test(haystack)) items.push('命中插桩框架文件也可能来自应用自身 SDK；应结合已加载模块、线程和调用路径复核用途。')
  if (/classloader|loadedapk|dexpathlist|dexelements|attachbasecontext/.test(haystack)) items.push(props.platform === 'android' ? '类加载器接管也可能来自正常热修复；请结合 KernSight L2 的安装态 DEX、内存 DEX、SHA-256 与业务归属索引复核。' : '类加载器接管也可能来自正常热修复；请结合运行时类加载证据复核。')
  return items
})

function statusLabel(status: string) {
  return ({
    'not-detected': '未发现',
    pending: '待运行确认',
    blocked: '确认拦截',
    passed: '探针通过',
  } as Record<string, string>)[status] || status
}

function runtimeLabel(status: string) {
  return ({ pending: 'PENDING', blocked: 'BLOCKED', passed: 'PASSED' } as Record<string, string>)[status] || status.toUpperCase()
}
</script>

<style scoped>
.anti-panel { margin: 18px 0; border: 1px solid rgba(72, 135, 255, .24); border-radius: 16px; background: rgba(11, 18, 29, .58); }
.anti-panel > summary { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 16px 18px; cursor: pointer; list-style: none; }
.anti-panel > summary::-webkit-details-marker { display: none; }
.anti-summary-copy { display: grid; min-width: 0; gap: 7px; }
.anti-summary-title-row { display: flex; align-items: baseline; gap: 12px; min-width: 0; flex-wrap: wrap; }
.anti-panel > summary strong { font-size: 17px; }
.filtered-candidate { opacity: .62; }
.runtime-filtered { color: #94a3b8; border-color: rgba(148, 163, 184, .28); }
.filtered-reason { margin: 8px 0 0; color: #94a3b8; font-size: 12px; }
.anti-panel > summary small { color: var(--muted); }
.anti-intro, .anti-empty { margin: 0; padding: 0 18px 15px; color: var(--muted); line-height: 1.6; }
.anti-workflow { display: flex; align-items: center; gap: 8px; padding: 0 18px 14px; color: var(--muted); }
.anti-workflow span { display: flex; align-items: center; gap: 6px; font-size: 12px; white-space: nowrap; }
.anti-workflow span b { display: grid; place-items: center; width: 22px; height: 22px; border-radius: 50%; background: rgba(145,160,182,.14); }
.anti-workflow span.done { color: #63d6a5; }
.anti-workflow span.done b { background: rgba(65,204,145,.16); }
.anti-workflow i { height: 1px; flex: 1; min-width: 18px; background: rgba(255,255,255,.12); }
.anti-actions { display: flex; gap: 9px; flex-wrap: wrap; padding: 0 18px 14px; }
.anti-actions button { display: inline-flex; align-items: center; gap: 6px; }
.anti-actions button:disabled { opacity: .45; cursor: not-allowed; }
.runtime-coverage { display: flex; gap: 7px; flex-wrap: wrap; padding: 0 18px 14px; }
.runtime-coverage span { padding: 5px 8px; border-radius: 999px; color: #91a0b6; background: rgba(145,160,182,.1); font-size: 10px; }
.runtime-coverage span.done { color: #63d6a5; background: rgba(65,204,145,.13); }
.runtime-coverage span.blocked { color: #ff7b85; background: rgba(255,85,101,.13); }
.anti-recommendations { margin: 0 18px 14px; padding: 11px 14px 11px 30px; border-radius: 10px; color: var(--muted); background: rgba(67,126,225,.07); font-size: 12px; line-height: 1.6; }
.anti-candidate-group { margin: 0 18px 12px; border: 1px solid rgba(255,255,255,.08); border-radius: 12px; background: rgba(0,0,0,.16); overflow: hidden; }
.anti-candidate-group > summary { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 13px 14px; cursor: pointer; list-style: none; }
.anti-candidate-group > summary::-webkit-details-marker, .anti-candidate > summary::-webkit-details-marker { display: none; }
.anti-candidate-group > summary strong, .anti-candidate-group > summary small { display: block; }
.anti-candidate-group > summary small { margin-top: 3px; color: var(--muted); font-size: 11px; }
.anti-candidate-group > summary > span { transition: transform .16s ease; }
.anti-candidate-group[open] > summary > span { transform: rotate(180deg); }
.anti-candidate { border-top: 1px solid rgba(255,255,255,.07); }
.anti-candidate > summary { display: grid; grid-template-columns: minmax(180px,1fr) minmax(120px,.55fr) auto auto; align-items: center; gap: 10px; padding: 11px 14px; cursor: pointer; list-style: none; }
.anti-candidate > summary > code { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.candidate-signal { color: #8bb6ff; }
.candidate-chevron { color: var(--muted); transition: transform .16s ease; }
.anti-candidate[open] .candidate-chevron { transform: rotate(90deg); }
.anti-candidate-detail { padding: 0 14px 13px; }
.anti-panel code { overflow-wrap: anywhere; }
.anti-panel dl { display: grid; grid-template-columns: 54px minmax(0, 1fr); gap: 7px 12px; margin: 12px 0 0; font-size: 13px; }
.anti-panel dt { color: var(--muted); }
.anti-panel dd { margin: 0; min-width: 0; }
.anti-status, .runtime-badge { border-radius: 999px; padding: 5px 9px; font-size: 11px; letter-spacing: .05em; }
.status-pending, .runtime-pending { color: #f7c96b; background: rgba(247,201,107,.12); }
.status-blocked, .runtime-blocked { color: #ff7b85; background: rgba(255,85,101,.13); }
.status-passed, .runtime-passed { color: #63d6a5; background: rgba(65,204,145,.13); }
.status-not-detected { color: #91a0b6; background: rgba(145,160,182,.12); }
.anti-evidence { margin-top: 12px; }
.anti-evidence > strong { color: #8bb6ff; font-size: 12px; }
.anti-evidence pre { max-height: 180px; overflow: auto; padding: 10px; border-radius: 8px; background: #080c12; white-space: pre-wrap; word-break: break-word; font-size: 11px; }
.ks-runtime-join { margin: 0 18px 14px; padding: 12px; border: 1px solid rgba(57,125,246,.22); border-radius: 12px; background: rgba(57,125,246,.05); }
.ks-runtime-join > header { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; }
.ks-runtime-join > header strong, .ks-runtime-join > header small { display: block; }
.ks-runtime-join > header strong { font-size: 13px; }
.ks-runtime-join > header small { margin-top: 3px; color: var(--muted); font-size: 11px; }
.ks-runtime-source { min-width: 0; }
.ks-runtime-title { display: flex; align-items: center; gap: 7px; }
.ks-evidence-source { display: inline-block; margin-left: 6px; padding: 2px 6px; border-radius: 999px; color: #8fb6f6; background: rgba(57,125,246,.12); font-size: 9px; font-weight: 700; vertical-align: 1px; }
.ks-runtime-join-actions { display: flex; flex-wrap: wrap; gap: 7px; }
.ks-runtime-help { position: relative; }
.ks-runtime-help > summary { display: grid; width: 20px; height: 20px; place-items: center; border: 1px solid rgba(127,176,240,.35); border-radius: 50%; color: #8bb6ff; background: rgba(57,125,246,.08); cursor: pointer; font-size: 11px; font-weight: 800; list-style: none; }
.ks-runtime-help > summary::-webkit-details-marker { display: none; }
.ks-runtime-help > div { position: absolute; z-index: 8; top: 27px; left: 0; width: min(520px, calc(100vw - 96px)); padding: 13px; border: 1px solid var(--line-strong); border-radius: 11px; color: var(--text); background: var(--surface); box-shadow: 0 18px 45px rgba(0,0,0,.28); }
.ks-runtime-help p { margin: 7px 0 0; color: var(--muted); font-size: 11px; line-height: 1.6; }
.ks-runtime-help dl { margin-top: 9px; font-size: 10px; }
.ks-runtime-help code { color: #8bb6ff; }
.ks-runtime-metrics { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 10px; }
.ks-runtime-metrics span { padding: 5px 8px; border: 1px solid rgba(127,176,240,.18); border-radius: 999px; color: var(--muted); background: rgba(127,176,240,.045); font-size: 10px; }
.ks-runtime-metrics b { color: #8bb6ff; }
.ks-evidence-details { margin-top: 10px; border-top: 1px solid rgba(127,176,240,.15); }
.ks-evidence-details > summary { display: flex; align-items: center; justify-content: space-between; padding: 10px 2px 0; color: #7f98bd; cursor: pointer; font-size: 11px; list-style: none; }
.ks-evidence-details > summary::-webkit-details-marker { display: none; }
.ks-evidence-details > summary .material-symbols-outlined { font-size: 17px; transition: transform .16s ease; }
.ks-evidence-details[open] > summary .material-symbols-outlined { transform: rotate(180deg); }
.ownership-rule-summary { margin-top: 10px; padding: 9px 10px; border: 1px solid rgba(127,176,240,.18); border-radius: 9px; background: rgba(127,176,240,.045); }
.ownership-rule-summary header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.ownership-rule-summary header strong { font-size: 11px; }
.ownership-rule-summary header b { color: #7fb0f0; font-size: 10px; }
.ownership-rule-summary p { margin: 6px 0 0; color: var(--muted); font-size: 10px; line-height: 1.5; }
.ownership-rule-summary div { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 7px; }
.ownership-rule-summary span { padding: 4px 7px; border-radius: 999px; color: #8bb6ff; background: rgba(57,125,246,.1); font-size: 9px; }
.ks-runtime-workflow { padding: 12px 0 0; }
.ks-runtime-facts { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin-top: 12px; }
.ks-runtime-facts > article { min-width: 0; padding: 10px; border: 1px solid rgba(255,255,255,.08); border-radius: 10px; background: rgba(0,0,0,.16); }
.ks-runtime-facts header { display: flex; align-items: center; gap: 7px; }
.ks-runtime-facts header > b { padding: 2px 6px; border-radius: 4px; color: #7fb0f0; background: rgba(57,125,246,.12); font-size: 10px; }
.ks-runtime-facts header > strong { flex: 1; font-size: 12px; }
.ks-runtime-facts header > em { font-size: 10px; font-style: normal; }
.ks-runtime-facts p { margin: 7px 0 0; color: var(--muted); font-size: 11px; line-height: 1.5; }
.ks-runtime-facts code { display: block; overflow: hidden; margin-top: 4px; color: #8bb6ff; font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
.ks-fact-more { margin-top: 7px; }
.ks-fact-more summary { cursor: pointer; color: #7f98bd; font-size: 10px; }
.ks-fact-more[open] { max-height: 220px; overflow: auto; padding-right: 4px; }
.ks-fact-more[open] summary { position: sticky; top: 0; padding: 3px 0; background: #111a27; }
.ks-runtime-facts .strength-confirmed > header > em { color: #63d6a5; }
.ks-runtime-facts .strength-correlated > header > em { color: #4fb8d0; }
.ks-runtime-facts .strength-inferred > header > em { color: #d1a35b; }
.ks-runtime-facts .strength-absent > header > em { color: #91a0b6; }
@media (max-width: 720px) { .anti-panel > summary { align-items: flex-start; } .anti-summary-title-row { display: grid; gap: 4px; } .anti-candidate > summary { grid-template-columns: minmax(0,1fr) auto auto; } .candidate-signal { display: none; } .ks-runtime-facts { grid-template-columns: 1fr; } .ks-runtime-join > header { flex-direction: column; } }
</style>
