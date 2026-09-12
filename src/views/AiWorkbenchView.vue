<template>
  <section class="ai-workbench">
    <ScrollAnchorNav :anchors="aiAnchors" @navigate="navigateAiAnchor" />
    <header class="ai-hero">
      <div>
        <div class="eyebrow">MODEL-READY CONTEXT BUILDER</div>
        <h2>AI Context / Review（本地证据整理）</h2>
        <p>先在本机生成低噪声 Context Pack，再按严格 Evidence ID 约定调用云端或本地模型。模型只能提出经证据约束的 hypothesis / verified finding，不能替代运行时验证。</p>
      </div>
      <div class="ai-hero-actions">
        <div class="ai-state-legend">
          <span><i class="static"></i>static candidate</span>
          <span><i class="runtime"></i>runtime observed</span>
          <span><i class="confirmed"></i>runtime confirmed</span>
          <span><i class="hypothesis"></i>AI hypothesis</span>
        </div>
        <button class="ghost-button ai-knowledge-open" @click="openKnowledgeLibrary">
          <span class="material-symbols-outlined">library_books</span>知识库
        </button>
        <button class="ghost-button ai-knowledge-open" @click="rulesOpen = true">
          <span class="material-symbols-outlined">rule_folder</span>规则库
        </button>
      </div>
    </header>

    <div v-if="!analysis" class="empty-state ai-empty">
      <span class="material-symbols-outlined">neurology</span>
      <h3>先导入 APK / IPA</h3>
      <p>App Analyzer 的结构化结果是 Context Pack 的事实底座；ADB / Frida 终端历史会作为运行时边界证据一起参与检索。</p>
    </div>

    <template v-else>
      <section class="ai-source-strip">
        <div><small>APP</small><strong>{{ analysis.displayName || analysis.fileName }}</strong><code>{{ analysis.packageId || analysis.platform }}</code></div>
        <div><small>STATIC</small><strong>{{ analysis.dataBoundaries.length }}</strong><span>边界候选</span></div>
        <div><small>RUNTIME · HISTORY</small><strong>{{ terminalRuntimeEvidence.length }}</strong><span>{{ analysis.packageId ? `仅 ${analysis.packageId}` : '未解析包名，仅静态证据' }}</span></div>
        <div :class="{ 'source-ready': kernSightJoin }"><small>KERNSIGHT · L0/L1/L2</small><strong>{{ kernSightFacts.length }}</strong><span>{{ kernSightJoin ? `${kernSightJoin.sessionId || '本地包证据'} · ${kernSightJoin.fileCount} files` : '尚未接入包证据' }}</span></div>
        <div><small>CODE</small><strong>{{ analysis.codeInsights.length }}</strong><span>代码入口</span></div>
      </section>

      <section class="ai-evidence-fusion" :class="{ ready: kernSightJoin }">
        <header>
          <div><div class="eyebrow">STATIC ↔ RUNTIME EVIDENCE JOIN</div><strong>{{ kernSightJoin ? 'KernSight 证据已进入 AI Context' : '当前 AI 只有静态结果与终端历史' }}</strong></div>
          <span>{{ kernSightJoin ? '按包名隔离 · 不自动升级结论' : 'WAITING FOR L2' }}</span>
        </header>
        <p v-if="!kernSightJoin">在 KernSight 的包证据区导入与当前包名一致的报告后，这里会把 L0/L1/L2 摘要作为独立 Evidence ID 送入 AI。不会把整份原始明文或全部文件无差别塞给模型。</p>
        <template v-else>
          <div class="ai-fusion-metrics">
            <span><small>已接入事实</small><strong>{{ kernSightFacts.length }}</strong></span>
            <span><small>名称/路径候选对齐</small><strong>{{ codeAlignment.matched }}</strong></span>
            <span><small>仅运行时出现</small><strong>{{ codeAlignment.runtimeOnly }}</strong></span>
            <span><small>物理文件</small><strong>{{ kernSightJoin.fileCount }}</strong></span>
          </div>
          <div class="ai-fusion-facts">
            <span v-for="fact in kernSightFacts" :key="fact.key" :data-strength="fact.strength"><b>{{ fact.layer }}</b>{{ fact.title }}<small>{{ fact.strength }}</small></span>
          </div>
          <p>{{ kernSightJoin.disclaimer }} DEX/SO 的名称或路径相同只算候选对齐；后续应优先补 SHA-256 / Build ID，再做类、方法、Endpoint 与内存映射的确定性关联。</p>
        </template>
      </section>

      <div class="ai-grid">
        <aside class="ai-config-panel">
          <header><span class="material-symbols-outlined">tune</span><div><strong>Review Workspace</strong><small>证据整理和低 Token 审查</small></div></header>

          <label class="ai-field">
            <span>分析任务</span>
            <select v-model="taskId">
              <option v-for="task in tasks" :key="task.id" :value="task.id">{{ task.label }}</option>
            </select>
          </label>
          <div v-if="selectedTask" class="ai-task-description">
            <p>{{ selectedTask.description }}</p>
            <ul><li v-for="goal in selectedTask.reviewGoals" :key="goal">{{ goal }}</li></ul>
          </div>

          <label class="ai-field"><span>Context 字符预算 <b>{{ maxChars.toLocaleString() }}</b></span><input v-model.number="maxChars" type="range" min="8000" max="120000" step="4000" /></label>
          <label class="ai-field"><span>最大证据数</span><input v-model.number="maxEvidenceItems" type="number" min="20" max="600" /></label>
          <label class="ai-field"><span>单条证据字符上限</span><input v-model.number="maxEvidenceChars" type="number" min="240" max="2400" /></label>

          <label class="ai-inline-option"><input v-model="includeLowConfidence" type="checkbox" /> 纳入低置信度代码入口</label>
          <details class="ai-token-contract"><summary>低 Token / 证据约定</summary><ul><li>自动构建任务相关 Context Pack，只发送入选 Evidence，不发送重复分块元数据。</li><li>最多 8 个高价值结论、6 个下一步动作；静态候选不能升级为已验证漏洞。</li><li>证据不足时说明缺口，并精确建议需要逆向的二进制、类、Selector 或调用点。</li></ul></details>
          <button class="primary-button ai-build-button" :disabled="providerRunning || building" @click="runProviderReview">
            <span class="material-symbols-outlined" :class="{ spinning: providerRunning }">{{ providerRunning ? 'sync' : 'neurology' }}</span>
            {{ providerRunning ? '正在构建并审查…' : '运行 AI 审查' }}
          </button>
          <button class="ghost-button ai-build-button ai-run-all" :disabled="providerRunning || building || batchRunning" @click="runAllTasks">
            <span class="material-symbols-outlined" :class="{ spinning: batchRunning }">{{ batchRunning ? 'sync' : 'playlist_play' }}</span>
            {{ batchRunning ? `全任务审查 ${batchProgress.done}/${batchProgress.total}` : `一键全任务分析（${tasks.length}）` }}
          </button>
          <div v-if="batchRunning || batchProgress.total" class="ai-batch-progress">
            <div><span :style="{ width: `${batchProgress.total ? batchProgress.done / batchProgress.total * 100 : 0}%` }"></span></div>
            <small>{{ batchProgress.current || `已完成 ${batchProgress.done} / ${batchProgress.total}` }}</small>
          </div>
          <small class="ai-provider-hint">可直接运行；模型若返回 Markdown、&lt;think&gt; 或格式不完整的 JSON，MobileE 会自动提取并修复一次。</small>
          <button class="ghost-button ai-build-button" :disabled="providerRunning || building" @click="buildPack">
            <span class="material-symbols-outlined" :class="{ spinning: building }">{{ building ? 'sync' : 'inventory_2' }}</span>
            {{ building ? '正在构建…' : '生成证据包（不调用 AI）' }}
          </button>
          <details class="ai-token-contract"><summary>证据包、复制与导出的区别</summary><ul><li><b>运行 AI 审查：</b>自动生成证据包并调用当前 Provider，结果会直接回填并校验。</li><li><b>生成证据包：</b>只在本机整理 App 与运行时证据，不调用模型。</li><li><b>复制完整 Pack：</b>适合模型上下文足够时，一次粘贴全部证据。</li><li><b>复制当前分块：</b>只复制当前页的 Evidence，适合上下文较小的模型分批审查。</li><li><b>导出 JSON：</b>保存同一份完整 Pack 到文件，用于留档、换电脑或交给其他模型。</li></ul></details>
          <p v-if="message" class="ai-message" :class="{ error: messageIsError }">{{ message }}</p>
        </aside>

        <main class="ai-main-panel">
          <section v-if="batchResults.length" class="ai-batch-results">
            <header><div><div class="eyebrow">ALL TASK REVIEW</div><strong>全任务串行结果</strong></div><small>{{ batchResults.length }} 任务 · {{ batchSuccessCount }} 成功 · {{ batchFailureCount }} 失败 · {{ batchFindingCount }} findings · {{ batchProposalCount }} 规则提议</small></header>
            <div>
              <button v-for="result in batchResults" :key="result.task.id" :class="{ active: pack?.task.id === result.task.id, failed: !!result.error }" @click="selectBatchResult(result)">
                <span class="material-symbols-outlined">{{ result.error ? 'error' : 'check_circle' }}</span>
                <strong>{{ result.task.label }}</strong>
                <small v-if="result.validation" :title="result.validation.normalizedResult.summary">{{ result.validation.normalizedResult.findings.length }} findings · {{ result.validation.normalizedResult.hypotheses.length }} hypotheses · {{ (result.validation.normalizedResult.proposedPatterns?.length || 0) + (result.validation.normalizedResult.proposedExclusions?.length || 0) }} proposals</small>
                <small v-else>{{ result.error }}</small>
              </button>
            </div>
          </section>

          <div v-if="!pack && !batchResults.length" class="ai-placeholder">
            <span class="material-symbols-outlined">dataset</span>
            <h3>选择任务并运行 AI 审查</h3>
            <p>程序会自动构建当前任务的 Context Pack，并使用齿轮设置中保存的 Provider、模型和 API Key 直接发起审查。</p>
          </div>

          <template v-if="pack">
            <section class="ai-pack-header">
              <div><span class="material-symbols-outlined">inventory_2</span><div><strong>{{ pack.task.label }}</strong><small>{{ pack.schemaVersion }} · 生成于 {{ formatDateTime(pack.generatedAt) }}</small></div></div>
              <div class="ai-pack-actions">
                <button class="ghost-button" title="复制包含全部 Evidence 的完整模型输入" @click="copyFullPack">复制完整 Pack</button>
                <button class="ghost-button" title="仅复制当前 Evidence 分块，供小上下文模型分批处理" @click="copySelectedChunk">复制当前分块</button>
                <button class="ghost-button" title="把完整 Pack 保存为本地 JSON 留档" @click="exportPack">导出 Pack JSON</button>
                <button class="ghost-button" title="高级功能：导入其他模型返回的 MobileE JSON" @click="openExternalResult"><span class="material-symbols-outlined">upload_file</span>外部结果</button>
              </div>
            </section>

            <section class="ai-pack-stats">
              <article><strong>{{ pack.evidence.length }}</strong><small>入选证据</small></article>
              <article><strong>{{ pack.chunks.length }}</strong><small>上下文分块</small></article>
              <article><strong>≈ {{ pack.estimatedTokens.toLocaleString() }}</strong><small>估算 Tokens</small></article>
              <article><strong>{{ pack.omittedEvidenceCount }}</strong><small>预算外省略</small></article>
              <article><strong>{{ pack.uncoveredTokens.length }}</strong><small>未覆盖原始线索</small></article>
            </section>

            <section v-if="pack.knowledgeHits.length" class="ai-knowledge-panel">
              <header><div><div class="eyebrow">KNOWLEDGE HITS</div><strong>历史知识命中提示</strong></div><small>仅作复核线索，不等于当前 App 已确认存在风险</small></header>
              <article v-for="pattern in pack.knowledgeHits" :key="pattern.patternId" class="ai-knowledge-card">
                <div><strong>{{ pattern.title }}</strong><span>{{ pattern.boundary }}</span></div>
                <p>触发信号：{{ pattern.triggerSignals.join(' · ') }}</p>
                <small>验证建议：{{ pattern.playbook.join(' → ') }}</small>
              </article>
            </section>

            <div class="ai-chunk-tabs">
              <button v-for="chunk in pack.chunks" :key="chunk.id" :class="{ active: selectedChunkId === chunk.id }" @click="selectedChunkId = chunk.id">
                <strong>{{ chunk.id }}</strong><small>{{ chunk.evidenceIds.length }} 条 · ≈{{ chunk.estimatedTokens }} tokens</small>
              </button>
            </div>

            <section v-if="selectedChunk" :id="`ai-chunk-${selectedChunk.id}`" class="ai-evidence-section">
              <header><div><strong>{{ selectedChunk.title }}</strong><small>{{ Object.entries(selectedChunk.boundaryCounts).map(([key, count]) => `${key} ${count}`).join(' · ') || 'mixed evidence' }}</small></div><span>{{ selectedChunk.characterCount.toLocaleString() }} chars</span></header>
              <div class="ai-evidence-list">
                <article v-for="item in selectedEvidence" :key="item.id" class="ai-evidence-card">
                  <div class="ai-evidence-title">
                    <code>{{ item.id }}</code>
                    <span :class="`state-${item.observationState}`">{{ item.observationState }}</span>
                    <span class="severity">{{ item.severity }}</span>
                    <strong>{{ item.title }}</strong>
                  </div>
                  <p>{{ item.summary }}</p>
                  <dl>
                    <div v-if="item.boundary"><dt>Boundary</dt><dd>{{ item.boundary }}</dd></div>
                    <div v-if="item.framework"><dt>Framework</dt><dd>{{ item.framework }}</dd></div>
                    <div v-if="item.endpoint"><dt>Endpoint</dt><dd><code>{{ item.endpoint }}</code></dd></div>
                    <div v-if="item.operation"><dt>Operation</dt><dd><code>{{ item.operation }}</code></dd></div>
                    <div v-if="item.location"><dt>Source</dt><dd><code>{{ item.location }}</code></dd></div>
                  </dl>
                  <ul v-if="item.lines.length"><li v-for="(line, index) in item.lines" :key="`${item.id}-${index}`"><code>{{ line }}</code></li></ul>
                </article>
              </div>
            </section>
          </template>
        </main>
      </div>

      <AiReviewResults v-if="validation" :validation="validation" :confirmed-pattern-ids="confirmedPatternIds" :confirmed-exclusion-ids="confirmedExclusionIds" @copy-normalized="copyNormalizedResult" @confirm-pattern="confirmPattern" @confirm-exclusion="confirmExclusion" />
    </template>

    <AiExternalResultDialog v-model="resultJson" :open="externalResultOpen" :validating="validating" :error="externalResultError" @close="externalResultOpen = false" @copy-template="copyResultTemplate" @validate="validateResult" />
    <RuleLibraryDrawer :open="rulesOpen" @close="rulesOpen = false" />

    <div v-if="knowledgeOpen" class="knowledge-overlay" @click.self="knowledgeOpen = false">
      <aside class="knowledge-drawer" role="dialog" aria-modal="true" aria-label="MobileE 经验知识库">
        <header>
          <div><div class="eyebrow">LOCAL KNOWLEDGE LIBRARY</div><h3>经验知识库</h3><p>人工确认的经验保存在本机；导入时按 Pattern ID 或触发信号自动去重合并。</p></div>
          <button class="icon-button" title="关闭" @click="knowledgeOpen = false"><span class="material-symbols-outlined">close</span></button>
        </header>

        <section class="knowledge-stats">
          <article><strong>{{ knowledgePatterns.length }}</strong><small>全部经验</small></article>
          <article><strong>{{ knowledgeBoundaries.length }}</strong><small>安全边界</small></article>
          <article><strong>{{ knowledgeHitIds.size }}</strong><small>当前 Pack 命中</small></article>
          <article><strong>{{ verifiedKnowledgeCount }}</strong><small>已有验证记录</small></article>
        </section>

        <div class="knowledge-toolbar">
          <label><span class="material-symbols-outlined">search</span><input v-model="knowledgeQuery" placeholder="搜索名称、信号、框架或 App" /></label>
          <select v-model="knowledgeBoundary"><option value="">全部边界</option><option v-for="boundary in knowledgeBoundaries" :key="boundary" :value="boundary">{{ boundary }}</option></select>
          <button class="ghost-button" :disabled="knowledgeBusy" @click="importKnowledge"><span class="material-symbols-outlined">upload_file</span>导入</button>
          <button class="primary-button" :disabled="knowledgeBusy || !knowledgePatterns.length" @click="exportKnowledge"><span class="material-symbols-outlined">download</span>导出</button>
        </div>
        <p v-if="knowledgeMessage" class="knowledge-message" :class="{ error: knowledgeMessageError }">{{ knowledgeMessage }}</p>

        <div v-if="knowledgeBusy && !knowledgePatterns.length" class="knowledge-empty">正在读取本地知识库…</div>
        <div v-else-if="!filteredKnowledge.length" class="knowledge-empty">没有符合筛选条件的经验。</div>
        <section v-else class="knowledge-list">
          <article v-for="pattern in filteredKnowledge" :key="pattern.patternId" class="knowledge-pattern-card" :class="{ hit: knowledgeHitIds.has(pattern.patternId) }">
            <header><div><span>{{ pattern.boundary }}</span><em v-if="knowledgeHitIds.has(pattern.patternId)">当前 Pack 命中</em><em v-if="!pattern.verifiedIn.length" class="static-pattern">静态经验</em><h4>{{ pattern.title }}</h4></div><code>{{ pattern.patternId }}</code></header>
            <div class="knowledge-card-section"><strong>触发信号</strong><div class="knowledge-tags"><span v-for="signal in pattern.triggerSignals" :key="signal">{{ signal }}</span></div></div>
            <div class="knowledge-card-section"><strong>验证步骤</strong><ol><li v-for="step in pattern.playbook" :key="step">{{ step }}</li></ol></div>
            <div v-if="pattern.reusableFor.length" class="knowledge-card-section"><strong>适用范围</strong><p>{{ pattern.reusableFor.join(' · ') }}</p></div>
            <div v-if="pattern.verifiedIn.length" class="knowledge-card-section verified"><strong>已验证 App</strong><p>{{ pattern.verifiedIn.join(' · ') }}</p></div>
            <details v-if="Object.keys(pattern.evidenceSchema || {}).length"><summary>查看证据结构</summary><pre>{{ JSON.stringify(pattern.evidenceSchema, null, 2) }}</pre></details>
          </article>
        </section>
      </aside>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'
import { open, save } from '@tauri-apps/plugin-dialog'
import { aiBackend } from '@/services/backend'
import { appConfig } from '@/services/config'
import { correlateBoundaries } from '@/services/boundaries'
import { useKernSightEvidence } from '@/composables/useKernSightEvidence'
import { formatDateTime } from '@/utils/time'
import ScrollAnchorNav from '@/components/ScrollAnchorNav.vue'
import AiExternalResultDialog from '@/components/ai/AiExternalResultDialog.vue'
import AiReviewResults from '@/components/ai/AiReviewResults.vue'
import RuleLibraryDrawer from '@/components/RuleLibraryDrawer.vue'
import type { AiContextPack, AiProviderRequest, AiTaskTemplate, AiValidationReport, AppAnalysis, DataBoundaryObservation, DeviceSummary, ExclusionRule, KnowledgePattern, TerminalEntry } from '@/types'

interface BatchTaskResult { task: AiTaskTemplate; pack?: AiContextPack; validation?: AiValidationReport; error?: string }

const props = defineProps<{ analysis: AppAnalysis | null; history: TerminalEntry[]; device?: DeviceSummary | null; taskRequest?: { id: number; taskId: string } }>()
const tasks = ref<AiTaskTemplate[]>([])
const taskId = ref('attack-surface')
const maxChars = ref(24000)
const maxEvidenceItems = ref(80)
const maxEvidenceChars = ref(700)
const includeLowConfidence = ref(false)
const building = ref(false)
const validating = ref(false)
const pack = ref<AiContextPack | null>(null)
const selectedChunkId = ref('')
const resultJson = ref('')
const validation = ref<AiValidationReport | null>(null)
const message = ref('')
const messageIsError = ref(false)
const providerRunning = ref(false)
const knowledgeOpen = ref(false)
const rulesOpen = ref(false)
const knowledgeBusy = ref(false)
const knowledgePatterns = ref<KnowledgePattern[]>([])
const knowledgeQuery = ref('')
const knowledgeBoundary = ref('')
const knowledgeMessage = ref('')
const knowledgeMessageError = ref(false)
const confirmedPatternIds = ref(new Set<string>())
const confirmedExclusionIds = ref(new Set<string>())
const batchRunning = ref(false)
const batchResults = ref<BatchTaskResult[]>([])
const batchProgress = ref({ done: 0, total: 0, current: '' })
const externalResultOpen = ref(false)
const externalResultError = ref('')

const selectedTask = computed(() => tasks.value.find((task) => task.id === taskId.value))
const correlated = computed(() => correlateBoundaries(props.analysis, props.history, props.analysis?.platform || props.device?.platform || 'unknown', props.device?.serial))
const terminalRuntimeEvidence = computed(() => correlated.value.items.filter((item) => item.sourceType === 'runtime' || item.sourceType === 'runtime-observed' || item.sourceType === 'static-correlated' || item.confidence === 'runtime-confirmed'))
const kernSight = useKernSightEvidence(computed(() => props.analysis?.packageId || ''))
const kernSightJoin = computed(() => props.analysis?.platform === 'android' ? kernSight.join.value : null)
const kernSightFacts = computed(() => kernSightJoin.value?.facts.filter((fact) => fact.strength !== 'absent') || [])
const kernSightEvidence = computed<DataBoundaryObservation[]>(() => kernSightFacts.value.map((fact) => ({
  id: `kernsight-${kernSightJoin.value?.sessionId || 'bundle'}-${fact.key}`,
  boundary: ({ sni: 'network', tls: 'tls', binder: 'ipc', dex: 'dynamic-code', so: 'native-bridge', private: 'storage', heap: 'storage', jni: 'native-bridge' } as Record<string, string>)[fact.key] || 'runtime-integrity',
  direction: 'observed',
  title: `KernSight ${fact.layer} · ${fact.title}`,
  summary: fact.summary,
  sourceType: fact.strength === 'confirmed' ? 'runtime' : `kernsight-${fact.strength}`,
  sourceLocation: kernSightJoin.value?.root,
  platform: 'android',
  dataTypes: [fact.layer, fact.strength, fact.key],
  severity: 'info',
  confidence: fact.strength === 'confirmed' ? 'runtime-observed' : fact.strength,
  evidence: fact.items,
})))
const runtimeEvidence = computed(() => [...terminalRuntimeEvidence.value, ...kernSightEvidence.value])
const codeAlignment = computed(() => {
  const staticNames = new Set((props.analysis?.files || []).map((path) => path.split(/[\\/]/).pop()?.toLowerCase()).filter(Boolean))
  const runtimeItems = kernSightFacts.value.filter((fact) => fact.key === 'dex' || fact.key === 'so').flatMap((fact) => fact.items)
  const matched = runtimeItems.filter((path) => staticNames.has(path.split(/[\\/]/).pop()?.toLowerCase())).length
  return { matched, runtimeOnly: Math.max(0, runtimeItems.length - matched) }
})
const selectedChunk = computed(() => pack.value?.chunks.find((chunk) => chunk.id === selectedChunkId.value) || pack.value?.chunks[0])
const selectedEvidence = computed(() => {
  const ids = new Set(selectedChunk.value?.evidenceIds || [])
  return pack.value?.evidence.filter((item) => ids.has(item.id)) || []
})
const knowledgeBoundaries = computed(() => [...new Set(knowledgePatterns.value.map((item) => item.boundary).filter(Boolean))].sort())
const verifiedKnowledgeCount = computed(() => knowledgePatterns.value.filter((item) => item.verifiedIn.length).length)
const knowledgeHitIds = computed(() => new Set((pack.value?.knowledgeHits || []).map((item) => item.patternId)))
const filteredKnowledge = computed(() => {
  const query = knowledgeQuery.value.trim().toLowerCase()
  return knowledgePatterns.value.filter((item) => {
    if (knowledgeBoundary.value && item.boundary !== knowledgeBoundary.value) return false
    if (!query) return true
    return [item.title, item.patternId, item.boundary, ...item.triggerSignals, ...item.playbook, ...item.reusableFor, ...item.verifiedIn]
      .some((value) => value.toLowerCase().includes(query))
  })
})
const aiAnchors = computed(() => (pack.value?.chunks || []).map((chunk) => ({ id: `ai-chunk-${chunk.id}`, label: chunk.title || chunk.id })))
const batchSuccessCount = computed(() => batchResults.value.filter((item) => item.validation).length)
const batchFailureCount = computed(() => batchResults.value.filter((item) => item.error).length)
const batchFindingCount = computed(() => batchResults.value.reduce((sum, item) => sum + (item.validation?.normalizedResult.findings.length || 0), 0))
const batchProposalCount = computed(() => batchResults.value.reduce((sum, item) => sum + (item.validation?.normalizedResult.proposedPatterns?.length || 0) + (item.validation?.normalizedResult.proposedExclusions?.length || 0), 0))

async function navigateAiAnchor(id: string) {
  const chunkId = id.replace(/^ai-chunk-/, '')
  if (pack.value?.chunks.some((chunk) => chunk.id === chunkId)) selectedChunkId.value = chunkId
  await nextTick()
}

function setMessage(value: string, isError = false) {
  message.value = value
  messageIsError.value = isError
}

async function loadKnowledge() {
  knowledgeBusy.value = true
  knowledgeMessage.value = ''
  try {
    knowledgePatterns.value = await aiBackend.listKnowledge()
  } catch (error) {
    knowledgeMessage.value = `读取知识库失败：${String(error)}`
    knowledgeMessageError.value = true
  } finally {
    knowledgeBusy.value = false
  }
}

async function openKnowledgeLibrary() {
  knowledgeOpen.value = true
  await loadKnowledge()
}

async function exportKnowledge() {
  const outputPath = await save({ defaultPath: 'mobilee-knowledge.json', filters: [{ name: 'MobileE Knowledge', extensions: ['json'] }] })
  if (!outputPath) return
  knowledgeBusy.value = true
  try {
    const written = await aiBackend.exportKnowledge(outputPath)
    knowledgeMessage.value = `知识库已导出：${written}`
    knowledgeMessageError.value = false
  } catch (error) {
    knowledgeMessage.value = `导出失败：${String(error)}`
    knowledgeMessageError.value = true
  } finally {
    knowledgeBusy.value = false
  }
}

async function importKnowledge() {
  const inputPath = await open({ multiple: false, filters: [{ name: 'MobileE Knowledge', extensions: ['json'] }] })
  if (!inputPath) return
  knowledgeBusy.value = true
  try {
    const report = await aiBackend.importKnowledge(inputPath)
    knowledgePatterns.value = await aiBackend.listKnowledge()
    knowledgeMessage.value = `导入 ${report.imported} 条：新增 ${report.created} 条，合并 ${report.merged} 条，当前共 ${report.total} 条。重新生成 Context Pack 后即可参与匹配。`
    knowledgeMessageError.value = false
  } catch (error) {
    knowledgeMessage.value = `导入失败：${String(error)}`
    knowledgeMessageError.value = true
  } finally {
    knowledgeBusy.value = false
  }
}

function providerRequest(): AiProviderRequest {
  return {
    providerKind: appConfig.aiProviderKind,
    baseUrl: appConfig.aiProviderBaseUrl,
    apiKey: appConfig.aiProviderApiKey || undefined,
    model: appConfig.aiProviderModel,
    timeoutSeconds: Math.max(10, appConfig.aiProviderTimeout || 120),
    maxOutputTokens: Math.max(400, appConfig.aiProviderOutputTokens || 2000),
  }
}

async function runProviderReview() {
  if (!props.analysis) return
  providerRunning.value = true
  validation.value = null
  setMessage('')
  try {
    const activePack = await createPack()
    const review = await aiBackend.runSecurityReview(providerRequest(), activePack)
    resultJson.value = review.rawResult
    validation.value = review.validation
    confirmedPatternIds.value = new Set()
    confirmedExclusionIds.value = new Set()
    setMessage(`AI 审查完成：输入约 ${review.inputEstimatedTokens} tokens，输出约 ${review.outputEstimatedTokens} tokens。`, !review.validation.valid)
  } catch (error) {
    setMessage(`AI 审查失败：${String(error)}`, true)
  } finally {
    providerRunning.value = false
  }
}

async function createPack(activeTaskId = taskId.value, updateCurrent = true): Promise<AiContextPack> {
  if (!props.analysis) throw new Error('请先导入 APK / IPA。')
  const created = await aiBackend.buildContextPack({
    analysis: props.analysis,
    runtimeObservations: runtimeEvidence.value,
    taskId: activeTaskId,
    options: {
      maxChars: maxChars.value,
      maxEvidenceItems: maxEvidenceItems.value,
      maxEvidenceChars: maxEvidenceChars.value,
      redactSensitive: false,
      // The context keeps evidence identifiers and redacted previews. Raw
      // credentials remain local unless a future explicit opt-in is added.
      includeRawSensitiveValues: false,
      includeLowConfidence: includeLowConfidence.value,
    },
  })
  if (updateCurrent) {
    pack.value = created
    selectedChunkId.value = created.chunks[0]?.id || ''
  }
  return created
}

async function runAllTasks() {
  if (!props.analysis || !tasks.value.length) return
  batchRunning.value = true
  batchResults.value = []
  batchProgress.value = { done: 0, total: tasks.value.length, current: '' }
  validation.value = null
  setMessage('')
  for (const task of tasks.value) {
    batchProgress.value.current = `正在审查：${task.label}`
    try {
      const taskPack = await createPack(task.id, false)
      const review = await aiBackend.runSecurityReview(providerRequest(), taskPack)
      batchResults.value.push({ task, pack: taskPack, validation: review.validation })
    } catch (error) {
      batchResults.value.push({ task, error: String(error) })
    }
    batchProgress.value.done += 1
  }
  batchRunning.value = false
  batchProgress.value.current = ''
  const first = batchResults.value.find((item) => item.validation)
  if (first) selectBatchResult(first)
  setMessage(`全任务审查完成：${batchSuccessCount.value} 成功，${batchFailureCount.value} 失败；单项失败未中断后续任务。`, batchSuccessCount.value === 0)
}

function selectBatchResult(result: BatchTaskResult) {
  if (!result.pack || !result.validation) {
    setMessage(`${result.task.label} 失败：${result.error || '未知错误'}`, true)
    return
  }
  taskId.value = result.task.id
  pack.value = result.pack
  validation.value = result.validation
  selectedChunkId.value = result.pack.chunks[0]?.id || ''
}

async function buildPack() {
  building.value = true
  validation.value = null
  setMessage('')
  try {
    const created = await createPack()
    setMessage(`Context Pack 已生成：${created.evidence.length} 条证据，省略 ${created.omittedEvidenceCount} 条低优先级候选。`)
  } catch (error) {
    setMessage(String(error), true)
  } finally {
    building.value = false
  }
}

function chunkPayload() {
  if (!pack.value || !selectedChunk.value) return null
  return {
    schemaVersion: pack.value.schemaVersion,
    task: pack.value.task,
    app: pack.value.app,
    safetyRules: pack.value.safetyRules,
    analysisInstructions: pack.value.analysisInstructions,
    chunk: selectedChunk.value,
    evidence: selectedEvidence.value,
    uncoveredTokens: pack.value.uncoveredTokens,
    resultSchema: pack.value.resultSchema,
  }
}

async function copy(value: unknown, success: string) {
  try {
    await navigator.clipboard.writeText(typeof value === 'string' ? value : JSON.stringify(value, null, 2))
    setMessage(success)
  } catch (error) {
    setMessage(`复制失败：${String(error)}`, true)
  }
}

const copyFullPack = () => pack.value && copy(pack.value, '完整 Context Pack 已复制。')
const copySelectedChunk = () => copy(chunkPayload(), '当前证据分块已复制，可单独交给模型分析。')
const copyNormalizedResult = () => validation.value && copy(validation.value.normalizedResult, '规范化 AI 结果已复制。')

function openExternalResult() {
  resultJson.value = ''
  externalResultError.value = ''
  externalResultOpen.value = true
}

function emptyResultTemplate() {
  return {
    schemaVersion: 'mobilee.ai-analysis-result/v1',
    summary: '',
    hypotheses: [],
    findings: [],
    missingEvidence: [],
    recommendedNextObservations: [],
    confidence: 'medium',
    model: { provider: '', model: '', generatedAt: new Date().toISOString() },
    proposedPatterns: [],
    proposedExclusions: [],
  }
}
const copyResultTemplate = () => copy(emptyResultTemplate(), 'AI 结果 JSON 模板已复制。')

async function exportPack() {
  if (!pack.value) return
  const outputPath = await save({ defaultPath: `${props.analysis?.fileName || 'app'}-${pack.value.task.id}-ai-context.json`, filters: [{ name: 'JSON', extensions: ['json'] }] })
  if (!outputPath) return
  try {
    const written = await aiBackend.exportContextPack(pack.value, outputPath)
    setMessage(`已导出：${written}`)
  } catch (error) {
    setMessage(String(error), true)
  }
}

async function validateResult() {
  if (!pack.value || !resultJson.value.trim()) return
  validating.value = true
  externalResultError.value = ''
  try {
    validation.value = await aiBackend.validateResult(pack.value, resultJson.value)
    confirmedPatternIds.value = new Set()
    setMessage(validation.value.valid ? 'AI 结果已通过证据引用校验。' : 'AI 结果包含未知 Evidence ID，已保留错误提示。', !validation.value.valid)
    if (validation.value.valid) externalResultOpen.value = false
    else externalResultError.value = validation.value.issues.map((issue) => issue.message).slice(0, 4).join('；') || '外部结果未通过证据引用校验。'
  } catch (error) {
    validation.value = null
    externalResultError.value = String(error)
    setMessage(`外部 AI 结果导入失败：${String(error)}`, true)
  } finally {
    validating.value = false
  }
}

async function confirmPattern(pattern: KnowledgePattern) {
  if (!hasMeaningfulPatternTitle(pattern.title)) {
    setMessage('知识模式缺少明确名称，已阻止入库；请重新运行审查，让模型给出可读、可区分的模式名称。', true)
    return
  }
  if (!pattern.triggerSignals.some((signal) => signal.trim())) {
    setMessage(`知识模式 ${pattern.title} 缺少可字面匹配的 triggerSignals，已阻止无效规则入库；请重新运行审查让模型补充信号。`, true)
    return
  }
  try {
    const mutation = await aiBackend.mergePattern(pattern)
    confirmedPatternIds.value = new Set([...confirmedPatternIds.value, pattern.patternId])
    await loadKnowledge()
    setMessage(mutation.created ? `知识模式已入库：${mutation.pattern.title}` : `知识模式已合并：${mutation.pattern.title}`)
  } catch (error) {
    setMessage(`知识模式入库失败：${String(error)}`, true)
  }
}

function hasMeaningfulPatternTitle(title: string) {
  const normalized = title.trim().toLowerCase()
  return !!normalized && !['未命名', '未命名模式', '无标题', 'untitled', 'unknown', 'n/a', 'none'].includes(normalized)
}

async function confirmExclusion(rule: ExclusionRule) {
  try {
    const normalized = normalizeExclusionForSave(rule)
    const mutation = await aiBackend.mergeExclusion(normalized)
    confirmedExclusionIds.value = new Set([...confirmedExclusionIds.value, mutation.rule.exclusionId])
    setMessage(mutation.created ? `排除规则已写入：${mutation.rule.reason}` : `排除规则已更新：${mutation.rule.reason}`)
  } catch (error) {
    setMessage(`排除规则保存失败：${String(error)}`, true)
  }
}

function looksLikeRustRegex(pattern: string) {
  const normalized = pattern.trim()
  if (!normalized || normalized.length > 4096) return false
  // The backend uses Rust's regex crate. Keep the frontend validator aligned
  // with it instead of accepting JavaScript-only lookarounds/backreferences
  // that would later be escaped or rejected by the backend.
  if (/\(\?[=!<]|\\[1-9]/.test(normalized)) return false
  try {
    new RegExp(normalized)
    return true
  } catch {
    return false
  }
}

function isOverlyBroadExclusion(pattern: string) {
  return /^(?:\.\*|\.\+|\(\?s\)\.\*)$/.test(pattern.trim())
}

function normalizeExclusionForSave(rule: ExclusionRule): ExclusionRule {
  const signals = new Set(rule.excludeSignals.map((value) => value.trim()).filter(Boolean))
  const patterns: string[] = []
  for (const value of rule.excludePatterns) {
    const pattern = value.trim()
    if (!pattern) continue
    if (looksLikeRustRegex(pattern) && !isOverlyBroadExclusion(pattern)) patterns.push(pattern)
    else signals.add(pattern)
  }
  return {
    ...rule,
    exclusionId: rule.exclusionId.trim(),
    appliesToKind: rule.appliesToKind.trim().toLowerCase(),
    reason: rule.reason.trim(),
    excludeSignals: [...signals],
    excludePatterns: [...new Set(patterns)],
    verifiedIn: [...new Set(rule.verifiedIn.map((value) => value.trim()).filter(Boolean))],
  }
}

watch(() => props.analysis?.artifactSha256 || props.analysis?.path, () => {
  pack.value = null
  validation.value = null
  resultJson.value = ''
  confirmedPatternIds.value = new Set()
  confirmedExclusionIds.value = new Set()
  batchResults.value = []
  batchProgress.value = { done: 0, total: 0, current: '' }
  externalResultOpen.value = false
  externalResultError.value = ''
})

watch(() => props.analysis?.packageId, async (packageName) => {
  if (packageName && props.analysis?.platform === 'android' && !kernSightJoin.value) {
    await kernSight.importForPackage(packageName)
  }
}, { immediate: true })

watch(() => props.taskRequest, (requested) => {
  if (requested && tasks.value.some((task) => task.id === requested.taskId)) taskId.value = requested.taskId
})

onMounted(async () => {
  try {
    tasks.value = await aiBackend.listTaskTemplates()
    const requested = props.taskRequest?.taskId
    if (requested && tasks.value.some((task) => task.id === requested)) taskId.value = requested
    else if (!tasks.value.some((task) => task.id === taskId.value)) taskId.value = tasks.value[0]?.id || 'attack-surface'
  } catch (error) {
    setMessage(`读取 AI 任务模板失败：${String(error)}`, true)
  }
})
</script>

<style scoped src="../assets/ai-workbench.css"></style>
