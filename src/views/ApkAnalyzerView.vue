<template>
  <div class="analyzer-layout">
    <section class="drop-zone panel" :class="{ dragging, 'has-analysis': !!analysis }" @dragover.prevent="dragging = true" @dragleave.prevent="dragging = false" @drop.prevent="onDrop">
      <span class="material-symbols-outlined">upload_file</span>
      <div class="drop-source-copy"><div class="eyebrow">APP SOURCE</div><h2>{{ selectedName || '导入 APK / IPA' }}</h2><p>拖入文件、选择本机文件，或直接粘贴绝对路径。分析始终在本机完成。</p></div>
      <div class="drop-path-row">
        <input v-model.trim="filePath" placeholder="/absolute/path/to/app.apk or app.ipa" @keyup.enter="analyze" />
        <button class="ghost-button" @click="chooseFile">选择文件</button>
        <button class="primary-button" :disabled="!filePath || analyzing" @click="analyze">{{ analyzing ? '分析中…' : '开始分析' }}</button>
      </div>
    </section>

    <section class="panel analyzer-card">
      <div class="section-title compact analyzer-title">
        <div><div class="eyebrow">STATIC INVENTORY</div><h2>App Analyzer</h2></div>
        <div class="analyzer-header-actions">
          <button v-if="analysis" class="ghost-button compact-button" :class="{ 'has-unsaved-assessment': assessmentDirty }" :title="`保存静态分析、人工结论和 ${scopedRuntimeHistory.length} 条当前包名运行记录`" @click="saveCase">保存快照{{ assessmentDirty ? ' · 未保存' : '' }}</button>
          <button class="ghost-button compact-button" @click="loadCase">打开快照</button>
          <button v-if="analysis" class="ghost-button compact-button" @click="emit('openAi')"><span class="material-symbols-outlined">neurology</span>AI Review</button>
          <button v-if="analysis" class="ghost-button compact-button" @click="focusOnly = !focusOnly">{{ focusOnly ? '重点视图' : '完整视图' }}</button>
          <details v-if="analysis" class="analyzer-more-actions">
            <summary class="ghost-button compact-button">更多 <span class="material-symbols-outlined">expand_more</span></summary>
            <div>
              <button class="ghost-button compact-button" @click="compareCase">基线对比</button>
              <button class="ghost-button compact-button" :disabled="exporting" @click="exportHtml(true)">{{ exporting ? '导出中…' : '导出 HTML（重点版）' }}</button>
              <button class="ghost-button compact-button" :disabled="exporting" @click="exportHtml(false)">导出 HTML（完整证据）</button>
              <small>当前包名运行记录：{{ scopedRuntimeHistory.length }}</small>
            </div>
          </details>
          <span class="live-pill" :class="{ online: !!analysis }">{{ analysis ? 'ANALYZED' : 'IDLE' }}</span>
        </div>
      </div>
      <section class="analyzer-config-summary">
        <div><span>Apktool</span><code>{{ apktoolPath || '未配置' }}</code></div>
        <div><span>JADX</span><code>{{ jadxPath || '未配置' }}</code></div>
        <div><span>URL 过滤</span><strong>{{ excludedUrlPatterns.length }} 条规则</strong></div>
        <div class="analyzer-config-actions">
          <button class="ghost-button" @click="emit('openSettings')"><span class="material-symbols-outlined">settings</span>分析器设置</button>
          <details class="analyzer-help-popover">
            <summary class="help-dot" title="查看分析器运行说明" aria-label="查看分析器运行说明">?</summary>
            <div>
              <strong>分析器运行说明</strong>
              <p>JADX / Apktool 在后台以 CLI 方式运行，不会打开 GUI。扫描完成后临时反编译目录会自动删除，终端进程短暂出现后消失属于正常完成。</p>
              <p>APK 的 JAR 工具需要 Java；IPA 的内置 Plist / Mach-O 分析不依赖 Java。</p>
            </div>
          </details>
        </div>
      </section>
      <div v-if="analyzing" class="analysis-progress"><div class="analysis-progress-bar"><i></i></div><strong>{{ progressSteps[progressStep] }}</strong><small>大型 APK、Flutter SO 或 JADX 反编译可能需要数分钟，请不要重复点击。</small></div>
      <div v-if="!analysis" class="analyzer-placeholder"><span class="material-symbols-outlined">policy</span><h3>等待 APK / IPA</h3><p>读取包名、版本、架构、权限、组件、签名摘要和敏感文件线索；不会上传文件，也不会默认提取密钥或敏感数据。</p></div>
      <template v-else>
        <p v-if="exportMessage" class="tool-used-line export-message">{{ exportMessage }}</p>
        <p v-if="sensitiveMessage" class="tool-used-line export-message">{{ sensitiveMessage }}</p>
        <div class="app-summary-grid">
          <div><span>Platform</span><strong>{{ analysis.platform.toUpperCase() }}</strong></div>
          <div><span>Bundle / Package</span><strong>{{ analysis.packageId || '—' }}</strong></div>
          <div><span>Name</span><strong>{{ analysis.displayName || '—' }}</strong></div>
          <div><span>{{ analysis.platform === 'ios' ? 'Version / Build' : 'Version' }}</span><strong>{{ analysis.versionName || '—' }} ({{ analysis.versionCode || '—' }})</strong></div>
          <div><span>Size</span><strong>{{ formatSize(analysis.fileSize) }}</strong></div>
          <div><span>Architectures</span><strong>{{ analysis.architectures.join(', ') || '未解析' }}</strong></div>
          <div><span>Likely framework</span><details class="summary-details"><summary>{{ analysis.frameworks[0] || 'Native / 未判断' }}</summary><p>{{ analysis.frameworks.join(', ') || 'Native / 未判断' }}</p></details></div>
          <div v-if="analysis.minSdk"><span>Min SDK</span><strong>{{ analysis.minSdk }}</strong></div>
          <div v-if="analysis.targetSdk"><span>Target SDK</span><strong>{{ analysis.targetSdk }}</strong></div>
          <div><span>Protection</span><strong :class="analysis.protection.status.includes('未命中') || analysis.protection.status.includes('未加密') || analysis.protection.status.includes('已经砸壳') ? 'safe' : 'warning'">{{ analysis.protection.status }}</strong></div>
          <div v-if="analysis.protection.packers.length"><span>Packer hints</span><strong>{{ analysis.protection.packers.join(', ') }}</strong></div>
          <div><span>Third-party libraries</span><details class="summary-details"><summary>{{ analysis.thirdPartyLibraries.length }} detected</summary><p>{{ analysis.thirdPartyLibraries.join(', ') || '未识别' }}</p></details></div>
          <div><span>Artifact SHA-256</span><strong :title="analysis.artifactSha256">{{ analysis.artifactSha256.slice(0, 16) }}…</strong></div>
        </div>
        <section class="scan-coverage" :class="{ incomplete: !analysis.scanCoverage.complete }">
          <header><div><strong>扫描覆盖度</strong><small>{{ analysis.scanCoverage.complete ? '本轮未触发扫描预算截断' : '本轮存在未扫描或被裁剪的数据' }}</small></div><b>{{ analysis.scanCoverage.complete ? 'COMPLETE' : 'PARTIAL' }}</b></header>
          <div class="coverage-grid"><div><span>归档索引</span><strong>{{ analysis.scanCoverage.archiveEntriesIndexed }} / {{ analysis.scanCoverage.archiveEntriesTotal }}</strong></div><div title="单个二进制文件最大深度分析 256 MB；每次最多选择 96 个候选"><span>深度二进制 · ≤256 MB</span><strong>{{ analysis.scanCoverage.binaryCandidatesScanned }} / {{ analysis.scanCoverage.binaryCandidatesTotal }}</strong></div><div><span>敏感线索</span><strong>{{ analysis.scanCoverage.sensitiveItemsReturned }} / {{ analysis.scanCoverage.sensitiveItemsDiscovered }}</strong></div><div><span>代码入口</span><strong>{{ analysis.scanCoverage.codeInsightsReturned }} / {{ analysis.scanCoverage.codeInsightsDiscovered }}</strong></div></div>
          <ul v-if="analysis.scanCoverage.warnings.length"><li v-for="warning in analysis.scanCoverage.warnings" :key="warning">{{ warning }}</li></ul>
        </section>
        <section v-if="baselineDiff" class="baseline-diff" :class="{ unchanged: !baselineDiff.changed }">
          <header><div><strong>基线对比 · {{ baselineDiff.baselineFileName }}</strong><small>{{ baselineDiff.changed ? '发现变化，展开查看新增与已消失证据' : '未发现受支持字段的变化' }}</small></div><button class="icon-button" @click="baselineDiff = null">×</button></header>
          <div class="baseline-metrics"><span>新增 Finding <b>{{ baselineDiff.addedFindings.length }}</b></span><span>已消失 Finding <b>{{ baselineDiff.resolvedFindings.length }}</b></span><span>新增敏感线索 <b>{{ baselineDiff.addedSensitiveItems.length }}</b></span><span>依赖变化 <b>{{ baselineDiff.addedLibraries.length + baselineDiff.removedLibraries.length }}</b></span></div>
          <details v-if="baselineDiff.changed"><summary>查看差异明细</summary><div class="baseline-columns"><div><strong>新增</strong><code v-for="item in [...baselineDiff.addedFindings, ...baselineDiff.addedSensitiveItems, ...baselineDiff.addedLibraries]" :key="`add-${item}`">+ {{ item }}</code></div><div><strong>已消失</strong><code v-for="item in [...baselineDiff.resolvedFindings, ...baselineDiff.resolvedSensitiveItems, ...baselineDiff.removedLibraries]" :key="`remove-${item}`">− {{ item }}</code></div></div></details>
        </section>
        <div v-if="analysis.missingDependencies.length" class="dependency-notice"><strong>分析能力提示</strong><p v-for="item in analysis.missingDependencies" :key="item">{{ item }}</p></div>
        <div class="tool-used-line">本次使用：{{ analysis.toolsUsed.join(' · ') }}</div>
        <section class="analyzer-flow-preview">
          <header><div><div class="eyebrow">DATA FLOW PREVIEW</div><strong>{{ boundaryFlows.length }} 条归并流程</strong><small>这里仅显示边界摘要；来源、去向和运行时关联统一放在 Data Flow 页面。</small></div><button class="ghost-button compact-button" @click="emit('openDataFlow')">打开 Data Flow <span class="material-symbols-outlined">arrow_forward</span></button></header>
          <div><article v-for="item in boundaryPreview" :key="item.boundary"><span>{{ item.label }}</span><strong>{{ item.count }}</strong></article><p v-if="!boundaryPreview.length">当前静态分析尚未形成可归并的数据边界。</p></div>
        </section>
        <nav class="analyzer-workspace-tabs" aria-label="分析结果工作区">
          <button v-for="item in workspaceTabs" :key="item.id" type="button" :class="{ active: activeWorkspace === item.id }" @click="activeWorkspace = item.id">
            <span class="material-symbols-outlined">{{ item.icon }}</span>
            <span><strong>{{ item.label }}</strong><small>{{ item.description }}</small></span>
            <b>{{ item.count }}</b>
          </button>
        </nav>

        <section v-show="activeWorkspace === 'evidence'" class="analyzer-workspace analyzer-workspace-evidence">
          <header class="analyzer-workspace-heading"><div><div class="eyebrow">STATIC ↔ RUNTIME</div><h3>证据关联</h3><p>按当前包名合并 KernSight session / dump 与静态候选；证据强度保持原样，不自动升级结论。</p></div><button class="ghost-button compact-button" @click="openPrimaryRuntime">{{ analysis.platform === 'android' ? '打开 KernSight' : '打开运行时工具' }}</button></header>
          <div id="analyzer-anti" class="analyzer-anchor-section" :class="{ focused: focusedSection === 'analyzer-anti' }"><AntiInstrumentationPanel
            :assessment="analysis.antiInstrumentation || { status: 'not-detected', candidates: [], indicators: [] }"
            :platform="analysis.platform"
            :runtime-steps="runtimeCoverage"
            :kern-sight-join="kernSightJoin"
            :ownership-rule-hits="ownershipRuleHits"
            :importing-kern-sight="importingKernSight"
            @open-runtime="emit('openRuntime')"
            @open-ai="emit('openAi')"
            @open-kern-sight="openKernSightChain"
            @import-kern-sight="importKernSightEvidence"
            @import-kern-sight-archive="importKernSightArchive"
          /></div>
        </section>

        <section v-show="activeWorkspace === 'validation'" class="analyzer-workspace">
          <header class="analyzer-workspace-heading"><div><div class="eyebrow">RISK VALIDATION</div><h3>风险验证</h3><p>先审阅静态攻击面与候选，再用 MASVS 矩阵记录人工或运行时结论。</p></div><button class="ghost-button compact-button" @click="emit('openAi', 'manifest-surface-review')"><span class="material-symbols-outlined">neurology</span>AI 辅助审阅</button></header>
          <div id="analyzer-static" class="analyzer-anchor-section" :class="{ focused: focusedSection === 'analyzer-static' }"><StaticSurfacePanel :analysis="analysis" @open-ai="emit('openAi', $event)" /></div>
          <div id="analyzer-masvs" class="analyzer-anchor-section" :class="{ focused: focusedSection === 'analyzer-masvs' }"><MasvsWorkbench
            :observations="analysis.masvsObservations"
            :recipes="analysis.verificationRecipes"
            :verdicts="assessmentVerdicts"
            :notes="assessmentNotes"
            :dirty="assessmentDirty"
            @verdict="setAssessmentVerdict"
            @update:notes="setAssessmentNotes"
            @open-ai="emit('openAi', $event)"
          /></div>
          <div id="analyzer-findings" class="findings-list analyzer-anchor-section" :class="{ focused: focusedSection === 'analyzer-findings' }"><h3>Review findings <small>{{ analysis.findings.length + analysis.protection.indicators.length }}</small></h3><article v-for="finding in analysis.findings" :key="finding.title + finding.detail"><b :class="`finding-${finding.severity}`">{{ finding.severity }}</b><div><strong>{{ finding.title }}</strong><p>{{ finding.detail }}</p></div></article><article v-for="indicator in analysis.protection.indicators" :key="indicator"><b class="finding-review">review</b><div><strong>加固/动态加载线索</strong><p>{{ indicator }}</p></div></article></div>
        </section>

        <section v-show="activeWorkspace === 'intelligence'" class="analyzer-workspace">
          <header class="analyzer-workspace-heading"><div><div class="eyebrow">CODE INTELLIGENCE</div><h3>代码与二进制</h3><p>聚焦业务入口、DEX / Mach-O / ELF 证据和动态加载线索；可随时切换重点或完整视图。</p></div><div class="analyzer-heading-actions"><button v-if="analysis.platform === 'android'" class="ghost-button compact-button" @click="emit('openAi', 'artifact-ownership')"><span class="material-symbols-outlined">neurology</span>AI 复核 DEX / SO</button><button class="ghost-button compact-button" @click="focusOnly = !focusOnly">{{ focusOnly ? '显示完整证据' : '返回重点视图' }}</button></div></header>
          <section v-if="analysis.platform === 'android'" class="artifact-ownership-card">
            <header>
              <div><div class="eyebrow">KERNSIGHT OWNERSHIP</div><strong>DEX / SO 业务归属</strong><p>{{ kernSightJoin ? `${kernSightJoin.sourceLabel} · ${kernSightJoin.dexOwnershipMode === 'class-index' ? '类级索引' : '旧版路径降级'} · ${ownershipRuleHits.length} 条本地规则命中` : '当前 APK 尚未关联 KernSight 运行时证据。' }}</p></div>
              <div><button v-if="!kernSightJoin" class="ghost-button compact-button" @click="openKernSightChain">先用 ksightd 采集</button><button v-else class="ghost-button compact-button" @click="openKernSightChain">查看完整证据链</button></div>
            </header>
            <div v-if="kernSightJoin" class="artifact-ownership-grid">
              <article v-for="fact in ownershipFacts" :key="fact.key" :class="`strength-${fact.strength}`">
                <div><b>{{ fact.layer }}</b><strong>{{ fact.title }}</strong><em>{{ fact.strength }}</em></div>
                <p>{{ fact.summary }}</p>
                <code v-for="line in fact.items.slice(0, 5)" :key="line">{{ line }}</code>
                <small v-if="fact.items.length > 5">另有 {{ fact.items.length - 5 }} 条，进入 KernSight 查看完整来源与映射链。</small>
              </article>
            </div>
            <footer><span>确定性分类负责事实</span><i></i><span>AI 只复核 mixed / unknown</span><i></i><span>确认后写入本地规则库</span><i></i><span>后续 APK 自动匹配</span></footer>
          </section>
          <p class="focus-view-hint"><strong>{{ focusOnly ? '重点视图' : '完整原始视图' }}</strong>：{{ focusOnly ? '优先展示业务类/方法、真实 Endpoint、TLS、Keychain、动态加载和 CodeProtect 映射；隐藏 SDK/编译器通用词、格式化模板及构建路径。' : '显示全部可恢复证据，可能包含 Swift/Foundation/NIO/OpenCV 等第三方内部噪音。' }}</p>
          <div id="analyzer-code" class="analyzer-anchor-section" :class="{ focused: focusedSection === 'analyzer-code' }"><CodeIntelligencePanel :items="analysis.codeInsights" :focus-only="focusOnly" /></div>
          <div id="analyzer-binary" class="analyzer-anchor-section" :class="{ focused: focusedSection === 'analyzer-binary' }"><BinaryInsightsPanel :items="analysis.binaryInsights" :focus-only="focusOnly" /></div>
        </section>

        <section v-show="activeWorkspace === 'sensitive'" class="analyzer-workspace">
          <header class="analyzer-workspace-heading"><div><div class="eyebrow">SENSITIVE MATERIAL</div><h3>敏感信息</h3><p>单独审阅密钥、凭据、端点和可能的隐私数据，避免与一般代码线索混排。</p></div></header>
          <div id="analyzer-sensitive" class="analyzer-anchor-section" :class="{ focused: focusedSection === 'analyzer-sensitive' }"><SensitiveItemsPanel :items="analysis.sensitiveItems" :file-name="analysis.fileName" :focus-only="focusOnly" @message="sensitiveMessage = $event" /></div>
        </section>

        <section v-show="activeWorkspace === 'raw'" class="analyzer-workspace">
          <header class="analyzer-workspace-heading"><div><div class="eyebrow">RAW INVENTORY</div><h3>原始清单</h3><p>签名、Manifest 与归档文件仅在需要追溯原始解析结果时展开。</p></div></header>
          <details v-if="analysis.signature" class="manifest-panel"><summary>签名与证书详情</summary><pre>{{ analysis.signature }}</pre></details>
          <details class="manifest-panel" v-if="analysis.platform === 'android' && analysis.manifestXml"><summary>AndroidManifest.xml（AXML / aapt 解码结果）</summary><pre>{{ analysis.manifestXml }}</pre></details>
          <details class="file-inventory"><summary>Interesting archive entries（{{ visibleFiles(analysis.files).length }} / {{ analysis.files.length }}）</summary><code v-for="file in visibleFiles(analysis.files)" :key="file">{{ file }}</code></details>
        </section>
      </template>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { open, save } from '@tauri-apps/plugin-dialog'
import { aiBackend, backend, readableError } from '@/services/backend'
import { appConfig } from '@/services/config'
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow'
import BinaryInsightsPanel from '@/components/analyzer/BinaryInsightsPanel.vue'
import AntiInstrumentationPanel from '@/components/analyzer/AntiInstrumentationPanel.vue'
import CodeIntelligencePanel from '@/components/analyzer/CodeIntelligencePanel.vue'
import MasvsWorkbench from '@/components/analyzer/MasvsWorkbench.vue'
import SensitiveItemsPanel from '@/components/analyzer/SensitiveItemsPanel.vue'
import StaticSurfacePanel from '@/components/analyzer/StaticSurfacePanel.vue'
import { buildBoundaryFlows, correlateBoundaries } from '@/services/boundaries'
import { runtimeEvidenceCoverage } from '@/services/runtimeCoverage'
import { useKernSightEvidence } from '@/composables/useKernSightEvidence'
import type { AnalysisBaselineDiff, AnalysisCase, AppAnalysis, TerminalEntry } from '@/types'
import type { KnowledgePattern } from '@/types/knowledge'

const props = defineProps<{ analysis: AppAnalysis | null; analyzing: boolean; history: TerminalEntry[]; focusRequest?: { id: string; sourceType: string; sourceLocation?: string } }>()
const emit = defineEmits<{ analyze: [request: { path: string; apktoolPath?: string; jadxPath?: string; excludedUrlPatterns?: string[] }]; openAi: [taskId?: string]; openRuntime: []; openDataFlow: []; openSettings: []; openKernSight: []; replaceAnalysis: [analysis: AppAnalysis]; restoreRuntimeHistory: [history: TerminalEntry[]]; focusConsumed: [] }>()
const filePath = ref('')
const selectedName = ref('')
const dragging = ref(false)
const apktoolPath = computed(() => appConfig.apktoolPath)
const jadxPath = computed(() => appConfig.jadxPath)
const excludedUrlsText = computed(() => appConfig.excludedUrls)
const exporting = ref(false)
const exportMessage = ref('')
const sensitiveMessage = ref('')
const assessmentVerdicts = ref<Record<string, string>>({})
const assessmentNotes = ref('')
const assessmentDirty = ref(false)
const baselineDiff = ref<AnalysisBaselineDiff | null>(null)
let pendingLoadedCase: AnalysisCase | null = null
const focusOnly = ref(true)
const activeWorkspace = ref<'evidence' | 'validation' | 'intelligence' | 'sensitive' | 'raw'>('evidence')
const focusedSection = ref('')
const progressStep = ref(0)
const progressSteps = ['读取 APK/IPA 文件清单…', '解析 Manifest / Info.plist…', '运行 Apktool/JADX 回退分析…', '扫描 DEX、SO、Mach-O 与 Flutter 字符串…', '整理风险、组件和敏感信息上下文…']
let unlistenDrop: (() => void) | undefined
let progressTimer: ReturnType<typeof setInterval> | undefined

const scopedRuntimeHistory = computed(() => {
  const appId = props.analysis?.packageId?.trim().toLowerCase()
  if (!appId) return []
  return props.history.filter((entry) => entry.appId?.trim().toLowerCase() === appId).slice(0, 500)
})
const boundaryFlows = computed(() => buildBoundaryFlows(correlateBoundaries(props.analysis, props.history, props.analysis?.platform || 'unknown').items))
const boundaryPreview = computed(() => {
  const labels: Record<string, string> = { network: '网络出口', tls: 'TLS / 信任', webview: 'WebView / 桥接', storage: '本地存储', identity: '身份 / 会话', crypto: '密码学', 'dynamic-code': '动态代码', 'runtime-code': '运行时代码', 'runtime-integrity': '运行时保护', 'anti-instrumentation': '注入保护' }
  return Object.entries(boundaryFlows.value.reduce<Record<string, number>>((counts, flow) => ({ ...counts, [flow.boundary]: (counts[flow.boundary] || 0) + 1 }), {}))
    .map(([boundary, count]) => ({ boundary, count, label: labels[boundary] || boundary }))
    .sort((left, right) => right.count - left.count)
    .slice(0, 8)
})

const runtimeCoverage = computed(() => runtimeEvidenceCoverage(
  scopedRuntimeHistory.value,
  props.analysis?.platform || 'android',
  props.analysis?.packageId,
))
const importingKernSight = ref(false)
const ownershipKnowledge = ref<KnowledgePattern[]>([])
const kernSight = useKernSightEvidence(computed(() => props.analysis?.packageId || ''))
const kernSightJoin = computed(() => props.analysis?.platform === 'android' ? kernSight.join.value : null)
const ownershipRuleHits = computed(() => {
  const analysis = props.analysis
  if (!analysis) return []
  const haystack = [
    ...analysis.files,
    ...analysis.frameworks,
    ...analysis.thirdPartyLibraries,
    ...analysis.rawInventory.map(item => item.value),
    ...analysis.binaryInsights.flatMap(item => [item.target, item.detail, ...item.evidence]),
    ...analysis.codeInsights.flatMap(item => [item.binary, item.className || '', item.name, ...item.references]),
  ].join('\n').toLowerCase()
  return ownershipKnowledge.value.filter(pattern =>
    ['artifact-ownership', 'vendor-sdk', 'dynamic-code', 'native-bridge'].includes(pattern.boundary)
    && pattern.triggerSignals.some(signal => signal.trim() && haystack.includes(signal.trim().toLowerCase())),
  )
})
const ownershipFacts = computed(() => kernSightJoin.value?.facts.filter(item => item.key === 'dex' || item.key === 'so') || [])
const workspaceTabs = computed(() => {
  const analysis = props.analysis
  if (!analysis) return []
  const runtimeCount = (kernSightJoin.value?.facts.filter((item) => item.strength !== 'absent').length || 0)
    + (analysis.antiInstrumentation?.candidates.filter((item) => !item.filtered).length || 0)
  return [
    { id: 'evidence' as const, icon: 'hub', label: '证据关联', description: '静态 ↔ 运行时', count: runtimeCount },
    { id: 'validation' as const, icon: 'verified_user', label: '风险验证', description: '攻击面 · MASVS', count: analysis.masvsObservations.length + analysis.findings.length },
    { id: 'intelligence' as const, icon: 'data_object', label: '代码与二进制', description: 'DEX · SO · Mach-O', count: analysis.codeInsights.length + analysis.binaryInsights.length },
    { id: 'sensitive' as const, icon: 'key', label: '敏感信息', description: '凭据 · 端点 · 隐私', count: analysis.sensitiveItems.length },
    { id: 'raw' as const, icon: 'inventory_2', label: '原始清单', description: '签名 · Manifest · 文件', count: analysis.files.length },
  ]
})

async function importKernSightEvidence() {
  importingKernSight.value = true
  try {
    const bundle = await kernSight.importDirectory()
    if (bundle && props.analysis?.packageId && bundle.package !== props.analysis.packageId) {
      exportMessage.value = `已接入 ${bundle.package}，与当前静态分析包名 ${props.analysis.packageId} 不一致；证据不会混用。`
    } else if (bundle) {
      exportMessage.value = `已接入 KernSight 证据：${bundle.package}`
    }
  } catch (cause) {
    exportMessage.value = `接入 KernSight 证据失败：${readableError(cause)}`
  } finally {
    importingKernSight.value = false
  }
}

async function importKernSightArchive() {
  importingKernSight.value = true
  try {
    const bundle = await kernSight.importArchive()
    if (bundle && props.analysis?.packageId && bundle.package !== props.analysis.packageId) {
      exportMessage.value = `证据包属于 ${bundle.package}，与当前静态分析包名 ${props.analysis.packageId} 不一致；证据不会混用。`
    } else if (bundle) {
      exportMessage.value = `已打开 MobileE 证据包：${bundle.package}`
    }
  } catch (cause) {
    exportMessage.value = `打开 MobileE 证据包失败：${readableError(cause)}`
  } finally {
    importingKernSight.value = false
  }
}

async function loadOwnershipKnowledge() {
  if (props.analysis?.platform !== 'android') {
    ownershipKnowledge.value = []
    return
  }
  try {
    ownershipKnowledge.value = await aiBackend.listKnowledge()
  } catch {
    ownershipKnowledge.value = []
  }
}

function openKernSightChain() {
  if (props.analysis?.packageId) kernSight.requestPackage(props.analysis.packageId)
  emit('openKernSight')
}

function openPrimaryRuntime() {
  if (props.analysis?.platform === 'android') openKernSightChain()
  else emit('openRuntime')
}

const excludedUrlPatterns = computed(() => excludedUrlsText.value
  .split(/\r?\n/)
  .map((value) => value.trim())
  .filter((value) => value && !value.startsWith('#')))

function useFile(file?: File) {
  dragging.value = false
  if (!file) return
  selectedName.value = file.name
  const possiblePath = (file as File & { path?: string }).path
  if (possiblePath) filePath.value = possiblePath
}
function onDrop(event: DragEvent) { useFile(event.dataTransfer?.files?.[0]) }
async function analyze() {
  if (!filePath.value) return
  if (/\.(?:mee|meevidence|mobileevidence)$/i.test(filePath.value)) {
    importingKernSight.value = true
    try {
      const bundle = await kernSight.importArchive(filePath.value)
      if (bundle) {
        kernSight.requestPackage(bundle.package)
        exportMessage.value = `已载入 ${bundle.package} 的 MobileE 证据，正在打开证据链。`
        emit('openKernSight')
      }
    } catch (cause) {
      exportMessage.value = `打开 MobileE 证据失败：${readableError(cause)}`
    } finally {
      importingKernSight.value = false
    }
    return
  }
  if (/\.(?:mec|mecase|mobileecase|mskcase|json)$/i.test(filePath.value)) {
    try {
      await restoreAnalysisCase(filePath.value)
    } catch (cause) {
      exportMessage.value = `打开 MobileE 分析案例失败：${readableError(cause)}`
    }
    return
  }
  emit('analyze', {
    path: filePath.value,
    apktoolPath: apktoolPath.value || undefined,
    jadxPath: jadxPath.value || undefined,
    excludedUrlPatterns: excludedUrlPatterns.value,
  })
}
async function chooseFile() {
  const selected = await open({ multiple: false, filters: [{ name: 'Mobile packages / cases', extensions: ['apk', 'ipa', 'mec', 'mee', 'mecase', 'meevidence', 'mobileecase', 'mobileevidence', 'mskcase', 'json'] }] })
  if (typeof selected === 'string') {
    filePath.value = selected
    selectedName.value = selected.split(/[\\/]/).pop() || selected
  }
}
async function exportHtml(compact: boolean) {
  if (!props.analysis || exporting.value) return
  exporting.value = true
  exportMessage.value = ''
  try {
    const baseName = props.analysis.fileName.replace(/\.(apk|ipa)$/i, '') || 'app-analysis'
    const suggested = `${baseName}-${compact ? '重点版' : '完整证据版'}.html`
    const outputPath = await save({
      defaultPath: suggested,
      filters: [{ name: 'HTML report', extensions: ['html'] }],
    })
    if (!outputPath) return
    const written = await backend.exportAnalysisHtml(props.analysis, outputPath, compact, assessmentVerdicts.value, assessmentNotes.value)
    exportMessage.value = `${compact ? '重点版' : '完整证据版'} HTML 报告已导出：${written}`
  } catch (cause) {
    exportMessage.value = `HTML 导出失败：${readableError(cause)}`
  } finally {
    exporting.value = false
  }
}

function setAssessmentVerdict(controlId: string, verdict: string) {
  assessmentVerdicts.value = { ...assessmentVerdicts.value, [controlId]: verdict }
  assessmentDirty.value = true
}

function setAssessmentNotes(notes: string) {
  assessmentNotes.value = notes
  assessmentDirty.value = true
}
async function saveCase() {
  if (!props.analysis) return
  const baseName = props.analysis.fileName.replace(/\.(apk|ipa)$/i, '') || 'mobile-assessment'
  const outputPath = await save({ defaultPath: `${baseName}.mec`, filters: [{ name: 'ME case', extensions: ['mec'] }] })
  if (!outputPath) return
  try {
    const written = await backend.saveAnalysisCase(outputPath, props.analysis, assessmentVerdicts.value, assessmentNotes.value, scopedRuntimeHistory.value)
    assessmentDirty.value = false
    exportMessage.value = `项目快照已保存：${written}（包含 ${scopedRuntimeHistory.value.length} 条当前 App 运行记录）`
  } catch (cause) {
    exportMessage.value = `保存项目快照失败：${readableError(cause)}`
  }
}
async function restoreAnalysisCase(path: string) {
  const loaded = await backend.loadAnalysisCase(path)
  pendingLoadedCase = loaded
  baselineDiff.value = null
  emit('restoreRuntimeHistory', (loaded.runtimeHistory || []).map((entry) => ({ ...entry, persisted: true })))
  emit('replaceAnalysis', loaded.analysis)
  exportMessage.value = `已打开 MobileE 案例：${path}（恢复 ${(loaded.runtimeHistory || []).length} 条运行记录）`
}
async function loadCase() {
  const selected = await open({ multiple: false, filters: [{ name: 'ME case', extensions: ['mec', 'mecase', 'mobileecase', 'mskcase', 'json'] }] })
  if (typeof selected !== 'string') return
  try {
    await restoreAnalysisCase(selected)
  } catch (cause) {
    exportMessage.value = `打开 MobileE 案例失败：${readableError(cause)}`
  }
}
async function compareCase() {
  if (!props.analysis) return
  const selected = await open({ multiple: false, filters: [{ name: 'ME case', extensions: ['mec', 'mecase', 'mobileecase', 'mskcase', 'json'] }] })
  if (typeof selected !== 'string') return
  try {
    baselineDiff.value = await backend.compareAnalysisCase(selected, props.analysis)
    exportMessage.value = baselineDiff.value.changed ? '基线对比完成：发现变化。' : '基线对比完成：未发现受支持字段变化。'
  } catch (cause) {
    exportMessage.value = `基线对比失败：${readableError(cause)}`
  }
}
function formatSize(bytes: number) { return `${(bytes / 1024 / 1024).toFixed(2)} MB` }
function visibleFiles(files: string[]) {
  const noise = /(^|\/)(Runner|Assets\.car|PkgInfo|CodeResources|AppFrameworkInfo\.plist|.*privacy\.bun)$/i
  return files.filter((file) => !noise.test(file)).slice(0, 300)
}

onMounted(async () => {
  await loadOwnershipKnowledge()
  try {
    const webview = getCurrentWebviewWindow()
    unlistenDrop = await webview.onDragDropEvent((event) => {
      const payload = event.payload as { type: string; paths?: string[] }
      if (payload.type === 'drop' && payload.paths?.[0]) {
        filePath.value = payload.paths[0]
        selectedName.value = payload.paths[0].split(/[\\/]/).pop() || payload.paths[0]
        dragging.value = false
      }
    })
  } catch {
    // Browser preview does not expose Tauri's native drag/drop event.
  }
})

watch(() => props.analyzing, (value) => {
  if (progressTimer) clearInterval(progressTimer)
  progressTimer = undefined
  progressStep.value = 0
  if (value) {
    progressTimer = setInterval(() => {
      progressStep.value = Math.min(progressStep.value + 1, progressSteps.length - 1)
    }, 2800)
  }
})
watch(() => props.analysis?.packageId, async (packageId) => {
  if (!packageId || props.analysis?.platform !== 'android') return
  try {
    await kernSight.importForPackage(packageId)
  } catch {
    // Parent directory unknown or dump missing; user can import manually.
  }
}, { immediate: true })
watch(() => props.analysis?.artifactSha256, (value) => {
  baselineDiff.value = null
  sensitiveMessage.value = ''
  activeWorkspace.value = 'evidence'
  if (pendingLoadedCase && pendingLoadedCase.analysis.artifactSha256 === value) {
    assessmentVerdicts.value = { ...pendingLoadedCase.verdicts }
    assessmentNotes.value = pendingLoadedCase.notes
    assessmentDirty.value = false
    pendingLoadedCase = null
    return
  }
  assessmentVerdicts.value = {}
  assessmentNotes.value = ''
  assessmentDirty.value = false
  void loadOwnershipKnowledge()
})
watch(() => props.focusRequest?.id, async () => {
  const request = props.focusRequest
  if (!request || !props.analysis) return
  const sectionBySource: Record<string, string> = {
    'static-code': 'analyzer-code', binary: 'analyzer-binary', sensitive: 'analyzer-sensitive',
    manifest: 'analyzer-static', protection: 'analyzer-anti', 'runtime-blocked': 'analyzer-anti',
    runtime: 'analyzer-code', 'runtime-observed': 'analyzer-code', 'static-correlated': 'analyzer-code',
  }
  focusedSection.value = sectionBySource[request.sourceType] || 'analyzer-static'
  activeWorkspace.value = ({
    'analyzer-anti': 'evidence',
    'analyzer-static': 'validation',
    'analyzer-masvs': 'validation',
    'analyzer-findings': 'validation',
    'analyzer-code': 'intelligence',
    'analyzer-binary': 'intelligence',
    'analyzer-sensitive': 'sensitive',
  } as const)[focusedSection.value] || 'validation'
  focusOnly.value = false
  exportMessage.value = `来自 Data Flow 的 Source ID：${request.id}${request.sourceLocation ? ` · ${request.sourceLocation}` : ''}`
  await nextTick()
  document.getElementById(focusedSection.value)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  emit('focusConsumed')
  window.setTimeout(() => { focusedSection.value = '' }, 2600)
}, { immediate: true })

onBeforeUnmount(() => {
  unlistenDrop?.()
  if (progressTimer) clearInterval(progressTimer)
})
</script>
