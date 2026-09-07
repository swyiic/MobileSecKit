<template>
  <div class="analyzer-layout">
    <ScrollAnchorNav :anchors="analyzerAnchors" />
    <section class="drop-zone panel" :class="{ dragging }" @dragover.prevent="dragging = true" @dragleave.prevent="dragging = false" @drop.prevent="onDrop">
      <input ref="fileInput" type="file" accept=".apk,.ipa,application/vnd.android.package-archive" @change="onSelect" />
      <span class="material-symbols-outlined">upload_file</span>
      <div><h2>{{ selectedName || 'Drop APK / IPA Here' }}</h2><p>{{ filePath || '拖拽文件或输入本机绝对路径，分析过程在本机完成。' }}</p></div>
      <div class="drop-actions"><button class="primary-button" @click="chooseFile">选择本机文件</button><button class="ghost-button" @click="fileInput?.click()">浏览器文件</button></div>
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
      <div class="analyzer-path-row"><input v-model.trim="filePath" placeholder="/absolute/path/to/app.apk or app.ipa" @keyup.enter="analyze" /><button class="primary-button" :disabled="!filePath || analyzing" @click="analyze">{{ analyzing ? '分析中…' : '开始分析' }}</button></div>
      <section class="analyzer-config-summary">
        <div><span>Apktool</span><code>{{ apktoolPath || '未配置' }}</code></div>
        <div><span>JADX</span><code>{{ jadxPath || '未配置' }}</code></div>
        <div><span>URL 过滤</span><strong>{{ excludedUrlPatterns.length }} 条规则</strong></div>
        <button class="ghost-button" @click="emit('openSettings')"><span class="material-symbols-outlined">settings</span>分析器设置</button>
      </section>
      <p class="tool-behavior-note">JADX/Apktool 以后台 CLI 方式运行，不会打开 GUI；扫描完成后临时反编译目录会自动删除，所以终端进程短暂出现后消失属于正常完成，不是闪退。APK 的 JAR 工具需要 Java，IPA 的内置 Plist/Mach-O 分析不依赖 Java。</p>
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
        <div id="analyzer-anti" class="analyzer-anchor-section" :class="{ focused: focusedSection === 'analyzer-anti' }"><AntiInstrumentationPanel
          :assessment="analysis.antiInstrumentation || { status: 'not-detected', candidates: [], indicators: [] }"
          :platform="analysis.platform"
          :runtime-steps="runtimeCoverage"
          :kern-sight-join="kernSightJoin"
          :importing-kern-sight="importingKernSight"
          @open-runtime="emit('openRuntime')"
          @open-ai="emit('openAi')"
          @open-kern-sight="openKernSightChain"
          @import-kern-sight="importKernSightEvidence"
        /></div>
        <div id="analyzer-masvs" class="analyzer-anchor-section" :class="{ focused: focusedSection === 'analyzer-masvs' }"><MasvsWorkbench
          :observations="analysis.masvsObservations"
          :recipes="analysis.verificationRecipes"
          :verdicts="assessmentVerdicts"
          :notes="assessmentNotes"
          :dirty="assessmentDirty"
          @verdict="setAssessmentVerdict"
          @update:notes="setAssessmentNotes"
        /></div>
        <details v-if="analysis.signature" class="manifest-panel"><summary>签名与证书详情</summary><pre>{{ analysis.signature }}</pre></details>
        <div id="analyzer-static" class="analyzer-anchor-section" :class="{ focused: focusedSection === 'analyzer-static' }"><StaticSurfacePanel :analysis="analysis" /></div>
        <p class="focus-view-hint"><strong>{{ focusOnly ? '重点视图' : '完整原始视图' }}</strong>：{{ focusOnly ? '优先展示业务类/方法、真实 Endpoint、TLS、Keychain、动态加载和 CodeProtect 映射；隐藏 SDK/编译器通用词、格式化模板及构建路径。' : '显示全部可恢复证据，可能包含 Swift/Foundation/NIO/OpenCV 等第三方内部噪音。' }}</p>
        <div id="analyzer-code" class="analyzer-anchor-section" :class="{ focused: focusedSection === 'analyzer-code' }"><CodeIntelligencePanel :items="analysis.codeInsights" :focus-only="focusOnly" /></div>
        <div id="analyzer-binary" class="analyzer-anchor-section" :class="{ focused: focusedSection === 'analyzer-binary' }"><BinaryInsightsPanel :items="analysis.binaryInsights" :focus-only="focusOnly" /></div>
        <div id="analyzer-findings" class="findings-list analyzer-anchor-section" :class="{ focused: focusedSection === 'analyzer-findings' }"><h3>Review findings <small>{{ analysis.findings.length + analysis.protection.indicators.length }}</small></h3><article v-for="finding in analysis.findings" :key="finding.title + finding.detail"><b :class="`finding-${finding.severity}`">{{ finding.severity }}</b><div><strong>{{ finding.title }}</strong><p>{{ finding.detail }}</p></div></article><article v-for="indicator in analysis.protection.indicators" :key="indicator"><b class="finding-review">review</b><div><strong>加固/动态加载线索</strong><p>{{ indicator }}</p></div></article></div>
        <div id="analyzer-sensitive" class="analyzer-anchor-section" :class="{ focused: focusedSection === 'analyzer-sensitive' }"><SensitiveItemsPanel :items="analysis.sensitiveItems" :file-name="analysis.fileName" :focus-only="focusOnly" @message="sensitiveMessage = $event" /></div>
        <details class="manifest-panel" v-if="analysis.platform === 'android' && analysis.manifestXml"><summary>AndroidManifest.xml（AXML / aapt 解码结果）</summary><pre>{{ analysis.manifestXml }}</pre></details>
        <details class="file-inventory"><summary>Interesting archive entries（{{ visibleFiles(analysis.files).length }} / {{ analysis.files.length }}）</summary><code v-for="file in visibleFiles(analysis.files)" :key="file">{{ file }}</code></details>
      </template>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { open, save } from '@tauri-apps/plugin-dialog'
import { backend, readableError } from '@/services/backend'
import { appConfig } from '@/services/config'
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow'
import BinaryInsightsPanel from '@/components/analyzer/BinaryInsightsPanel.vue'
import AntiInstrumentationPanel from '@/components/analyzer/AntiInstrumentationPanel.vue'
import CodeIntelligencePanel from '@/components/analyzer/CodeIntelligencePanel.vue'
import MasvsWorkbench from '@/components/analyzer/MasvsWorkbench.vue'
import SensitiveItemsPanel from '@/components/analyzer/SensitiveItemsPanel.vue'
import StaticSurfacePanel from '@/components/analyzer/StaticSurfacePanel.vue'
import ScrollAnchorNav from '@/components/ScrollAnchorNav.vue'
import { buildBoundaryFlows, correlateBoundaries } from '@/services/boundaries'
import { runtimeEvidenceCoverage } from '@/services/runtimeCoverage'
import { useKernSightEvidence } from '@/composables/useKernSightEvidence'
import type { AnalysisBaselineDiff, AnalysisCase, AppAnalysis, TerminalEntry } from '@/types'

const props = defineProps<{ analysis: AppAnalysis | null; analyzing: boolean; history: TerminalEntry[]; focusRequest?: { id: string; sourceType: string; sourceLocation?: string } }>()
const analyzerAnchors = computed(() => props.analysis ? [
  { id: 'analyzer-anti', label: 'RUNTIME EVIDENCE' },
  { id: 'analyzer-masvs', label: 'MASVS 验证' },
  { id: 'analyzer-static', label: '静态攻击面' },
  { id: 'analyzer-code', label: '代码入口' },
  { id: 'analyzer-binary', label: '二进制证据' },
  { id: 'analyzer-findings', label: '风险结论' },
  { id: 'analyzer-sensitive', label: '敏感信息' },
] : [])
const emit = defineEmits<{ analyze: [request: { path: string; apktoolPath?: string; jadxPath?: string; excludedUrlPatterns?: string[] }]; openAi: []; openRuntime: []; openDataFlow: []; openSettings: []; openKernSight: []; replaceAnalysis: [analysis: AppAnalysis]; restoreRuntimeHistory: [history: TerminalEntry[]]; focusConsumed: [] }>()
const fileInput = ref<HTMLInputElement>()
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
const kernSight = useKernSightEvidence(computed(() => props.analysis?.packageId || ''))
const kernSightJoin = computed(() => props.analysis?.platform === 'android' ? kernSight.join.value : null)

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

function openKernSightChain() {
  if (props.analysis?.packageId) kernSight.requestPackage(props.analysis.packageId)
  emit('openKernSight')
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
function onSelect(event: Event) { useFile((event.target as HTMLInputElement).files?.[0]) }
function onDrop(event: DragEvent) { useFile(event.dataTransfer?.files?.[0]) }
function analyze() {
  if (!filePath.value) return
  emit('analyze', {
    path: filePath.value,
    apktoolPath: apktoolPath.value || undefined,
    jadxPath: jadxPath.value || undefined,
    excludedUrlPatterns: excludedUrlPatterns.value,
  })
}
async function chooseFile() {
  const selected = await open({ multiple: false, filters: [{ name: 'Mobile packages', extensions: ['apk', 'ipa'] }] })
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
  const outputPath = await save({ defaultPath: `${baseName}.mobileecase`, filters: [{ name: 'MobileE case', extensions: ['mobileecase', 'mskcase', 'json'] }] })
  if (!outputPath) return
  try {
    const written = await backend.saveAnalysisCase(outputPath, props.analysis, assessmentVerdicts.value, assessmentNotes.value, scopedRuntimeHistory.value)
    assessmentDirty.value = false
    exportMessage.value = `项目快照已保存：${written}（包含 ${scopedRuntimeHistory.value.length} 条当前 App 运行记录）`
  } catch (cause) {
    exportMessage.value = `保存项目快照失败：${readableError(cause)}`
  }
}
async function loadCase() {
  const selected = await open({ multiple: false, filters: [{ name: 'MobileE case', extensions: ['mobileecase', 'mskcase', 'json'] }] })
  if (typeof selected !== 'string') return
  try {
    const loaded = await backend.loadAnalysisCase(selected)
    pendingLoadedCase = loaded
    baselineDiff.value = null
    emit('restoreRuntimeHistory', (loaded.runtimeHistory || []).map((entry) => ({ ...entry, persisted: true })))
    emit('replaceAnalysis', loaded.analysis)
    exportMessage.value = `已打开项目快照：${selected}（恢复 ${(loaded.runtimeHistory || []).length} 条运行记录）`
  } catch (cause) {
    exportMessage.value = `打开项目快照失败：${readableError(cause)}`
  }
}
async function compareCase() {
  if (!props.analysis) return
  const selected = await open({ multiple: false, filters: [{ name: 'MobileE case', extensions: ['mobileecase', 'mskcase', 'json'] }] })
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
