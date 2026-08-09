<template>
  <div class="analyzer-layout">
    <section class="drop-zone panel" :class="{ dragging }" @dragover.prevent="dragging = true" @dragleave.prevent="dragging = false" @drop.prevent="onDrop">
      <input ref="fileInput" type="file" accept=".apk,.ipa,application/vnd.android.package-archive" @change="onSelect" />
      <span class="material-symbols-outlined">upload_file</span>
      <div><h2>{{ selectedName || 'Drop APK / IPA Here' }}</h2><p>{{ filePath || '拖拽文件或输入本机绝对路径，分析过程在本机完成。' }}</p></div>
      <div class="drop-actions"><button class="primary-button" @click="chooseFile">选择本机文件</button><button class="ghost-button" @click="fileInput?.click()">浏览器文件</button></div>
    </section>

    <section class="panel analyzer-card">
      <div class="section-title compact"><div><div class="eyebrow">STATIC INVENTORY</div><h2>App Analyzer</h2></div><span class="live-pill" :class="{ online: !!analysis }">{{ analysis ? 'ANALYZED' : 'IDLE' }}</span></div>
      <div class="analyzer-path-row"><input v-model.trim="filePath" placeholder="/absolute/path/to/app.apk or app.ipa" @keyup.enter="analyze" /><button class="primary-button" :disabled="!filePath || analyzing" @click="analyze">{{ analyzing ? '分析中…' : '开始分析' }}</button></div>
      <div class="analyzer-tools-row"><label><span>Apktool（可选，Manifest/资源回退，自动保存）</span><div class="tool-path-control"><input v-model.trim="apktoolPath" placeholder="/absolute/path/apktool 或 apktool.jar" /><button class="ghost-button" @click="chooseTool('apktool')">选择</button></div></label><label><span>JADX（可选，源码/Manifest 回退，自动保存）</span><div class="tool-path-control"><input v-model.trim="jadxPath" placeholder="/absolute/path/jadx 或 jadx.jar" /><button class="ghost-button" @click="chooseTool('jadx')">选择</button></div></label></div>
      <p class="tool-behavior-note">JADX/Apktool 以后台 CLI 方式运行，不会打开 GUI；扫描完成后临时反编译目录会自动删除，所以终端进程短暂出现后消失属于正常完成，不是闪退。APK 的 JAR 工具需要 Java，IPA 的内置 Plist/Mach-O 分析不依赖 Java。</p>
      <div v-if="analyzing" class="analysis-progress"><div class="analysis-progress-bar"><i></i></div><strong>{{ progressSteps[progressStep] }}</strong><small>大型 APK、Flutter SO 或 JADX 反编译可能需要数分钟，请不要重复点击。</small></div>
      <div v-if="!analysis" class="analyzer-placeholder"><span class="material-symbols-outlined">policy</span><h3>等待 APK / IPA</h3><p>读取包名、版本、架构、权限、组件、签名摘要和敏感文件线索；不会上传文件，也不会默认提取密钥或敏感数据。</p></div>
      <template v-else>
        <div class="app-summary-grid">
          <div><span>Platform</span><strong>{{ analysis.platform.toUpperCase() }}</strong></div>
          <div><span>Bundle / Package</span><strong>{{ analysis.packageId || '—' }}</strong></div>
          <div><span>Name</span><strong>{{ analysis.displayName || '—' }}</strong></div>
          <div><span>Version</span><strong>{{ analysis.versionName || '—' }} ({{ analysis.versionCode || '—' }})</strong></div>
          <div><span>Size</span><strong>{{ formatSize(analysis.fileSize) }}</strong></div>
          <div><span>Architectures</span><strong>{{ analysis.architectures.join(', ') || '未解析' }}</strong></div>
          <div><span>Likely framework</span><details class="summary-details"><summary>{{ analysis.frameworks[0] || 'Native / 未判断' }}</summary><p>{{ analysis.frameworks.join(', ') || 'Native / 未判断' }}</p></details></div>
          <div v-if="analysis.minSdk"><span>Min SDK</span><strong>{{ analysis.minSdk }}</strong></div>
          <div v-if="analysis.targetSdk"><span>Target SDK</span><strong>{{ analysis.targetSdk }}</strong></div>
          <div><span>Protection</span><strong :class="analysis.protection.status.includes('未命中') || analysis.protection.status.includes('未加密') || analysis.protection.status.includes('已经砸壳') ? 'safe' : 'warning'">{{ analysis.protection.status }}</strong></div>
          <div v-if="analysis.protection.packers.length"><span>Packer hints</span><strong>{{ analysis.protection.packers.join(', ') }}</strong></div>
          <div><span>Third-party libraries</span><details class="summary-details"><summary>{{ analysis.thirdPartyLibraries.length }} detected</summary><p>{{ analysis.thirdPartyLibraries.join(', ') || '未识别' }}</p></details></div>
        </div>
        <div v-if="analysis.missingDependencies.length" class="dependency-notice"><strong>分析能力提示</strong><p v-for="item in analysis.missingDependencies" :key="item">{{ item }}</p></div>
        <div class="tool-used-line">本次使用：{{ analysis.toolsUsed.join(' · ') }}</div>
        <details v-if="analysis.signature" class="manifest-panel"><summary>签名与证书详情</summary><pre>{{ analysis.signature }}</pre></details>
        <div class="analysis-columns">
          <div><h3>Permissions <small>{{ analysis.permissions.length }}</small><button class="help-dot" @click="showPermissionHelp = !showPermissionHelp">?</button></h3><p v-if="showPermissionHelp" class="inline-help">红色为短信、联系人、录音、精确位置、安装包、悬浮窗、全盘存储等高风险权限；黄色为需要结合业务确认的设备状态/后台能力。厂商自定义权限只在对应 ROM 生效，也应在真机上复核。</p><div class="tag-list"><span v-for="permission in analysis.permissions" :key="permission" :class="`risk-tag-${permissionRisk(permission)}`" :title="permissionHint(permission)">{{ permission }}</span><em v-if="!analysis.permissions.length">未找到 / 工具不可用</em></div></div>
          <div><h3>Components <small>{{ analysis.components.length }}</small><button class="help-dot" @click="showComponentHelp = !showComponentHelp">?</button></h3><p v-if="showComponentHelp" class="inline-help">重点手测 exported=true 且没有 permission 保护的 Activity/Service/Receiver/Provider。可用 adb shell am start、am startservice、am broadcast 或 content query 验证是否能被外部调用；仅“存在组件”不等于漏洞。</p><div class="tag-list"><span v-for="component in analysis.components" :key="component" :class="`risk-tag-${componentRisk(component)}`" :title="componentHint(component)">{{ component }}</span><em v-if="!analysis.components.length">未找到 / 工具不可用</em></div></div>
        </div>
        <div class="analysis-columns"><div><h3>Manifest security flags <small>{{ analysis.manifestFlags.length }}</small><button class="help-dot" @click="showManifestHelp = !showManifestHelp">?</button></h3><p v-if="showManifestHelp" class="inline-help">debuggable=true、allowBackup=true、usesCleartextTraffic=true 通常需要醒目标记；但最终风险仍取决于 targetSdk、网络安全配置和业务数据。</p><div class="tag-list"><span v-for="flag in analysis.manifestFlags" :key="flag" :class="`risk-tag-${manifestRisk(flag)}`" :title="manifestHint(flag)">{{ flag }}</span><em v-if="!analysis.manifestFlags.length">未显式配置</em></div></div><div><h3>Exported components <small>{{ analysis.exportedComponents.length }}</small><button class="help-dot" @click="showExportedHelp = !showExportedHelp">?</button></h3><p v-if="showExportedHelp" class="inline-help">导出组件是外部入口，不一定是漏洞；无权限保护、接受外部 URI/Intent、可读写 Provider 或能触发敏感操作时风险更高。</p><div class="tag-list"><span v-for="component in analysis.exportedComponents" :key="component" :class="`risk-tag-${componentRisk(component)}`" :title="componentHint(component)">{{ component }}</span><em v-if="!analysis.exportedComponents.length">未发现 exported=true</em></div></div></div>
        <div class="analysis-columns">
          <div><h3>Intent Filters / Deep Links <small>{{ analysis.intentFilters.length }}</small><button class="help-dot" @click="showIntentHelp = !showIntentHelp">?</button></h3><p v-if="showIntentHelp" class="inline-help">重点检查自定义 Scheme、HTTP(S) App Link 的 host/path 限制、参数校验和登录态。带 intent-filter 且未显式 exported=false 的组件会进入导出组件复核清单。</p><div class="tag-list"><span v-for="filter in analysis.intentFilters" :key="filter" class="risk-tag-review">{{ filter }}</span><em v-if="!analysis.intentFilters.length">未发现自定义 Intent Filter</em></div></div>
          <div><h3>Third-party SDKs / Libraries <small>{{ analysis.thirdPartyLibraries.length }}</small><button class="help-dot" @click="showSdkHelp = !showSdkHelp">?</button></h3><p v-if="showSdkHelp" class="inline-help">通过归档路径以及 DEX、SO、Framework、JS Bundle 可见字符串综合识别。结果用于建立依赖清单；版本和 CVE 仍需结合构建元数据或 SBOM 确认。</p><div class="tag-list"><span v-for="library in analysis.thirdPartyLibraries" :key="library" class="risk-tag-normal">{{ library }}</span><em v-if="!analysis.thirdPartyLibraries.length">未识别到已知 SDK 特征</em></div></div>
        </div>
        <div class="findings-list"><h3>Review findings <small>{{ analysis.findings.length + analysis.protection.indicators.length }}</small></h3><article v-for="finding in analysis.findings" :key="finding.title + finding.detail"><b :class="`finding-${finding.severity}`">{{ finding.severity }}</b><div><strong>{{ finding.title }}</strong><p>{{ finding.detail }}</p></div></article><article v-for="indicator in analysis.protection.indicators" :key="indicator"><b class="finding-review">review</b><div><strong>加固/动态加载线索</strong><p>{{ indicator }}</p></div></article></div>
        <div class="sensitive-panel"><h3>Sensitive information / location <small>{{ analysis.sensitiveItems.length }}</small></h3><div v-if="analysis.sensitiveItems.length" class="sensitive-table"><div class="sensitive-head"><span>敏感信息 / 实际值</span><span>地址</span></div><template v-for="item in analysis.sensitiveItems" :key="item.item + item.location + item.value"><button class="sensitive-row" :class="{ expanded: selectedSensitive === item }" @click="selectedSensitive = selectedSensitive === item ? null : item"><span><b :class="`finding-${item.severity}`">{{ item.item }}</b><small>{{ item.value || '文件名线索' }}</small></span><code>{{ item.location }}{{ item.lineNumber ? `:${item.lineNumber}` : '' }}</code></button><div v-if="selectedSensitive === item" class="sensitive-detail sensitive-detail-row"><header><div><strong>{{ item.item }}</strong><code>{{ item.location }}{{ item.lineNumber ? `:${item.lineNumber}` : '' }}</code></div><button class="icon-button" @click.stop="selectedSensitive = null">×</button></header><p><b>匹配值：</b>{{ item.value || '仅命中文件名规则' }}</p><pre v-if="item.context">{{ item.context }}</pre></div></template></div><p v-else class="empty-hint">未发现按名称或文本模式匹配的线索；请结合运行时测试复核。</p></div>
        <details class="manifest-panel" v-if="analysis.platform === 'android' && analysis.manifestXml"><summary>AndroidManifest.xml（AXML / aapt 解码结果）</summary><pre>{{ analysis.manifestXml }}</pre></details>
        <details class="file-inventory"><summary>Interesting archive entries（{{ visibleFiles(analysis.files).length }} / {{ analysis.files.length }}）</summary><code v-for="file in visibleFiles(analysis.files)" :key="file">{{ file }}</code></details>
      </template>
    </section>
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { open } from '@tauri-apps/plugin-dialog'
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow'
import type { AppAnalysis, SensitiveItem } from '@/types'

const props = defineProps<{ analysis: AppAnalysis | null; analyzing: boolean }>()
const emit = defineEmits<{ analyze: [request: { path: string; apktoolPath?: string; jadxPath?: string }] }>()
const fileInput = ref<HTMLInputElement>()
const filePath = ref('')
const selectedName = ref('')
const dragging = ref(false)
const apktoolPath = ref(localStorage.getItem('security-console.apktoolPath') || '')
const jadxPath = ref(localStorage.getItem('security-console.jadxPath') || '')
const selectedSensitive = ref<SensitiveItem | null>(null)
const showPermissionHelp = ref(false)
const showComponentHelp = ref(false)
const showManifestHelp = ref(false)
const showExportedHelp = ref(false)
const showIntentHelp = ref(false)
const showSdkHelp = ref(false)
const progressStep = ref(0)
const progressSteps = ['读取 APK/IPA 文件清单…', '解析 Manifest / Info.plist…', '运行 Apktool/JADX 回退分析…', '扫描 DEX、SO、Mach-O 与 Flutter 字符串…', '整理风险、组件和敏感信息上下文…']
let unlistenDrop: (() => void) | undefined
let progressTimer: ReturnType<typeof setInterval> | undefined

const highPermissions = ['READ_SMS', 'RECEIVE_SMS', 'SEND_SMS', 'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_CALL_LOG', 'WRITE_CALL_LOG', 'RECORD_AUDIO', 'CAMERA', 'ACCESS_FINE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'MANAGE_EXTERNAL_STORAGE', 'REQUEST_INSTALL_PACKAGES', 'SYSTEM_ALERT_WINDOW', 'WRITE_SETTINGS', 'PACKAGE_USAGE_STATS', 'QUERY_ALL_PACKAGES', 'BIND_ACCESSIBILITY_SERVICE']
const reviewPermissions = ['READ_PHONE_STATE', 'READ_MEDIA_', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'BLUETOOTH_', 'BODY_SENSORS', 'POST_NOTIFICATIONS', 'FOREGROUND_SERVICE', 'REQUEST_IGNORE_BATTERY_OPTIMIZATIONS', 'USE_BIOMETRIC', 'NFC']

function permissionRisk(permission: string) {
  if (highPermissions.some((value) => permission.includes(value))) return 'high'
  if (reviewPermissions.some((value) => permission.includes(value)) || !permission.startsWith('android.permission.')) return 'review'
  return 'normal'
}
function permissionHint(permission: string) {
  const risk = permissionRisk(permission)
  if (risk === 'high') return '高敏感权限：确认业务必要性、最小授权、运行时请求和数据保护'
  if (risk === 'review') return '需要结合 Android 版本、厂商 ROM 和实际调用场景复核'
  return '未按内置规则标为高风险；仍需结合业务用途判断'
}
function componentRisk(component: string) {
  if (component.includes('exported=true') && !component.includes('permission=')) return 'high'
  if (component.includes('exported=true') || component.includes('implicit/unspecified')) return 'review'
  return 'normal'
}
function componentHint(component: string) {
  if (componentRisk(component) === 'high') return '导出且未发现组件级权限保护，建议手动构造 Intent/Provider 请求验证'
  if (componentRisk(component) === 'review') return '需要结合 intent-filter、targetSdk、调用权限和业务逻辑确认'
  return '当前未发现显式外部暴露；仍需检查动态注册和代码逻辑'
}
function manifestRisk(flag: string) {
  if (/^(debuggable|allowBackup|usesCleartextTraffic)=true$/i.test(flag)) return 'high'
  if (/networkSecurityConfig|extractNativeLibs/i.test(flag)) return 'review'
  return 'normal'
}
function manifestHint(flag: string) {
  return manifestRisk(flag) === 'high' ? '发布配置存在明显安全风险，请结合 targetSdk 与业务数据确认' : '需要结合系统版本和配置文件内容进一步判断'
}

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
  localStorage.setItem('security-console.apktoolPath', apktoolPath.value)
  localStorage.setItem('security-console.jadxPath', jadxPath.value)
  emit('analyze', { path: filePath.value, apktoolPath: apktoolPath.value || undefined, jadxPath: jadxPath.value || undefined })
}
async function chooseFile() {
  const selected = await open({ multiple: false, filters: [{ name: 'Mobile packages', extensions: ['apk', 'ipa'] }] })
  if (typeof selected === 'string') {
    filePath.value = selected
    selectedName.value = selected.split(/[\\/]/).pop() || selected
  }
}
async function chooseTool(kind: 'apktool' | 'jadx') {
  const selected = await open({ multiple: false })
  if (typeof selected !== 'string') return
  if (kind === 'apktool') apktoolPath.value = selected
  else jadxPath.value = selected
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

watch(apktoolPath, (value) => localStorage.setItem('security-console.apktoolPath', value))
watch(jadxPath, (value) => localStorage.setItem('security-console.jadxPath', value))
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

onBeforeUnmount(() => {
  unlistenDrop?.()
  if (progressTimer) clearInterval(progressTimer)
})
</script>
