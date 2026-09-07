<template>
  <div class="app-shell" :class="{ 'sidebar-is-collapsed': sidebarCollapsed }">
    <header class="app-header">
      <div class="brand-status">
        <button class="icon-button sidebar-toggle" :title="sidebarCollapsed ? '展开菜单' : '收起菜单'" @click="sidebarCollapsed = !sidebarCollapsed"><span class="material-symbols-outlined">{{ sidebarCollapsed ? 'menu_open' : 'menu' }}</span></button>
        <h1>MobileE</h1>
      </div>
      <div class="workspace-context">
        <span>{{ activeViewMeta.section }}</span>
        <strong>{{ activeViewMeta.label }}</strong>
      </div>
      <div class="header-actions">
        <button class="icon-button" :title="theme === 'dark' ? '切换 Codex 浅色' : '切换暗色'" @click="toggleTheme"><span class="material-symbols-outlined">{{ theme === 'dark' ? 'light_mode' : 'dark_mode' }}</span></button>
        <button class="icon-button" title="全局设置" @click="showSettings = true"><span class="material-symbols-outlined">settings</span></button>
        <button class="icon-button" title="刷新设备状态" :disabled="loading" @click="refreshDevices"><span class="material-symbols-outlined" :class="{ spinning: loading }">refresh</span></button>
      </div>
    </header>

    <div class="workspace-shell" :class="{ 'sidebar-collapsed': sidebarCollapsed }">
      <aside class="workspace-sidebar">
        <nav class="workspace-nav" aria-label="主导航">
          <section class="nav-cluster" :class="{ active: deviceViews.includes(activeTab) }">
            <button class="nav-parent" title="Connected Devices" :class="{ active: activeTab === 'devices' }" @click="activeTab = 'devices'">
              <span class="material-symbols-outlined">devices</span><span><strong>Connected Devices</strong><small>设备、连接与基础操作</small></span>
            </button>
            <div class="nav-children">
              <button :class="{ active: activeTab === 'devices' }" @click="activeTab = 'devices'"><span class="material-symbols-outlined">smartphone</span>设备总览</button>
              <button :class="{ active: activeTab === 'adb' }" @click="activeTab = 'adb'"><span class="material-symbols-outlined">handyman</span>Device Tools</button>
            </div>
          </section>

          <section class="nav-cluster" :class="{ active: analysisViews.includes(activeTab) }">
            <button class="nav-parent" title="App / IPA Analysis" :class="{ active: analysisViews.includes(activeTab) }" @click="activeTab = 'analyzer'">
              <span class="material-symbols-outlined">security</span><span><strong>App / IPA Analysis</strong><small>单个移动应用的证据工作台</small></span>
            </button>
            <div class="nav-children analysis-menu">
              <button v-for="item in analysisMenu" :key="item.id" :class="{ active: activeTab === item.id }" @click="activeTab = item.id"><span class="material-symbols-outlined">{{ item.icon }}</span>{{ item.label }}</button>
            </div>
          </section>

          <section class="nav-cluster runtime-nav" :class="{ active: activeTab === 'android-runtime' }">
            <button class="nav-parent" title="KernSight 证据链" :class="{ active: activeTab === 'android-runtime' }" @click="activeTab = 'android-runtime'">
              <span class="material-symbols-outlined">monitor_heart</span><span><strong>KernSight 证据链</strong><small>L0 Observe · L1 Inspect · L2 Dump</small></span><em>NEW</em>
            </button>
          </section>
        </nav>

      </aside>

      <div class="workspace-main">
        <div v-if="error" class="notice error-notice" role="alert">
          <span class="material-symbols-outlined">error</span>
          <span>{{ error }}</span>
          <button @click="error = ''">关闭</button>
        </div>
        <div v-if="environmentChecking" class="notice environment-startup-notice"><span class="material-symbols-outlined spinning">sync</span><span>首次启动环境检查：正在识别 ADB、Frida、Python 与 iOS USB 工具…</span></div>

        <main class="content-area">
      <ConnectedDevicesView
        v-if="activeTab === 'devices'"
        :devices="devices"
        :selected-serial="selectedSerial"
        :details="details"
        :ios-details="iosDetails"
        :processes="processes"
        :loading="loading"
        @select-device="selectDevice"
        @refresh="refreshSelected"
        @refresh-devices="refreshDevices"
        @inspect-process="inspectProcess"
      />
      <!-- Keep KernSight mounted so device/session/report state survives menu switches. -->
      <AndroidRuntimeMonitorView
        v-show="activeTab === 'android-runtime'"
        :device="selectedDevice"
        :details="details"
        @open-devices="activeTab = 'devices'"
        @open-ai="activeTab = 'ai-workbench'"
      />
      <AdbToolboxView
        v-show="activeTab === 'adb'"
        :device="selectedDevice"
        :android-available="selectedDevice?.platform === 'android'"
        :history="terminalHistory"
        :running="commandRunning"
        :certificate="activeCertificate"
        :certificate-busy="certificateBusy"
        :certificate-feedback="certificateFeedback"
        @run="runAction"
        @shell="runShell"
        @proxy="runProxy"
        @certificate-info="certificateInfo"
        @install-certificate="installCertificate"
        @pull="pullDumps"
        @push="pushToDevice"
        @log="entry => terminalHistory.unshift({ time: Date.now(), ...entry })"
        @clear="terminalHistory = []"
      />
      <FridaToolboxView
        v-if="activeTab === 'frida'"
        :device="selectedDevice"
        :processes="fridaProcesses"
        :scripts="fridaScripts"
        :environment="environment"
        :history="terminalHistory"
        :running="commandRunning"
        :analysis-app-id="analysis?.packageId || undefined"
        :guidance-request="fridaGuidanceRequest"
        @refresh="refreshFrida"
        @run="runFrida"
        @runtime-workflow="runRuntimeWorkflow"
        @dex-dump="runDexDump"
        @so-dump="runSoDump"
        @ios-dump="runIosDump"
        @server="manageFridaServer"
        @download="downloadFridaServer"
        @install-host="installFridaTools"
        @open-terminal="openEnvironmentTerminal"
        @mount-image="mountIosDeveloperImage"
        @refresh-environment="refreshEnvironment"
        @open-settings="showSettings = true"
        @guidance-consumed="fridaGuidanceRequest = undefined"
      />
      <ApkAnalyzerView v-else-if="activeTab === 'analyzer'" :analysis="analysis" :analyzing="analysisRunning" :history="terminalHistory" :focus-request="analyzerFocusRequest" @analyze="analyzeApp" @replace-analysis="analysis = $event" @restore-runtime-history="restoreRuntimeHistory" @open-runtime="openRuntimeConfirmation" @open-ai="activeTab = 'ai-workbench'" @open-data-flow="activeTab = 'boundaries'" @open-settings="showSettings = true" @open-kern-sight="activeTab = 'android-runtime'" @focus-consumed="analyzerFocusRequest = undefined" />
      <DataBoundariesView v-else-if="activeTab === 'boundaries'" :analysis="analysis" :history="terminalHistory" :device="selectedDevice" @open-ai="activeTab = 'ai-workbench'" @open-analyzer="openAnalyzerEvidence" />
      <!-- Keep the workbench mounted: provider requests and generated evidence must survive tab switches. -->
      <AiWorkbenchView v-show="activeTab === 'ai-workbench'" :analysis="analysis" :history="terminalHistory" :device="selectedDevice" />
        </main>
      </div>
    </div>
    <SettingsDrawer :open="showSettings" @close="showSettings = false" />
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import AdbToolboxView from '@/views/AdbToolboxView.vue'
import AndroidRuntimeMonitorView from '@/views/AndroidRuntimeMonitorView.vue'
import AiWorkbenchView from '@/views/AiWorkbenchView.vue'
import ApkAnalyzerView from '@/views/ApkAnalyzerView.vue'
import ConnectedDevicesView from '@/views/ConnectedDevicesView.vue'
import DataBoundariesView from '@/views/DataBoundariesView.vue'
import FridaToolboxView from '@/views/FridaToolboxView.vue'
import SettingsDrawer from '@/components/SettingsDrawer.vue'
import { useDeviceManager } from '@/composables/useDeviceManager'
import { useFridaToolbox } from '@/composables/useFridaToolbox'
import { backend, readableError } from '@/services/backend'
import { appConfig, saveAppConfigNow } from '@/services/config'
import type {
  AdbAction,
  AppAnalysis,
  CertificateInfo,
  EnvironmentReport,
  ProcessInfo,
  TerminalEntry,
} from '@/types'

type TabId = 'devices' | 'adb' | 'frida' | 'analyzer' | 'boundaries' | 'ai-workbench' | 'android-runtime'

const deviceViews: TabId[] = ['devices', 'adb']
const analysisViews: TabId[] = ['analyzer', 'frida', 'boundaries', 'ai-workbench']
const analysisMenu: { id: TabId; label: string; icon: string }[] = [
  { id: 'analyzer', label: 'Static Analysis', icon: 'document_scanner' },
  { id: 'frida', label: 'Runtime / Frida', icon: 'hub' },
  { id: 'boundaries', label: 'Data Flow', icon: 'account_tree' },
  { id: 'ai-workbench', label: 'AI Review', icon: 'neurology' },
]

const viewMetadata: Record<TabId, { section: string; label: string }> = {
  devices: { section: 'DEVICE WORKSPACE', label: 'Connected Devices' },
  adb: { section: 'DEVICE WORKSPACE', label: 'Device Tools' },
  analyzer: { section: 'APP / IPA ANALYSIS', label: 'Static Analysis' },
  frida: { section: 'APP / IPA ANALYSIS', label: 'Runtime / Frida' },
  boundaries: { section: 'APP / IPA ANALYSIS', label: 'Data Flow' },
  'ai-workbench': { section: 'APP / IPA ANALYSIS', label: 'AI Context / Review' },
  'android-runtime': { section: 'ANDROID · EVIDENCE CHAIN', label: 'L0 / L1 / L2' },
}

const activeTab = ref<TabId>('devices')
const activeViewMeta = computed(() => viewMetadata[activeTab.value])
const terminalHistory = ref<TerminalEntry[]>([])
const environment = ref<EnvironmentReport | null>(null)
const toolDirectory = computed(() => appConfig.toolDirectory)
const analysis = ref<AppAnalysis | null>(null)
const fridaGuidanceRequest = ref<{ id: number; appId: string; platform: 'android' | 'ios'; purpose: 'anti-instrumentation' }>()
const analyzerFocusRequest = ref<{ id: string; sourceType: string; sourceLocation?: string }>()
const activeCertificate = ref<CertificateInfo | null>(null)
const commandRunning = ref(false)
const analysisRunning = ref(false)
const environmentChecking = ref(true)
const error = ref('')
const showSettings = ref(false)
const sidebarCollapsed = ref(localStorage.getItem('mobilee.sidebarCollapsed') === 'true')
const theme = ref<'dark' | 'light'>(localStorage.getItem('mobilee.theme') === 'light' ? 'light' : 'dark')
let connectionTimer: ReturnType<typeof setInterval> | undefined

const {
  devices,
  selectedSerial,
  details,
  iosDetails,
  processes,
  loading,
  selectedDevice,
  refreshDevices,
  monitorDeviceConnection,
  refreshSelected,
  selectDevice: selectManagedDevice,
} = useDeviceManager({
  environment,
  terminalHistory,
  error,
})

const {
  fridaProcesses,
  fridaScripts,
  refreshFrida,
  runFrida,
  runRuntimeWorkflow,
  runDexDump,
  runSoDump,
  runIosDump,
  manageFridaServer,
  downloadFridaServer,
  installFridaTools,
  openEnvironmentTerminal,
  mountIosDeveloperImage,
} = useFridaToolbox({
  selectedSerial,
  selectedDevice,
  environment,
  toolDirectory,
  terminalHistory,
  error,
  commandRunning,
  analysis,
})

function openAnalyzerEvidence(request: { id: string; sourceType: string; sourceLocation?: string }) {
  analyzerFocusRequest.value = { ...request }
  activeTab.value = 'analyzer'
}

async function runShell(command: string) {
  if (!selectedSerial.value || selectedDevice.value?.platform !== 'android') {
    error.value = '请先连接并选择一台 Android 设备'
    return
  }
  commandRunning.value = true
  try {
    const result = await backend.runShell(selectedSerial.value, command)
    terminalHistory.value.unshift({ time: Date.now(), command: `adb shell ${command}`, output: result.output, success: result.success })
  } catch (cause) {
    error.value = readableError(cause)
  } finally {
    commandRunning.value = false
  }
}

async function runProxy(request: { action: string; host?: string; port?: number }) {
  if (!selectedSerial.value || selectedDevice.value?.platform !== 'android') {
    error.value = '请先连接 Android 设备'
    return
  }
  try {
    const result = await backend.runProxy({ serial: selectedSerial.value, ...request })
    terminalHistory.value.unshift({ time: Date.now(), command: result.command, output: result.output, success: result.success })
  } catch (cause) {
    error.value = readableError(cause)
  }
}

const certificateBusy = ref(false)
const certificateFeedback = ref('')
function certificateLog(message: string, success: boolean) {
  certificateFeedback.value = message
  terminalHistory.value.unshift({ time: Date.now(), command: '证书操作', output: message, success })
}
async function certificateInfo(path: string): Promise<CertificateInfo | null> {
  if (certificateBusy.value) return null
  certificateBusy.value = true
  activeCertificate.value = null
  certificateLog(`正在读取证书并计算 Hash：${path}`, true)
  try {
    activeCertificate.value = await backend.certificateInfo(path)
    certificateLog(`计算成功：${path}\nsubject_hash_old：${activeCertificate.value.subjectHash}\n${activeCertificate.value.sha256}`, true)
    return activeCertificate.value
  } catch (cause) {
    error.value = readableError(cause)
    certificateLog(`计算证书失败：${error.value}`, false)
    return null
  } finally {
    certificateBusy.value = false
  }
}

async function installCertificate(path: string) {
  if (certificateBusy.value) return
  if (!selectedSerial.value || selectedDevice.value?.platform !== 'android') {
    error.value = '请先连接 Android 设备'
    certificateLog(error.value, false)
    return
  }
  certificateBusy.value = true
  certificateLog(`正在安装证书：${path}\n设备：${selectedSerial.value}`, true)
  try {
    const result = await backend.installCertificate(selectedSerial.value, path)
    certificateLog(`${result.success ? '安装命令完成' : '安装失败'}\n${result.output}`, result.success)
    terminalHistory.value.unshift({ time: Date.now(), command: result.command, output: result.output, success: result.success })
  } catch (cause) {
    error.value = readableError(cause)
    certificateLog(`安装证书失败：${error.value}`, false)
  } finally {
    certificateBusy.value = false
  }
}

async function pullDumps(request: { remote: string; local: string }) {
  if (!selectedSerial.value || selectedDevice.value?.platform !== 'android') {
    error.value = '请先连接并选择一台 Android 设备'
    return
  }
  commandRunning.value = true
  try {
    const result = await backend.pullFiles({ serial: selectedSerial.value, remotePath: request.remote, localDir: request.local })
    terminalHistory.value.unshift({ time: Date.now(), command: result.command, output: result.output, success: result.success })
  } catch (cause) {
    error.value = readableError(cause)
  } finally {
    commandRunning.value = false
  }
}

async function pushToDevice(localPath: string) {
  if (!selectedSerial.value || selectedDevice.value?.platform !== 'android') {
    error.value = '请先连接并选择一台 Android 设备'
    return
  }
  commandRunning.value = true
  try {
    const result = await backend.pushFile({ serial: selectedSerial.value, localPath })
    terminalHistory.value.unshift({ time: Date.now(), command: result.command, output: result.output, success: result.success })
  } catch (cause) {
    error.value = readableError(cause)
  } finally {
    commandRunning.value = false
  }
}

function applyTheme() {
  document.documentElement.dataset.theme = theme.value
}

function toggleTheme() {
  theme.value = theme.value === 'dark' ? 'light' : 'dark'
}

async function refreshEnvironment(recordHistory = true) {
  try {
    environment.value = await backend.inspectEnvironment({
      serial: selectedSerial.value || undefined,
      platform: selectedDevice.value?.platform,
      toolDirectory: toolDirectory.value || undefined,
    })
    if (recordHistory) {
      terminalHistory.value.unshift({
        time: Date.now(),
        command: 'inspect environment',
        output: '已重新检测主机 Frida 工具链与当前设备通道。',
        success: true,
      })
    }
  } catch (cause) {
    error.value = readableError(cause)
  }
}

async function selectDevice(serial: string) {
  await selectManagedDevice(serial)
  await refreshEnvironment(false)
}

async function analyzeApp(request: { path: string; apktoolPath?: string; jadxPath?: string; excludedUrlPatterns?: string[] }) {
  analysisRunning.value = true
  error.value = ''
  try {
    analysis.value = await backend.analyzeApp(request)
  } catch (cause) {
    error.value = readableError(cause)
  } finally {
    analysisRunning.value = false
  }
}

function restoreRuntimeHistory(entries: TerminalEntry[]) {
  const existing = new Set(terminalHistory.value.map((entry) => `${entry.time}|${entry.command}|${entry.appId || ''}`))
  const restored = entries.filter((entry) => !existing.has(`${entry.time}|${entry.command}|${entry.appId || ''}`))
  terminalHistory.value = [...restored, ...terminalHistory.value].sort((a, b) => b.time - a.time).slice(0, 2000)
}

async function runAction(payload: { action: AdbAction; argument?: string }) {
  if (!selectedSerial.value || selectedDevice.value?.platform !== 'android') {
    error.value = '请先连接并选择一台 Android 设备'
    return
  }
  commandRunning.value = true
  try {
    const result = await backend.runAction(selectedSerial.value, payload.action, payload.argument)
    terminalHistory.value.unshift({
      time: Date.now(),
      command: result.command,
      output: result.output,
      success: result.success,
    })
    if (payload.action === 'reboot' || payload.action === 'recovery') {
      setTimeout(refreshDevices, 1800)
    } else if (payload.action.startsWith('selinux_')) {
      await refreshSelected()
    }
  } catch (cause) {
    const message = readableError(cause)
    terminalHistory.value.unshift({
      time: Date.now(),
      command: payload.action,
      output: message,
      success: false,
    })
  } finally {
    commandRunning.value = false
  }
}

async function inspectProcess(process: ProcessInfo) {
  activeTab.value = 'adb'
  await runAction({ action: 'process_info', argument: process.name })
}

function openRuntimeConfirmation() {
  const appId = analysis.value?.packageId?.trim()
  if (!appId || !analysis.value) {
    error.value = '当前静态分析没有解析出 Bundle ID / 包名，无法自动关联运行时进程。'
    return
  }
  if (!selectedDevice.value || selectedDevice.value.platform !== analysis.value.platform) {
    error.value = `静态目标是 ${analysis.value.platform.toUpperCase()}，当前${selectedDevice.value ? `选择的是 ${selectedDevice.value.platform.toUpperCase()}` : '没有选择设备'}。请先连接并选择同平台设备，再进行运行确认。`
    activeTab.value = 'devices'
    return
  }
  fridaGuidanceRequest.value = {
    id: Date.now(),
    appId,
    platform: analysis.value.platform,
    purpose: 'anti-instrumentation',
  }
  activeTab.value = 'frida'
}

onMounted(async () => {
  applyTheme()
  try {
    await backend.configureHostEnvironment(toolDirectory.value || undefined)
    await refreshDevices()
    await refreshEnvironment(false)
    const core = environment.value?.tools.filter((tool) => ['adb', 'frida', 'frida-ps', 'idevice_id'].includes(tool.executable)) || []
    const missing = core.filter((tool) => !tool.available).map((tool) => tool.name)
    terminalHistory.value.unshift({
      time: Date.now(),
      command: 'startup environment check',
      output: missing.length ? `环境检查完成；未找到：${missing.join('、')}。可在 Frida / 环境检测页面配置目录。` : '环境检查完成：ADB、Frida 与 iOS USB 工具均可识别。',
      success: missing.length === 0,
    })
    if (!devices.value.length && missing.length) {
      activeTab.value = 'frida'
      error.value = `打包应用未找到：${missing.join('、')}。请在全局设置中配置工具目录，再到 Frida 环境与检测重新检测。`
    }
  } catch (cause) {
    error.value = `首次环境检查失败：${readableError(cause)}`
  } finally {
    environmentChecking.value = false
  }
  connectionTimer = setInterval(() => void monitorDeviceConnection(), 4000)
})

watch(activeTab, (tab) => {
  if (tab === 'frida') {
    void refreshFrida()
    void refreshEnvironment(false)
  }
})

watch(toolDirectory, async (directory) => {
  try {
    await backend.configureHostEnvironment(directory || undefined)
  } catch (cause) {
    error.value = readableError(cause)
  }
})

watch(sidebarCollapsed, value => localStorage.setItem('mobilee.sidebarCollapsed', String(value)))
watch(theme, value => {
  localStorage.setItem('mobilee.theme', value)
  applyTheme()
})

onBeforeUnmount(() => {
  if (connectionTimer) clearInterval(connectionTimer)
  void saveAppConfigNow().catch(() => {})
})
</script>
