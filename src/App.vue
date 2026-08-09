<template>
  <div class="app-shell">
    <header class="app-header">
      <div class="brand-status">
        <span class="status-dot" :class="{ offline: !isConnected }"></span>
        <div>
          <h1>Mobile Security Kits</h1>
          <p>{{ connectionLabel }}</p>
        </div>
      </div>
      <div class="header-actions">
        <button class="icon-button" title="环境菜单" @click="showMenu = !showMenu"><span class="material-symbols-outlined">settings</span></button>
        <button class="icon-button" title="刷新设备" :disabled="loading" @click="refreshDevices"><span class="material-symbols-outlined" :class="{ spinning: loading }">refresh</span></button>
        <div v-if="showMenu" class="header-menu">
          <button @click="activeTab = 'frida'; showMenu = false"><span class="material-symbols-outlined">hub</span>Frida / 环境检测</button>
          <button @click="openEnvironmentTerminal(); showMenu = false"><span class="material-symbols-outlined">terminal</span>打开系统终端检测</button>
          <button @click="refreshDevices(); showMenu = false"><span class="material-symbols-outlined">sync</span>重新扫描工具和设备</button>
        </div>
      </div>
    </header>

    <nav class="tabs" aria-label="主导航">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        class="tab-button"
        :class="{ active: activeTab === tab.id }"
        @click="activeTab = tab.id"
      >
        <span class="material-symbols-outlined">{{ tab.icon }}</span>
        {{ tab.label }}
        <span v-if="tab.id === 'devices' && signals.length" class="tab-count">{{ signals.length }}</span>
      </button>
    </nav>

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
        :signals="signals"
        :loading="loading"
        :bridge-status="bridgeStatus"
        @select-device="selectDevice"
        @refresh="refreshSelected"
        @start-bridge="startBridge"
        @inspect-process="inspectProcess"
      />
      <AdbToolboxView
        v-else-if="activeTab === 'adb'"
        :device="selectedDevice"
        :android-available="selectedDevice?.platform === 'android'"
        :history="terminalHistory"
        :running="commandRunning"
        :certificate="activeCertificate"
        @run="runAction"
        @shell="runShell"
        @proxy="runProxy"
        @certificate-info="certificateInfo"
        @install-certificate="installCertificate"
        @clear="terminalHistory = []"
      />
      <FridaToolboxView
        v-else-if="activeTab === 'frida'"
        :device="selectedDevice"
        :processes="fridaProcesses"
        :scripts="fridaScripts"
        :environment="environment"
        :tool-directory="toolDirectory"
        :script-directory="fridaScriptDirectory"
        :history="terminalHistory"
        :running="commandRunning"
        @refresh="refreshFrida"
        @run="runFrida"
        @dex-dump="runDexDump"
        @so-dump="runSoDump"
        @ios-dump="runIosDump"
        @script-directory="setFridaScriptDirectory"
        @server="manageFridaServer"
        @download="downloadFridaServer"
        @install-host="installFridaTools"
        @environment-config="setToolDirectory"
        @open-terminal="openEnvironmentTerminal"
        @mount-image="mountIosDeveloperImage"
      />
      <ApkAnalyzerView v-else :analysis="analysis" :analyzing="analysisRunning" @analyze="analyzeApp" />
    </main>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import AdbToolboxView from '@/views/AdbToolboxView.vue'
import ApkAnalyzerView from '@/views/ApkAnalyzerView.vue'
import ConnectedDevicesView from '@/views/ConnectedDevicesView.vue'
import FridaToolboxView from '@/views/FridaToolboxView.vue'
import { backend, readableError } from '@/services/backend'
import type {
  AdbAction,
  AppAnalysis,
  BridgeStatus,
  CertificateInfo,
  DeviceDetails,
  DeviceSummary,
  EnvironmentReport,
  FridaProcess,
  FridaScriptEntry,
  IosDeviceDetails,
  ProcessInfo,
  SignalEvent,
} from '@/types'

type TabId = 'devices' | 'adb' | 'frida' | 'analyzer'
interface TerminalEntry { time: number; command: string; output: string; success: boolean }

const tabs: { id: TabId; label: string; icon: string }[] = [
  { id: 'devices', label: 'Connected Devices', icon: 'devices' },
  { id: 'adb', label: 'ADB Toolbox', icon: 'handyman' },
  { id: 'frida', label: 'Frida Toolbox', icon: 'hub' },
  { id: 'analyzer', label: 'App Analyzer', icon: 'security' },
]

const activeTab = ref<TabId>('devices')
const devices = ref<DeviceSummary[]>([])
const selectedSerial = ref('')
const details = ref<DeviceDetails | null>(null)
const iosDetails = ref<IosDeviceDetails | null>(null)
const processes = ref<ProcessInfo[]>([])
const signals = ref<SignalEvent[]>([])
const bridgeStatus = ref<BridgeStatus | null>(null)
const terminalHistory = ref<TerminalEntry[]>([])
const environment = ref<EnvironmentReport | null>(null)
const toolDirectory = ref(localStorage.getItem('security-console.toolDirectory') || '')
const fridaScriptDirectory = ref(localStorage.getItem('security-console.fridaScriptDirectory') || '')
const fridaProcesses = ref<FridaProcess[]>([])
const fridaScripts = ref<FridaScriptEntry[]>([])
const analysis = ref<AppAnalysis | null>(null)
const activeCertificate = ref<CertificateInfo | null>(null)
const loading = ref(false)
const commandRunning = ref(false)
const analysisRunning = ref(false)
const environmentChecking = ref(true)
const error = ref('')
const showMenu = ref(false)
let unlistenSignal: UnlistenFn | undefined
let connectionTimer: ReturnType<typeof setInterval> | undefined
let connectionCheckRunning = false

const selectedDevice = computed(() =>
  devices.value.find((device) => device.serial === selectedSerial.value),
)
const isConnected = computed(() => selectedDevice.value?.status === 'device' || selectedDevice.value?.status === 'frida')
const connectionLabel = computed(() => {
  if (!selectedDevice.value) return '等待连接移动设备'
  return `${selectedDevice.value.platform.toUpperCase()} · ${selectedDevice.value.serial} · ${selectedDevice.value.status}`
})

async function refreshDevices() {
  loading.value = true
  error.value = ''
  try {
    devices.value = await backend.listDevices()
    const currentStillExists = devices.value.some((device) => device.serial === selectedSerial.value)
    if (!currentStillExists) selectedSerial.value = devices.value[0]?.serial || ''
    await refreshSelected()
    bridgeStatus.value = await backend.getBridgeStatus()
    environment.value = await backend.inspectEnvironment({ serial: selectedSerial.value || undefined, platform: selectedDevice.value?.platform, toolDirectory: toolDirectory.value || undefined })
  } catch (cause) {
    error.value = readableError(cause)
    details.value = null
    processes.value = []
  } finally {
    loading.value = false
  }
}

async function monitorDeviceConnection() {
  if (connectionCheckRunning || !selectedSerial.value) return
  connectionCheckRunning = true
  const previousSerial = selectedSerial.value
  try {
    const latest = await backend.listDevices()
    if (!latest.some((device) => device.serial === previousSerial)) {
      terminalHistory.value.unshift({
        time: Date.now(),
        command: 'device monitor',
        output: `设备已断开：${previousSerial}`,
        success: false,
      })
      devices.value = latest
      selectedSerial.value = latest[0]?.serial || ''
      details.value = null
      iosDetails.value = null
      processes.value = []
      fridaProcesses.value = []
      environment.value = null
      if (selectedSerial.value) await refreshSelected()
    }
  } catch {
    // 短暂扫描失败不覆盖当前状态，下一轮继续检查。
  } finally {
    connectionCheckRunning = false
  }
}

async function refreshSelected() {
  const device = selectedDevice.value
  if (!device) {
    details.value = null
    iosDetails.value = null
    processes.value = []
    return
  }
  if (device.platform === 'ios') {
    details.value = null
    processes.value = []
    if (['device', 'frida'].includes(device.status)) {
      try {
        iosDetails.value = await backend.getIosDeviceDetails(device.serial)
      } catch (cause) {
        error.value = readableError(cause)
      }
    } else {
      iosDetails.value = null
    }
    return
  }
  if (device.status !== 'device') {
    details.value = null
    iosDetails.value = null
    processes.value = []
    return
  }
  iosDetails.value = null
  try {
    const [deviceDetails, deviceProcesses] = await Promise.all([
      backend.getDeviceDetails(device.serial),
      backend.listProcesses(device.serial),
    ])
    details.value = deviceDetails
    processes.value = deviceProcesses
  } catch (cause) {
    error.value = readableError(cause)
  }
}

async function selectDevice(serial: string) {
  selectedSerial.value = serial
  loading.value = true
  await refreshSelected()
  loading.value = false
}

async function startBridge() {
  if (!selectedSerial.value || selectedDevice.value?.platform !== 'android') {
    error.value = '信号桥只适用于当前有线 Android 设备'
    return
  }
  try {
    bridgeStatus.value = await backend.startSignalBridge(selectedSerial.value)
  } catch (cause) {
    error.value = readableError(cause)
  }
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

async function certificateInfo(path: string): Promise<CertificateInfo | null> {
  try {
    activeCertificate.value = await backend.certificateInfo(path)
    return activeCertificate.value
  } catch (cause) {
    error.value = readableError(cause)
    return null
  }
}

async function installCertificate(path: string) {
  if (!selectedSerial.value || selectedDevice.value?.platform !== 'android') {
    error.value = '请先连接 Android 设备'
    return
  }
  try {
    const result = await backend.installCertificate(selectedSerial.value, path)
    terminalHistory.value.unshift({ time: Date.now(), command: result.command, output: result.output, success: result.success })
  } catch (cause) {
    error.value = readableError(cause)
  }
}

async function refreshFrida() {
  try {
    fridaScripts.value = await backend.listFridaScripts(fridaScriptDirectory.value || undefined)
    try {
      fridaProcesses.value = await backend.listFridaProcesses(selectedSerial.value || undefined)
    } catch (cause) {
      fridaProcesses.value = []
      error.value = readableError(cause)
    }
  } catch (cause) {
    error.value = readableError(cause)
  }
}

async function setFridaScriptDirectory(directory: string) {
  fridaScriptDirectory.value = directory
  localStorage.setItem('security-console.fridaScriptDirectory', directory)
  await refreshFrida()
}

async function runFrida(request: { process: string; pid?: number; mode: string; script: string; scriptPath?: string }) {
  try {
    const result = await backend.runFridaScript({ serial: selectedSerial.value || undefined, ...request })
    terminalHistory.value.unshift({ time: Date.now(), command: result.command, output: result.output, success: result.success })
  } catch (cause) {
    error.value = readableError(cause)
  }
}

async function runDexDump(request: { package: string; scriptPath: string; destinationDirectory?: string; durationSeconds?: number }) {
  if (!selectedSerial.value || selectedDevice.value?.platform !== 'android') {
    error.value = 'DEX Dump 需要选择已 Root 的 Android 设备'
    return
  }
  commandRunning.value = true
  try {
    const result = await backend.runDexDump({ serial: selectedSerial.value, ...request })
    terminalHistory.value.unshift({ time: Date.now(), command: result.command, output: result.output, success: result.success })
  } catch (cause) {
    error.value = readableError(cause)
  } finally {
    commandRunning.value = false
  }
}

async function runSoDump(request: { package: string; scriptPath: string; destinationDirectory?: string; durationSeconds?: number }) {
  if (!selectedSerial.value || selectedDevice.value?.platform !== 'android') {
    error.value = 'SO Dump 需要选择已 Root 的 Android 设备'
    return
  }
  commandRunning.value = true
  try {
    const result = await backend.runSoDump({ serial: selectedSerial.value, ...request })
    terminalHistory.value.unshift({ time: Date.now(), command: result.command, output: result.output, success: result.success })
  } catch (cause) {
    error.value = readableError(cause)
  } finally {
    commandRunning.value = false
  }
}

async function runIosDump(request: { bundleId: string; destinationDirectory?: string }) {
  if (!selectedSerial.value || selectedDevice.value?.platform !== 'ios') { error.value = '请先选择 Frida 可访问的越狱 iOS 设备'; return }
  commandRunning.value = true
  try {
    const result = await backend.runIosDump({ serial: selectedSerial.value, ...request })
    terminalHistory.value.unshift({ time: Date.now(), command: result.command, output: result.output, success: result.success })
  } catch (cause) { error.value = readableError(cause) } finally { commandRunning.value = false }
}

async function manageFridaServer(request: { action: 'start' | 'stop' | 'log'; path?: string }) {
  if (!selectedSerial.value || selectedDevice.value?.platform !== 'android') {
    error.value = '请先连接 Android 设备'
    return
  }
  try {
    const result = await backend.manageFridaServer({ serial: selectedSerial.value, ...request })
    terminalHistory.value.unshift({ time: Date.now(), command: result.command, output: result.output, success: result.success })
    environment.value = await backend.inspectEnvironment({ serial: selectedSerial.value, platform: selectedDevice.value?.platform, toolDirectory: toolDirectory.value || undefined })
  } catch (cause) {
    error.value = readableError(cause)
  }
}

async function downloadFridaServer(destinationDirectory?: string) {
  if (!selectedSerial.value || selectedDevice.value?.platform !== 'android') {
    error.value = '请先连接 Android 设备'
    return
  }
  try {
    const result = await backend.downloadFridaServer({ serial: selectedSerial.value, destinationDirectory })
    terminalHistory.value.unshift({ time: Date.now(), command: result.command, output: result.output, success: result.success })
    if (result.success) {
      const deploy = await backend.manageFridaServer({ serial: selectedSerial.value, action: 'start', path: result.output.trim() })
      terminalHistory.value.unshift({ time: Date.now(), command: deploy.command, output: deploy.output, success: deploy.success })
      environment.value = await backend.inspectEnvironment({ serial: selectedSerial.value, platform: selectedDevice.value?.platform, toolDirectory: toolDirectory.value || undefined })
    }
  } catch (cause) {
    error.value = readableError(cause)
  }
}

async function installFridaTools() {
  try {
    const result = await backend.installFridaTools()
    terminalHistory.value.unshift({ time: Date.now(), command: result.command, output: result.output, success: result.success })
    environment.value = await backend.inspectEnvironment({ serial: selectedSerial.value || undefined, platform: selectedDevice.value?.platform, toolDirectory: toolDirectory.value || undefined })
  } catch (cause) {
    error.value = readableError(cause)
  }
}

async function setToolDirectory(directory: string) {
  toolDirectory.value = directory.trim()
  localStorage.setItem('security-console.toolDirectory', toolDirectory.value)
  try {
    await backend.configureHostEnvironment(toolDirectory.value || undefined)
    await refreshDevices()
  } catch (cause) {
    error.value = readableError(cause)
  }
}

async function openEnvironmentTerminal() {
  try {
    const message = await backend.openEnvironmentTerminal()
    terminalHistory.value.unshift({ time: Date.now(), command: 'open environment terminal', output: message, success: true })
  } catch (cause) {
    error.value = readableError(cause)
  }
}

async function mountIosDeveloperImage(directory: string) {
  if (!selectedSerial.value || selectedDevice.value?.platform !== 'ios') return
  try {
    const result = await backend.mountIosDeveloperImage({ serial: selectedSerial.value, directory })
    terminalHistory.value.unshift({ time: Date.now(), command: result.command, output: result.output, success: result.success })
    await setToolDirectory(toolDirectory.value)
  } catch (cause) {
    error.value = readableError(cause)
  }
}

async function analyzeApp(request: { path: string; apktoolPath?: string; jadxPath?: string }) {
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

onMounted(async () => {
  unlistenSignal = await listen<SignalEvent>('phone-signal', ({ payload }) => {
    signals.value.unshift(payload)
    signals.value = signals.value.slice(0, 50)
  })
  try {
    await backend.configureHostEnvironment(toolDirectory.value || undefined)
    environment.value = await backend.inspectEnvironment({ toolDirectory: toolDirectory.value || undefined })
    await refreshDevices()
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
      error.value = `打包应用未找到：${missing.join('、')}。请在环境面板配置工具目录，配置后会自动重新扫描设备。`
    }
  } catch (cause) {
    error.value = `首次环境检查失败：${readableError(cause)}`
  } finally {
    environmentChecking.value = false
  }
  connectionTimer = setInterval(() => void monitorDeviceConnection(), 4000)
})

watch(activeTab, (tab) => {
  if (tab === 'frida') void refreshFrida()
})

onBeforeUnmount(() => {
  unlistenSignal?.()
  if (connectionTimer) clearInterval(connectionTimer)
})
</script>
