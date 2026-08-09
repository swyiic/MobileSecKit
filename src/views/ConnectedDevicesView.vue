<template>
  <div class="page-stack">
    <section v-if="!devices.length" class="empty-state panel">
      <span class="material-symbols-outlined">phonelink_off</span>
      <h2>没有发现 Android 设备</h2>
      <p>请连接 Android 或已配对的 iPhone；Android 需要 USB 调试，iOS 需要 libimobiledevice / Frida 工具链。</p>
      <button class="primary-button" @click="$emit('refresh')">重新检测</button>
    </section>

    <template v-else>
      <section class="device-card panel">
        <div class="device-card-top">
          <div class="phone-avatar">
            <span class="material-symbols-outlined">smartphone</span>
            <i :class="{ offline: !['device', 'frida'].includes(selectedDevice?.status || '') }"></i>
          </div>
          <div class="device-heading">
            <label for="device-select">当前设备 · {{ selectedDevice?.platform?.toUpperCase() }}</label>
            <select
              id="device-select"
              :value="selectedSerial"
              @change="$emit('select-device', ($event.target as HTMLSelectElement).value)"
            >
              <option v-for="device in devices" :key="device.serial" :value="device.serial">
                {{ device.model }} · {{ device.serial }}
              </option>
            </select>
            <p>{{ details?.manufacturer || selectedDevice?.product || 'Android' }} · {{ selectedDevice?.status }}</p>
          </div>
          <div v-if="details?.batteryLevel != null" class="battery-pill">
            <span class="material-symbols-outlined">battery_android_frame_4</span>
            {{ details.batteryLevel }}%
          </div>
        </div>

        <div v-if="details" class="spec-grid">
          <div><span>Android</span><strong>{{ details.androidVersion }} (SDK {{ details.sdkVersion }})</strong></div>
          <div><span>Root Status</span><strong :class="tone(details.rootStatus)">{{ details.rootStatus }}</strong></div>
          <div><span>SELinux</span><strong :class="tone(details.selinuxStatus)">{{ details.selinuxStatus }}</strong></div>
          <div><span>Bootloader</span><strong :class="tone(details.bootloaderStatus)">{{ details.bootloaderStatus }}</strong></div>
          <div class="wide"><span>Build Number</span><code>{{ details.buildNumber }}</code></div>
          <div><span>IP Address</span><strong class="accent">{{ details.ipAddress }}</strong></div>
          <div><span>Architecture</span><strong>{{ details.architecture }}</strong></div>
          <div><span>Family</span><strong>{{ details.architectureFamily }}</strong></div>
          <div><span>ABI List</span><strong>{{ details.abiList.join(', ') || '—' }}</strong></div>
          <div><span>Security Patch</span><strong>{{ details.securityPatch }}</strong></div>
          <div><span>Brand</span><strong>{{ details.brand }}</strong></div>
          <div><span>Frida Server</span><details class="summary-details"><summary :class="details.fridaServerVersion ? 'safe' : 'danger'">{{ details.fridaServerVersion || 'Not detected' }}</summary><p>{{ details.fridaServerVersion || '未在 /data/local/tmp/frida-server 检测到版本；可到 Frida Toolbox 自动部署。' }}</p></details></div>
          <div class="wide"><span>Kernel</span><strong>{{ details.kernelVersion }}</strong></div>
        </div>
        <div v-else-if="iosDetails" class="spec-grid">
          <div><span>Device Name</span><strong>{{ iosDetails.deviceName }}</strong></div>
          <div><span>Product Type</span><strong>{{ iosDetails.productType }}</strong></div>
          <div><span>iOS Version</span><strong>{{ iosDetails.productVersion }}</strong></div>
          <div><span>Build</span><strong>{{ iosDetails.buildVersion }}</strong></div>
          <div><span>Activation</span><strong :class="iosDetails.activationState === 'Activated' ? 'safe' : 'danger'">{{ iosDetails.activationState }}</strong></div>
          <div><span>Architecture</span><strong>{{ iosDetails.architecture }}</strong></div>
          <div><span>Battery</span><strong>{{ iosDetails.batteryLevel == null ? '—' : `${iosDetails.batteryLevel}%` }}</strong></div>
          <div class="wide"><span>Runtime note</span><strong>{{ iosDetails.jailbreakHint }}</strong></div>
        </div>
        <div v-else class="inline-state">
          {{ selectedDevice?.platform === 'ios' ? '已识别 iOS：ADB 不可用；请在 Frida Toolbox 中进行运行时观测。' : selectedDevice?.status === 'unauthorized' ? '请在手机上点击“允许 USB 调试”' : '设备暂不可读取' }}
        </div>
      </section>

      <section class="bridge-panel panel">
        <div class="section-title">
          <div>
            <div class="eyebrow">ANDROID → RUST → VUE</div>
            <h2>Signal Bridge</h2>
            <p>接收手机 JSON 信号，由 Rust 规则判断并实时返回。</p>
          </div>
          <span class="live-pill" :class="{ online: bridgeStatus?.running }">
            {{ bridgeStatus?.running ? 'LISTENING' : 'STOPPED' }}
          </span>
        </div>
        <div class="bridge-actions">
          <div class="endpoint">
            <span class="material-symbols-outlined">lan</span>
            {{ bridgeStatus?.endpoint || '127.0.0.1:7878' }}
          </div>
          <button class="primary-button" :disabled="selectedDevice?.platform !== 'android' || selectedDevice?.status !== 'device' || bridgeStatus?.running" @click="$emit('start-bridge')">
            <span class="material-symbols-outlined">sensors</span>
            {{ bridgeStatus?.running ? '服务已启动' : '启动信号服务' }}
          </button>
        </div>

        <div v-if="signals.length" class="signal-list">
          <article v-for="event in signals.slice(0, 6)" :key="`${event.decision.signalId}-${event.decision.receivedAt}`" class="signal-row">
            <span class="decision-icon" :class="event.decision.decision">
              <span class="material-symbols-outlined">{{ decisionIcon(event.decision.decision) }}</span>
            </span>
            <div>
              <strong>{{ event.signal.kind }}</strong>
              <p>{{ event.decision.message }}</p>
            </div>
            <div class="signal-meta">
              <span :class="`risk-${event.decision.riskLevel}`">{{ event.decision.decision }}</span>
              <time>{{ formatTime(event.decision.receivedAt) }}</time>
            </div>
          </article>
        </div>
        <div v-else class="empty-inline">启动后，等待安卓端发送第一条信号。</div>
      </section>

      <section class="process-panel panel">
        <div class="section-title compact">
          <div>
            <h2>Process Monitor</h2>
            <p>{{ selectedDevice?.platform === 'ios' ? 'iOS 进程请在 Frida Toolbox 中刷新' : '按内存排序的实时进程快照' }}</p>
          </div>
          <button class="icon-button" :disabled="loading" title="刷新进程" @click="$emit('refresh')">
            <span class="material-symbols-outlined">refresh</span>
          </button>
        </div>
        <label class="search-box">
          <span class="material-symbols-outlined">search</span>
          <input v-model="query" placeholder="搜索 PID、用户或包名" />
        </label>
        <div v-if="selectedDevice?.platform === 'ios'" class="empty-inline">iOS 不使用 ADB 进程接口；切换到 Frida Toolbox 查看运行中的 App。</div>
        <div v-else class="process-list">
          <article v-for="process in filteredProcesses" :key="process.pid" class="process-row" :class="[process.system ? 'system-process' : 'user-process', { muted: process.protected }]">
            <div class="process-mark">
              <span class="material-symbols-outlined">{{ process.protected ? 'shield_lock' : 'memory' }}</span>
            </div>
            <div class="process-copy">
              <strong>{{ process.name }}</strong>
              <p>PID {{ process.pid }} · {{ process.user }} · {{ formatMemory(process.memoryKb) }}</p>
            </div>
            <button class="ghost-button" :disabled="process.protected" @click="$emit('inspect-process', process)">
              Inspect
            </button>
          </article>
          <div v-if="!filteredProcesses.length" class="empty-inline">没有匹配的进程</div>
        </div>
      </section>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import type { BridgeStatus, DeviceDetails, DeviceSummary, IosDeviceDetails, ProcessInfo, SignalEvent } from '@/types'

const props = defineProps<{
  devices: DeviceSummary[]
  selectedSerial: string
  details: DeviceDetails | null
  iosDetails: IosDeviceDetails | null
  processes: ProcessInfo[]
  signals: SignalEvent[]
  loading: boolean
  bridgeStatus: BridgeStatus | null
}>()

defineEmits<{
  'select-device': [serial: string]
  refresh: []
  'start-bridge': []
  'inspect-process': [process: ProcessInfo]
}>()

const query = ref('')
const selectedDevice = computed(() => props.devices.find((item) => item.serial === props.selectedSerial))
const filteredProcesses = computed(() => {
  const needle = query.value.trim().toLowerCase()
  if (!needle) return props.processes
  return props.processes.filter((process) =>
    `${process.pid} ${process.user} ${process.name}`.toLowerCase().includes(needle),
  )
})

function formatMemory(memoryKb: number) {
  return memoryKb ? `${(memoryKb / 1024).toFixed(memoryKb > 10240 ? 0 : 1)} MB` : '—'
}

function formatTime(timestamp: number) {
  return new Intl.DateTimeFormat('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(timestamp)
}

function tone(value: string) {
  const normalized = value.toLowerCase()
  if (normalized.includes('not detected') || normalized.includes('enforcing') || normalized.includes('locked')) return 'safe'
  if (normalized.includes('root') || normalized.includes('permissive') || normalized.includes('unlocked')) return 'danger'
  return ''
}

function decisionIcon(decision: string) {
  return decision === 'block' || decision === 'reject'
    ? 'block'
    : decision === 'review'
      ? 'warning'
      : 'check_circle'
}
</script>
