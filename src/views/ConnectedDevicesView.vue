<template>
  <div class="page-stack">
    <section v-if="!devices.length" class="empty-state panel">
      <span class="material-symbols-outlined">phonelink_off</span>
      <h2>没有发现移动设备</h2>
      <p>请连接 Android 或已配对的 iPhone；Android 需要 USB 调试，iOS 需要 libimobiledevice / Frida 工具链。</p>
      <button class="primary-button" @click="$emit('refresh-devices')">刷新设备列表</button>
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
            <p>{{ details?.manufacturer || iosDetails?.productType || selectedDevice?.product || selectedDevice?.platform || '移动设备' }} · {{ selectedDevice?.transportId || 'unknown transport' }} · {{ selectedDevice?.status }}</p>
          </div>
          <div v-if="details?.batteryLevel != null" class="battery-pill">
            <span class="material-symbols-outlined">{{ batteryIcon(details.batteryLevel) }}</span>
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
          <div class="wide"><span>Frida Server</span><details class="summary-details"><summary :class="details.fridaServerVersion ? 'safe' : 'danger'">{{ details.fridaServerVersion || 'Not detected' }}</summary><p>{{ details.fridaServerVersion || '未在 /data/local/tmp/frida-server 检测到版本；可到 Frida Toolbox 自动部署。' }}</p></details></div>
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

      <section class="process-panel panel">
        <div class="section-title compact">
          <div>
            <h2>已安装应用</h2>
            <p>{{ selectedDevice?.platform === 'ios' ? 'iOS 应用清单请在运行时分析中查看' : `第三方应用 · ${installedApps.length} 个` }}</p>
          </div>
          <button class="icon-button" :disabled="loading" title="刷新应用清单" @click="$emit('refresh')">
            <span class="material-symbols-outlined">refresh</span>
          </button>
        </div>
        <label class="search-box">
          <span class="material-symbols-outlined">search</span>
          <input v-model="query" placeholder="搜索应用名称或包名" />
        </label>
        <div v-if="selectedDevice?.platform === 'ios'" class="empty-inline">iOS 不使用 Android 安装包接口；请切换到运行时分析查看应用清单。</div>
        <div v-else class="process-list">
          <article v-for="app in filteredApps" :key="app.packageName" class="process-row installed-app-row user-process">
            <div class="process-mark">
              <span class="material-symbols-outlined">apps</span>
            </div>
            <div class="process-copy">
              <strong>{{ app.displayName }}</strong>
              <p><code>{{ app.packageName }}</code><span v-if="!app.labelResolved"> · 应用名称未解析</span></p>
            </div>
          </article>
          <div v-if="!filteredApps.length" class="empty-inline">没有匹配的第三方应用</div>
        </div>
      </section>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import type { DeviceDetails, DeviceSummary, InstalledAppInfo, IosDeviceDetails } from '@/types'

function batteryIcon(level: number) {
  if (level >= 90) return 'battery_android_full'
  if (level >= 70) return 'battery_android_frame_6'
  if (level >= 50) return 'battery_android_frame_4'
  if (level >= 25) return 'battery_android_frame_2'
  return 'battery_android_alert'
}

const props = defineProps<{
  devices: DeviceSummary[]
  selectedSerial: string
  details: DeviceDetails | null
  iosDetails: IosDeviceDetails | null
  installedApps: InstalledAppInfo[]
  loading: boolean
}>()

defineEmits<{
  'select-device': [serial: string]
  refresh: []
  'refresh-devices': []
}>()

const query = ref('')
const selectedDevice = computed(() => props.devices.find((item) => item.serial === props.selectedSerial))
const filteredApps = computed(() => {
  const needle = query.value.trim().toLowerCase()
  if (!needle) return props.installedApps
  return props.installedApps.filter((app) =>
    `${app.displayName} ${app.packageName}`.toLowerCase().includes(needle),
  )
})

function tone(value: string) {
  const normalized = value.toLowerCase()
  if (normalized.includes('not detected') || normalized.includes('enforcing') || normalized.includes('locked')) return 'safe'
  if (normalized.includes('root') || normalized.includes('permissive') || normalized.includes('unlocked')) return 'danger'
  return ''
}

</script>
