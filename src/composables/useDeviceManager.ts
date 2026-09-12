import { computed, ref, type Ref } from 'vue'
import { deviceBackend, readableError } from '@/services/backend'
import type { TerminalEntry } from '@/types/common'
import type { DeviceDetails, DeviceSummary, InstalledAppInfo, IosDeviceDetails } from '@/types/device'
import type { EnvironmentReport } from '@/types/environment'

interface DeviceManagerContext {
  environment: Ref<EnvironmentReport | null>
  terminalHistory: Ref<TerminalEntry[]>
  error: Ref<string>
}

export function useDeviceManager(context: DeviceManagerContext) {
  const devices = ref<DeviceSummary[]>([])
  const selectedSerial = ref('')
  const details = ref<DeviceDetails | null>(null)
  const iosDetails = ref<IosDeviceDetails | null>(null)
  const installedApps = ref<InstalledAppInfo[]>([])
  const loading = ref(false)
  let connectionCheckRunning = false

  const selectedDevice = computed(() =>
    devices.value.find((device) => device.serial === selectedSerial.value),
  )
  const isConnected = computed(
    () => selectedDevice.value?.status === 'device' || selectedDevice.value?.status === 'frida',
  )
  const connectionLabel = computed(() => {
    if (!selectedDevice.value) return '等待连接移动设备'
    return `${selectedDevice.value.platform.toUpperCase()} · ${selectedDevice.value.serial} · ${selectedDevice.value.status}`
  })

  async function refreshSelected() {
    const device = selectedDevice.value
    if (!device) {
      details.value = null
      iosDetails.value = null
      installedApps.value = []
      return
    }
    if (device.platform === 'ios') {
      details.value = null
      installedApps.value = []
      if (['device', 'frida'].includes(device.status)) {
        try {
          iosDetails.value = await deviceBackend.iosDetails(device.serial)
        } catch (cause) {
          context.error.value = readableError(cause)
        }
      } else {
        iosDetails.value = null
      }
      return
    }
    if (device.status !== 'device') {
      details.value = null
      iosDetails.value = null
      installedApps.value = []
      return
    }
    iosDetails.value = null
    try {
      const [deviceDetails, deviceApps] = await Promise.all([
        deviceBackend.details(device.serial),
        deviceBackend.installedApps(device.serial),
      ])
      details.value = deviceDetails
      installedApps.value = deviceApps
    } catch (cause) {
      context.error.value = readableError(cause)
    }
  }

  async function refreshDevices() {
    loading.value = true
    context.error.value = ''
    try {
      const previousSerial = selectedSerial.value
      devices.value = await deviceBackend.list()
      const currentStillExists = devices.value.some(
        (device) => device.serial === selectedSerial.value,
      )
      if (!currentStillExists) selectedSerial.value = devices.value[0]?.serial || ''
      if (selectedSerial.value !== previousSerial) context.environment.value = null
      await refreshSelected()
    } catch (cause) {
      context.error.value = readableError(cause)
      details.value = null
      installedApps.value = []
    } finally {
      loading.value = false
    }
  }

  async function monitorDeviceConnection() {
    if (connectionCheckRunning) return
    connectionCheckRunning = true
    const previousSerial = selectedSerial.value
    try {
      const latest = await deviceBackend.list()
      if (!previousSerial) {
        devices.value = latest
        selectedSerial.value = latest[0]?.serial || ''
        if (selectedSerial.value) {
          context.environment.value = null
          await refreshSelected()
          context.terminalHistory.value.unshift({
            time: Date.now(),
            command: 'device monitor',
            output: `发现设备：${selectedSerial.value}`,
            success: true,
          })
        }
        return
      }
      if (!latest.some((device) => device.serial === previousSerial)) {
        context.terminalHistory.value.unshift({
          time: Date.now(),
          command: 'device monitor',
          output: `设备已断开：${previousSerial}`,
          success: false,
        })
        devices.value = latest
        selectedSerial.value = latest[0]?.serial || ''
        details.value = null
        iosDetails.value = null
        installedApps.value = []
        context.environment.value = null
        if (selectedSerial.value) await refreshSelected()
      }
    } catch {
      // 短暂扫描失败不覆盖当前状态，下一轮继续检查。
    } finally {
      connectionCheckRunning = false
    }
  }

  async function selectDevice(serial: string) {
    if (serial !== selectedSerial.value) context.environment.value = null
    selectedSerial.value = serial
    loading.value = true
    await refreshSelected()
    loading.value = false
  }

  return {
    devices,
    selectedSerial,
    details,
    iosDetails,
    installedApps,
    loading,
    selectedDevice,
    isConnected,
    connectionLabel,
    refreshDevices,
    monitorDeviceConnection,
    refreshSelected,
    selectDevice,
  }
}
