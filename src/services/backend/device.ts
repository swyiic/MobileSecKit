import { invoke } from '@tauri-apps/api/core'
import type { DeviceDetails, DeviceSummary, InstalledAppInfo, IosDeviceDetails, ProcessInfo } from '@/types/device'

export const deviceBackend = {
  list: () => invoke<DeviceSummary[]>('list_devices'),
  details: (serial: string) => invoke<DeviceDetails>('get_device_details', { serial }),
  iosDetails: (serial: string) => invoke<IosDeviceDetails>('get_ios_device_details', { serial }),
  processes: (serial: string) => invoke<ProcessInfo[]>('list_processes', { serial }),
  installedApps: (serial: string) => invoke<InstalledAppInfo[]>('list_installed_apps', { serial }),
}
