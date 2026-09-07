export interface DeviceSummary {
  platform: 'android' | 'ios'
  serial: string
  status: string
  model: string
  product: string
  device: string
  transportId?: string
}

export interface DeviceDetails {
  serial: string
  model: string
  manufacturer: string
  androidVersion: string
  sdkVersion: string
  buildNumber: string
  codename: string
  architecture: string
  rootStatus: string
  selinuxStatus: string
  bootloaderStatus: string
  ipAddress: string
  kernelVersion: string
  batteryLevel?: number
  architectureFamily: string
  abiList: string[]
  securityPatch: string
  brand: string
  fridaServerVersion?: string
}

export interface IosDeviceDetails {
  serial: string
  deviceName: string
  productType: string
  productVersion: string
  buildVersion: string
  activationState: string
  batteryLevel?: number
  architecture: string
  jailbreakHint: string
}

export interface ProcessInfo {
  pid: number
  user: string
  memoryKb: number
  name: string
  protected: boolean
  system: boolean
}

export type AdbAction =
  | 'reboot'
  | 'recovery'
  | 'logcat'
  | 'packages'
  | 'processes'
  | 'permissions'
  | 'process_info'
  | 'storage'
  | 'shared_preferences'
  | 'databases'
  | 'webview_storage'
  | 'system_properties'
  | 'mounts'
  | 'proxy_status'
  | 'selinux_status'
  | 'selinux_permissive'
  | 'selinux_enforcing'
  | 'install_apk'
  | 'uninstall_apk'
