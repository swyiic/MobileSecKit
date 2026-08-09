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

export interface CommandResult {
  success: boolean
  command: string
  output: string
  exitCode?: number
}

export interface BridgeStatus {
  running: boolean
  port: number
  endpoint: string
}

export interface PhoneSignal {
  id: string
  deviceId: string
  kind: string
  value: string
  timestamp?: number
  payload: unknown
}

export interface SignalDecision {
  signalId: string
  accepted: boolean
  decision: 'allow' | 'review' | 'block' | 'record' | 'reject'
  riskLevel: 'info' | 'low' | 'medium' | 'high' | 'critical'
  message: string
  receivedAt: number
}

export interface SignalEvent {
  signal: PhoneSignal
  decision: SignalDecision
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

export interface ToolStatus {
  name: string
  executable: string
  available: boolean
  version?: string
  path?: string
  category: 'system' | 'optional'
  group: 'frida' | 'analyzer'
}

export interface EnvironmentReport {
  hostOs: string
  hostArch: string
  tools: ToolStatus[]
  deviceFridaVersion?: string
  deviceFridaReachable: boolean
  deviceFridaRequiresDeveloperImage: boolean
  deviceArchitecture?: string
  recommendedFridaServer?: string
  fridaVersionMatch?: boolean
  hostFridaToolsMatch?: boolean
}

export interface AdvancedCommandResult extends CommandResult {}

export interface FridaProcess {
  pid?: number
  name: string
  identifier: string
  platform: string
}

export interface FridaScriptEntry {
  id: string
  name: string
  description: string
  category: string
  path: string
  platform: 'android' | 'ios' | 'both'
}

export interface CertificateInfo {
  path: string
  subjectHash: string
  sha256: string
  systemTarget: string
  note: string
}

export interface AppFinding {
  severity: string
  title: string
  detail: string
}

export interface SensitiveItem {
  item: string
  location: string
  kind: string
  severity: string
  value?: string
  lineNumber?: number
  context?: string
}

export interface ProtectionAssessment {
  status: string
  packers: string[]
  indicators: string[]
}

export interface AppAnalysis {
  platform: 'android' | 'ios'
  path: string
  fileName: string
  fileSize: number
  packageId?: string
  displayName?: string
  versionName?: string
  versionCode?: string
  minSdk?: string
  targetSdk?: string
  architectures: string[]
  frameworks: string[]
  thirdPartyLibraries: string[]
  protection: ProtectionAssessment
  permissions: string[]
  components: string[]
  exportedComponents: string[]
  intentFilters: string[]
  manifestFlags: string[]
  files: string[]
  manifestXml?: string
  sensitiveItems: SensitiveItem[]
  signature?: string
  findings: AppFinding[]
  toolsUsed: string[]
  missingDependencies: string[]
}
