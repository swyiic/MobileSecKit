import { invoke } from '@tauri-apps/api/core'
import type {
  AdbAction,
  AdvancedCommandResult,
  AppAnalysis,
  BridgeStatus,
  CertificateInfo,
  CommandResult,
  DeviceDetails,
  DeviceSummary,
  EnvironmentReport,
  FridaProcess,
  FridaScriptEntry,
  IosDeviceDetails,
  ProcessInfo,
} from '@/types'

export const backend = {
  configureHostEnvironment: (directory?: string) => invoke<string>('configure_host_environment', { directory }),
  listDevices: () => invoke<DeviceSummary[]>('list_devices'),
  getDeviceDetails: (serial: string) =>
    invoke<DeviceDetails>('get_device_details', { serial }),
  getIosDeviceDetails: (serial: string) =>
    invoke<IosDeviceDetails>('get_ios_device_details', { serial }),
  listProcesses: (serial: string) =>
    invoke<ProcessInfo[]>('list_processes', { serial }),
  runAction: (serial: string, action: AdbAction, argument = '') =>
    invoke<CommandResult>('run_adb_action', {
      request: { serial, action, argument },
    }),
  inspectEnvironment: (request: { serial?: string; platform?: 'android' | 'ios'; toolDirectory?: string } = {}) =>
    invoke<EnvironmentReport>('inspect_environment', { request }),
  runShell: (serial: string, command: string) =>
    invoke<AdvancedCommandResult>('run_shell', { request: { serial, command } }),
  runProxy: (request: { serial: string; action: string; host?: string; port?: number }) =>
    invoke<AdvancedCommandResult>('run_proxy', { request }),
  certificateInfo: (path: string) => invoke<CertificateInfo>('certificate_info', { path }),
  installCertificate: (serial: string, path: string) =>
    invoke<AdvancedCommandResult>('install_certificate', { request: { serial, path } }),
  listFridaProcesses: (serial?: string) =>
    invoke<FridaProcess[]>('list_frida_processes', { serial }),
  listFridaScripts: (directory?: string) => invoke<FridaScriptEntry[]>('list_frida_scripts', { directory }),
  runFridaScript: (request: { serial?: string; process: string; pid?: number; mode: string; script: string; scriptPath?: string }) =>
    invoke<AdvancedCommandResult>('run_frida_script', { request }),
  runDexDump: (request: { serial: string; package: string; scriptPath: string; destinationDirectory?: string; durationSeconds?: number }) =>
    invoke<AdvancedCommandResult>('run_dex_dump', { request }),
  runSoDump: (request: { serial: string; package: string; scriptPath: string; destinationDirectory?: string; durationSeconds?: number }) =>
    invoke<AdvancedCommandResult>('run_so_dump', { request }),
  runIosDump: (request: { serial: string; bundleId: string; destinationDirectory?: string }) => invoke<AdvancedCommandResult>('run_ios_dump', { request }),
  manageFridaServer: (request: { serial: string; action: 'start' | 'stop' | 'log'; path?: string }) =>
    invoke<AdvancedCommandResult>('manage_frida_server', { request }),
  downloadFridaServer: (request: { serial: string; destinationDirectory?: string }) =>
    invoke<AdvancedCommandResult>('download_frida_server', { request }),
  installFridaTools: () => invoke<AdvancedCommandResult>('install_frida_tools'),
  openEnvironmentTerminal: () => invoke<string>('open_environment_terminal'),
  mountIosDeveloperImage: (request: { serial: string; directory: string }) =>
    invoke<AdvancedCommandResult>('mount_ios_developer_image', { request }),
  analyzeApp: (request: { path: string; apktoolPath?: string; jadxPath?: string }) =>
    invoke<AppAnalysis>('analyze_app', { request }),
  startSignalBridge: (serial: string) =>
    invoke<BridgeStatus>('start_signal_bridge', { serial }),
  getBridgeStatus: () => invoke<BridgeStatus>('get_bridge_status'),
}

export function readableError(error: unknown): string {
  if (typeof error === 'string') return error
  if (error instanceof Error) return error.message
  return '发生未知错误'
}
