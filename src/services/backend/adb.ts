import { invoke } from '@tauri-apps/api/core'
import type { AdvancedCommandResult, CommandResult } from '@/types/common'
import type { AdbAction } from '@/types/device'
import type { CertificateInfo } from '@/types/environment'

export const adbBackend = {
  runAction: (serial: string, action: AdbAction, argument = '') =>
    invoke<CommandResult>('run_adb_action', { request: { serial, action, argument } }),
  runShell: (serial: string, command: string) =>
    invoke<AdvancedCommandResult>('run_shell', { request: { serial, command } }),
  runProxy: (request: { serial: string; action: string; host?: string; port?: number }) =>
    invoke<AdvancedCommandResult>('run_proxy', { request }),
  certificateInfo: (path: string) => invoke<CertificateInfo>('certificate_info', { path }),
  installCertificate: (serial: string, path: string) =>
    invoke<AdvancedCommandResult>('install_certificate', { request: { serial, path } }),
  pullFiles: (request: { serial: string; remotePath: string; localDir: string }) =>
    invoke<CommandResult>('pull_device_files', { request }),
  pushFile: (request: { serial: string; localPath: string }) =>
    invoke<CommandResult>('push_device_file', { request }),
}
