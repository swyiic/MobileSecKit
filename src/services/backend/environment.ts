import { invoke } from '@tauri-apps/api/core'
import type { AdvancedCommandResult } from '@/types/common'
import type { EnvironmentReport } from '@/types/environment'

export interface InspectEnvironmentRequest {
  serial?: string
  platform?: 'android' | 'ios'
  toolDirectory?: string
}

export const environmentBackend = {
  configure: (directory?: string) => invoke<string>('configure_host_environment', { directory }),
  inspect: (request: InspectEnvironmentRequest = {}) =>
    invoke<EnvironmentReport>('inspect_environment', { request }),
  installFridaTools: () => invoke<AdvancedCommandResult>('install_frida_tools'),
  openTerminal: () => invoke<string>('open_environment_terminal'),
  mountIosDeveloperImage: (request: { serial: string; directory: string }) =>
    invoke<AdvancedCommandResult>('mount_ios_developer_image', { request }),
}
