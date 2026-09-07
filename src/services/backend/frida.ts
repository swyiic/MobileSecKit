import { invoke } from '@tauri-apps/api/core'
import type { AdvancedCommandResult } from '@/types/common'
import type { AntiInstrumentationAssessment } from '@/types/analysis'
import type {
  DexDumpRequest,
  FridaProcess,
  FridaScriptEntry,
  FridaServerRequest,
  IosDumpRequest,
  RunFridaRequest,
  SoDumpRequest,
} from '@/types/frida'

export const fridaBackend = {
  listProcesses: (serial?: string) => invoke<FridaProcess[]>('list_frida_processes', { serial }),
  listScripts: (directory?: string) => invoke<FridaScriptEntry[]>('list_frida_scripts', { directory }),
  runScript: (request: RunFridaRequest & { serial?: string }) =>
    invoke<AdvancedCommandResult>('run_frida_script', { request }),
  confirmAntiInstrumentation: (request: {
    assessment: AntiInstrumentationAssessment
    runtimeOutput: string
    exitCode?: number
    appId?: string
  }) => invoke<AntiInstrumentationAssessment>('confirm_anti_instrumentation', { request }),
  dumpDex: (request: DexDumpRequest & { serial: string }) =>
    invoke<AdvancedCommandResult>('run_dex_dump', { request }),
  dumpSo: (request: SoDumpRequest & { serial: string }) =>
    invoke<AdvancedCommandResult>('run_so_dump', { request }),
  dumpIos: (request: IosDumpRequest & { serial: string }) =>
    invoke<AdvancedCommandResult>('run_ios_dump', { request }),
  manageServer: (request: FridaServerRequest & { serial: string }) =>
    invoke<AdvancedCommandResult>('manage_frida_server', { request }),
  downloadServer: (request: { serial: string; destinationDirectory?: string }) =>
    invoke<AdvancedCommandResult>('download_frida_server', { request }),
}
