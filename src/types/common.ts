export interface CommandResult {
  success: boolean
  command: string
  output: string
  exitCode?: number
}

export interface AdvancedCommandResult extends CommandResult {}

export interface TerminalEntry {
  time: number
  command: string
  output: string
  success: boolean
  /** Bundle ID / package name explicitly selected for this runtime action. */
  appId?: string
  deviceId?: string
  platform?: 'android' | 'ios' | 'unknown'
  source?: 'frida' | 'adb' | 'environment' | 'system'
  /** Stable runtime workflow step used by coverage/status correlation. */
  runtimeStep?: RuntimeEvidenceStepKey
  /** Entry restored from a project snapshot; device mismatch must not hide it. */
  persisted?: boolean
}

export type RuntimeEvidenceStepKey =
  | 'injection'
  | 'language-runtime'
  | 'network-tls'
  | 'webview-bridge'
  | 'storage-crypto'
  | 'root-environment'
  | 'dex-artifact'
  | 'so-artifact'
  | 'app-artifact'
  | 'protection'

export type RuntimeEvidenceStatus = 'idle' | 'complete' | 'blocked'

export interface RuntimeEvidenceStepStatus {
  key: RuntimeEvidenceStepKey
  label: string
  description: string
  status: RuntimeEvidenceStatus
  detail?: string
  lastRunAt?: number
}
