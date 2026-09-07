import type { RuntimeEvidenceStepKey } from './common'

export type IosCompatibilityProfile = 'minimal' | 'compat' | 'aggressive'
export type FridaMode = 'attach' | 'spawn'

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

export interface RunFridaRequest {
  process: string
  pid?: number
  mode: string
  script: string
  scriptPath?: string
  durationSeconds?: number
  compatibilityProfile?: IosCompatibilityProfile
  platform?: 'android' | 'ios'
}

export interface RuntimeWorkflowStep {
  key: RuntimeEvidenceStepKey
  scriptPath: string
}

export interface RuntimeWorkflowRequest {
  process: string
  pid?: number
  mode: FridaMode
  durationSeconds?: number
  compatibilityProfile?: IosCompatibilityProfile
  steps: RuntimeWorkflowStep[]
}

export interface DexDumpRequest {
  package: string
  scriptPath: string
  destinationDirectory?: string
  durationSeconds?: number
  mode?: FridaMode
  pid?: number
}

export interface SoDumpRequest extends DexDumpRequest {}

export interface IosDumpRequest {
  bundleId: string
  destinationDirectory?: string
  mode?: FridaMode
  compatibilityProfile?: IosCompatibilityProfile
}

export interface FridaServerRequest {
  action: 'start' | 'stop' | 'log' | 'harden'
  path?: string
}
