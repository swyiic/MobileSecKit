import { invoke } from '@tauri-apps/api/core'
import { reactive } from 'vue'
import type { AiProviderKind } from '@/types'

export type IosCompatibilityProfile = 'minimal' | 'compat' | 'aggressive'
export type AndroidMonitorDeploymentMode = 'auto' | 'development' | 'system'

export interface AppConfig {
  toolDirectory: string
  fridaScriptDirectory: string
  fridaScriptPath: string
  fridaServerPath: string
  iosDeveloperImageDirectory: string
  dexDestination: string
  soDestination: string
  iosDumpDestination: string
  iosCompatibilityProfile: IosCompatibilityProfile
  hardenFridaByDefault: boolean
  apktoolPath: string
  jadxPath: string
  excludedUrls: string
  aiProviderKind: AiProviderKind
  aiProviderBaseUrl: string
  aiProviderModel: string
  aiProviderApiKey: string
  aiProviderTimeout: number
  aiProviderOutputTokens: number
  androidMonitorDeploymentMode: AndroidMonitorDeploymentMode
  androidMonitorAutoReconnect: boolean
  androidMonitorAutoProvision: boolean
  androidMonitorLocalPort: number
  androidMonitorBatchSize: number
  androidMonitorSpoolLimitMb: number
}

export const defaultAppConfig: AppConfig = {
  toolDirectory: '',
  fridaScriptDirectory: '',
  fridaScriptPath: '',
  fridaServerPath: '',
  iosDeveloperImageDirectory: '',
  dexDestination: '',
  soDestination: '',
  iosDumpDestination: '',
  iosCompatibilityProfile: 'minimal',
  hardenFridaByDefault: false,
  apktoolPath: '',
  jadxPath: '',
  excludedUrls: '',
  aiProviderKind: 'ollama',
  aiProviderBaseUrl: 'http://127.0.0.1:11434',
  aiProviderModel: '',
  aiProviderApiKey: '',
  aiProviderTimeout: 120,
  aiProviderOutputTokens: 2000,
  androidMonitorDeploymentMode: 'auto',
  androidMonitorAutoReconnect: true,
  androidMonitorAutoProvision: false,
  androidMonitorLocalPort: 18080,
  androidMonitorBatchSize: 500,
  androidMonitorSpoolLimitMb: 512,
}

export const appConfig = reactive<AppConfig>({ ...defaultAppConfig })

const legacyKeys: Array<{
  storageKey: string
  configKey: keyof AppConfig
  parse?: (value: string) => AppConfig[keyof AppConfig]
}> = [
  { storageKey: 'security-console.toolDirectory', configKey: 'toolDirectory' },
  { storageKey: 'security-console.fridaScriptDirectory', configKey: 'fridaScriptDirectory' },
  { storageKey: 'security-console.fridaScriptPath', configKey: 'fridaScriptPath' },
  { storageKey: 'security-console.fridaServerPath', configKey: 'fridaServerPath' },
  { storageKey: 'security-console.iosDeveloperImageDirectory', configKey: 'iosDeveloperImageDirectory' },
  { storageKey: 'security-console.dexDestination', configKey: 'dexDestination' },
  { storageKey: 'security-console.soDestination', configKey: 'soDestination' },
  { storageKey: 'security-console.iosDumpDestination', configKey: 'iosDumpDestination' },
  { storageKey: 'security-console.iosCompatibilityProfile', configKey: 'iosCompatibilityProfile', parse: parseProfile },
  { storageKey: 'mobilee.frida.hardenByDefault', configKey: 'hardenFridaByDefault', parse: (value) => value === 'true' },
  { storageKey: 'security-console.apktoolPath', configKey: 'apktoolPath' },
  { storageKey: 'security-console.jadxPath', configKey: 'jadxPath' },
  { storageKey: 'security-console.excludedUrls', configKey: 'excludedUrls' },
  { storageKey: 'me.ai.provider.kind', configKey: 'aiProviderKind', parse: parseProviderKind },
  { storageKey: 'me.ai.provider.baseUrl', configKey: 'aiProviderBaseUrl' },
  { storageKey: 'me.ai.provider.model', configKey: 'aiProviderModel' },
  { storageKey: 'me.ai.provider.apiKey', configKey: 'aiProviderApiKey' },
  { storageKey: 'me.ai.provider.timeout', configKey: 'aiProviderTimeout', parse: (value) => Math.min(600, Math.max(10, parseNumber(value) || 120)) },
  { storageKey: 'me.ai.provider.outputTokens', configKey: 'aiProviderOutputTokens', parse: (value) => Math.min(32_000, Math.max(400, parseNumber(value) || 2000)) },
]

let loadPromise: Promise<AppConfig> | undefined
let persistTimer: ReturnType<typeof setTimeout> | undefined

function parseNumber(value: string): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : 0
}

function parseProviderKind(value: string): AppConfig['aiProviderKind'] {
  return value === 'openai-compatible' ? 'openai-compatible' : 'ollama'
}

function parseProfile(value: string): IosCompatibilityProfile {
  return value === 'compat' || value === 'aggressive' ? value : 'minimal'
}

function localStorageAvailable(): boolean {
  return typeof window !== 'undefined' && typeof window.localStorage !== 'undefined'
}

function legacyPatch(): { patch: Partial<AppConfig>; keys: string[] } {
  const patch: Partial<AppConfig> = {}
  const keys: string[] = []
  if (!localStorageAvailable()) return { patch, keys }
  for (const item of legacyKeys) {
    const value = window.localStorage.getItem(item.storageKey)
    if (value === null) continue
    const parsed = item.parse ? item.parse(value) : value
    ;(patch as Record<string, unknown>)[item.configKey] = parsed
    keys.push(item.storageKey)
  }
  return { patch, keys }
}

function snapshot(): AppConfig {
  return { ...appConfig }
}

async function persist(config: AppConfig): Promise<string> {
  return invoke<string>('save_app_config', { config })
}

export function loadAppConfig(): Promise<AppConfig> {
  if (loadPromise) return loadPromise
  loadPromise = (async () => {
    const migration = legacyPatch()
    try {
      const loaded = await invoke<AppConfig>('load_app_config')
      Object.assign(appConfig, defaultAppConfig, loaded, migration.patch)
      if (migration.keys.length) {
        await persist(snapshot())
        for (const key of migration.keys) window.localStorage.removeItem(key)
      }
    } catch (error) {
      // Browser preview has no Tauri IPC. Keep defaults and legacy values in memory,
      // and retain legacy storage until a native config.ini write succeeds.
      Object.assign(appConfig, defaultAppConfig, migration.patch)
      console.warn('Unable to load local config.ini; using in-memory settings.', error)
    }
    return snapshot()
  })()
  return loadPromise
}

export function updateAppConfig(patch: Partial<AppConfig>): void {
  Object.assign(appConfig, patch)
  if (persistTimer) clearTimeout(persistTimer)
  persistTimer = setTimeout(() => {
    persistTimer = undefined
    void persist(snapshot()).catch((error) => {
      console.warn('Unable to save local config.ini.', error)
    })
  }, 400)
}

export async function saveAppConfigNow(patch: Partial<AppConfig> = {}): Promise<string> {
  Object.assign(appConfig, patch)
  if (persistTimer) {
    clearTimeout(persistTimer)
    persistTimer = undefined
  }
  return persist(snapshot())
}
