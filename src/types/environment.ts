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

export interface CertificateInfo {
  path: string
  subjectHash: string
  sha256: string
  systemTarget: string
  note: string
}
