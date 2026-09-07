export type MonitorCapabilityStatus = 'available' | 'restricted' | 'missing' | 'warning' | 'unknown' | string
export type MonitorDeploymentRecommendation = 'standard' | 'development' | 'system' | string

export interface MonitorCapabilityCheck {
  key: string
  label: string
  status: MonitorCapabilityStatus
  detail: string
}

export interface AndroidMonitorCapabilityProbe {
  serial: string
  probedAt: number
  kernelVersion: string
  architecture: string
  androidVersion: string
  sdkVersion: string
  verifiedBootState: string
  bootloaderStatus: string
  selinuxStatus: string
  rootStatus: string
  btfStatus: string
  bpffsStatus: string
  bpfStatus: string
  agentStatus: string
  recommendedMode: MonitorDeploymentRecommendation
  trustLevel: string
  summary: string
  checks: MonitorCapabilityCheck[]
  warnings: string[]
}

export interface KernSightDurableSession {
  session_id: string
  batch_count: number
  event_count: number
  first_batch_sequence?: number | null
  last_batch_sequence?: number | null
  used_bytes: number
  state: string
  compressed: boolean
  started_unix_ms?: number | null
  stop_reason?: string | null
}

export interface KernSightAgentStatus {
  request_id: string
  session_id?: string | null
  last_batch_sequence: number
  session_count: number
  spool_used_bytes: number
  last_exit?: {
    written_unix_ms: number
    pid: number
    session_id?: string | null
    reason: string
    detail?: string | null
    clean: boolean
  } | null
  heartbeat_monotonic_ns: number
  latest_session_state?: string | null
  dropped_records?: number | null
}

export interface KernSightOverview {
  agentVersion: string
  protocolMajor: number
  protocolMinor: number
  status: KernSightAgentStatus
  sessions: KernSightDurableSession[]
  privatePackageBytes: number
  publicPackageBytes: number
}

export interface KernSightProvisionResult {
  installedVersion: string
  releaseTag: string
  releaseUrl: string
  assetSha256: string
  assetBytes: number
  steps: Array<{
    key: string
    label: string
    status: string
    detail: string
  }>
}

export interface KernSightSessionReportDocument {
  sessionId: string
  reportSchema: string
  report: Record<string, unknown>
}

export interface KernSightCaptureRequest {
  serial: string
  package?: string | null
  durationSeconds: number
  files: boolean
  filesFd: boolean
  network: boolean
  networkIo: boolean
  memory: boolean
  memoryAll: boolean
  binder: boolean
  sched: boolean
  includeThreads: boolean
  inspectTls: boolean
  inspectJni: boolean
  inspectLinker: boolean
  inspectAdapter?: 'binder_userspace' | null
  hideDebug: boolean
  sampleOneIn: number
  inspectMaxBytes: number
  inspectMaxHits: number
  launchAfterAttach?: boolean
  /** Burp HTTP proxy host:port. Phone feeds reconstructed HTTP/WS; app TLS is unchanged. */
  mirrorBurp?: string | null
  /** adb reverse the Burp port and adb forward playback 18081. */
  mirrorViaAdb?: boolean
}

export interface KernSightMirrorStatus {
  running: boolean
  cleanupPending: boolean
  package?: string | null
  serial?: string | null
  detail?: string | null
  logs: string[]
}

export interface KernSightCaptureResult {
  sessionId?: string | null
  startedUnixMs: number
  finishedUnixMs: number
  commandPreview: string
  stdout: string
  stderr: string
  exitCode?: number | null
  hideDebug: boolean
}

export interface KernSightEventPage {
  sessionId: string
  offset: number
  limit: number
  totalMatches: number
  nextOffset?: number | null
  typeCounts: Record<string, number>
  events: Array<Record<string, unknown>>
}

export interface KernSightSensitiveFile {
  relative_path: string
  content_class: string
  bytes: number
  sha256: string
  confirmed: boolean
}

export interface KernSightEvidenceFileContent {
  package: string
  relativePath: string
  bytes: number
  truncated: boolean
  encoding: 'base64' | string
  content: string
}

export interface KernSightLocalEvidenceBundle {
  root: string
  package: string
  fileCount: number
  totalBytes: number
  dumpReport: KernSightPackageDumpReport
  sessionReport?: Record<string, unknown> | null
  captureText: string
  files: Array<{
    relativePath: string
    bytes: number
    category: string
  }>
}

export type KernSightEvidenceStrength = 'confirmed' | 'correlated' | 'inferred' | 'absent'

export interface KernSightAnalyzerFact {
  key: string
  layer: 'L0' | 'L1' | 'L2'
  title: string
  summary: string
  strength: KernSightEvidenceStrength
  items: string[]
}

export interface KernSightAnalyzerJoin {
  package: string
  root: string
  sessionId?: string
  fileCount: number
  facts: KernSightAnalyzerFact[]
  disclaimer: string
}

export interface KernSightDexObservation {
  source: string
  relative_path: string
  pid?: number | null
  vma_start?: number | null
  vma_end?: number | null
  map_path?: string | null
  dex_offset?: number | null
}

export interface KernSightDexSemanticSummary {
  version: string
  declared_file_size: number
  string_ids: number
  type_ids: number
  field_ids: number
  method_ids: number
  class_defs: number
  class_descriptors: string[]
  class_descriptors_truncated: boolean
  method_names: string[]
  method_names_truncated: boolean
}

export interface KernSightDexSet {
  sha256: string
  bytes: number
  canonical_relative_path: string
  sources: string[]
  observations: KernSightDexObservation[]
  semantic?: KernSightDexSemanticSummary | null
}

export interface KernSightDexIndex {
  unique_dex: number
  observations: number
  indexed_class_samples: number
  indexed_method_name_samples: number
  class_conflicts: Array<{ descriptor: string; dex_sha256: string[] }>
  semantic_parse_failures: number
  semantic_index_truncated: boolean
}

export interface KernSightNativeFrameworkMatch {
  rule_id: string
  name: string
  category: 'packer_shell' | 'crypto_framework' | string
  confidence: string
  description: string
  evidence: Array<{
    relative_path: string
    source: string
    sha256?: string | null
    pid?: number | null
  }>
}

export interface KernSightPackageDumpReport {
  schema_version?: string
  agent_version?: string
  created_unix_ms?: number
  package: string
  dump_id?: string
  install_dir?: string | null
  launched?: boolean
  pids?: number[]
  apk_files?: number
  native_libs?: number
  oat_files?: number
  apk_dex?: number
  memory_images?: number
  vdex_images?: number
  fd_images?: number
  readable_dex?: number
  runtime_libs?: number
  runtime_blob_dex?: number
  asset_files?: number
  private_files?: number
  packer_regions?: number
  plaintext_windows?: number
  http_calls?: Array<Record<string, unknown>>
  http_code_refs?: Array<Record<string, unknown>>
  jni_exports?: Array<{ relative_path?: string; names?: string[] }>
  key_slots?: number
  secneo_decrypted?: number
  artifacts?: unknown[]
  dex_sets?: KernSightDexSet[]
  dex_index?: KernSightDexIndex
  native_rule_version?: string
  native_framework_matches?: KernSightNativeFrameworkMatch[]
  sensitive_files?: KernSightSensitiveFile[]
  snapshots?: Array<Record<string, unknown>>
  mapped_code?: Array<Record<string, unknown>>
  open_code?: Array<Record<string, unknown>>
  code_loaders?: Array<Record<string, unknown>>
  total_bytes?: number
  warnings?: string[]
  graph?: {
    entities?: Array<Record<string, unknown>>
    edges?: Array<Record<string, unknown>>
  }
}
