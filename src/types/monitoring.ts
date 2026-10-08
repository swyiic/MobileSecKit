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
  agentBuildIdentity?: {
    version: string
    gitCommit: string | null
    gitDirty: boolean | null
    source: 'git' | 'override' | 'unknown'
    binarySha256: string | null
  } | null
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
  runtimePaths?:{root:string;agentPath:string;expectedSha256:string}|null
  sessionBudget?:{totalBytes:number;maxSeconds:number}|null
  codeOnly?:boolean
  collectKeys?:boolean
  collectPrivate?:boolean
  collectMemoryWindows?:boolean
  outputBudgetBytes?:number|null
  outputBudgetMs?:number|null
  captureRelation?:KernSightCaptureRelation|null
  captureRelations?:KernSightCaptureRelation[]|null
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
  inspectStages?: string | null
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
  coverage: KernSightMirrorCoverage
}

export interface KernSightMirrorCoverage {
  networkConnects: number
  networkHandshakes: number
  observedFragments: number
  observedBytes: number
  reconstructedMessages: number
  reconstructedRequests: number
  reconstructedResponses: number
  delivered: number
  deliveryFailed: number
  retryPending: number
  unknownDirections: number
  bufferedBytes: number
  attachedProbes: number
  activeProbes: number
  standardTlsFragments: number
  vendorFragments: number
  jniFragments: number
  stackCandidates: number
  stackExportCandidates: number
  stackPinnedBoundaries: number
  stackEmpiricalBoundaries: number
  stackKeylogCandidates: number
  stackUncovered: number
  state: 'idle' | 'waiting_for_network' | 'waiting_for_boundary' | 'unrecognized_stream' | 'delivery_failed' | 'waiting_for_pair' | 'delivering'
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
    memoryEvidence?: Array<Record<string, unknown>>
    codeEvidence?: Array<Record<string, unknown>>
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
  source: 'local'
  sourceLabel: string
  dumpId?: string
  agentVersion?: string
  dexOwnershipMode: 'class-index' | 'legacy-path'
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
  method_prototypes?: string[]
  method_prototypes_truncated?: boolean
  api_strings?: string[]
}

export type KernSightDexOwnershipCategory =
  | 'business'
  | 'internal_component'
  | 'third_party_sdk'
  | 'dynamic_payload'
  | 'mixed'
  | 'unknown'

export interface KernSightDexOwnershipEntry {
  sha256: string
  canonical_relative_path: string
  category: KernSightDexOwnershipCategory
  confidence: number
  sampled_classes: number
  business_classes: number
  internal_classes: number
  third_party_classes: number
  unknown_classes: number
  dominant_namespaces: string[]
  reasons: string[]
}

export interface KernSightDexOwnershipReport {
  schema_version: string
  package: string
  inferred_internal_namespaces?: Array<{
    namespace: string
    registered_components: number
    sampled_classes: number
    reason: string
  }>
  entries: KernSightDexOwnershipEntry[]
  business: number
  internal_components: number
  third_party_sdks: number
  dynamic_payloads: number
  mixed: number
  unknown: number
  business_class_samples?: number
  business_dex_sets?: number
  internal_class_samples?: number
  third_party_class_samples?: number
  unknown_class_samples?: number
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
  memory_window_write_failures?: number
  memory_window_read_failures?: number
  memory_window_short_reads?: number
  http_calls?: Array<Record<string, unknown>>
  http_code_refs?: Array<Record<string, unknown>>
  jni_exports?: Array<{ relative_path?: string; names?: string[] }>
  recovered_sm4_key?: string | null
  packed_plaintext_names?: Array<{ sha256?: string; sidecar?: string; count?: number; truncated?: boolean; splash_names?: string[]; note?: string }>
  dynamic_symbols?: Array<{ relative_path?: string; defined_function_count?: number; names?: string[]; status?: string }>
  key_slots?: number
  secneo_decrypted?: number
  artifacts?: unknown[]
  dex_sets?: KernSightDexSet[]
  dex_index?: KernSightDexIndex
  dex_ownership?: KernSightDexOwnershipReport
  registered_component_classes?: string[]
  native_rule_version?: string
  native_framework_matches?: KernSightNativeFrameworkMatch[]
  sensitive_files?: KernSightSensitiveFile[]
  snapshots?: Array<Record<string, unknown>>
  mapped_code?: Array<Record<string, unknown>>
  open_code?: Array<Record<string, unknown>>
  code_loaders?: Array<Record<string, unknown>>
  total_bytes?: number
  physical_bytes?: number
  deduplicated_bytes?: number
  mobilee_archive_coverage?: { status: 'partial' | 'unknown'; scope?: string; complete_collection?: false }
  mobilee_transport_status?: { complete: false; status: 'partial'; notes: Array<Record<string, unknown>>; scope: string }
  local_storage_accounting?: { logical_file_bytes: number; allocated_bytes: number | null; verified_code_duplicate_bytes: number; runtime_observations?: Array<Record<string, any>>; elf_module_observations?: Array<Record<string, any>>; runtime_source_diagnostics?: Array<Record<string, unknown>>; [key: string]: unknown }
  content_dex_class_index?: { schema: string; scope: string; objects: Array<{sha256: string; bytes: number; sources: Array<Record<string, any>>; ownership: string; declared_classes: number | null; indexed_classes: number | null; omitted_classes?: number | null; classes?: string[]; declared_file_bytes?: number | null; length_matches_declared?: boolean | null; class_index_status: string; layout_diagnostics?: Record<string, any>; validation_status?: string; sha1_signature_verified?: boolean | null; adler32_checksum_verified?: boolean | null; class_hints?: Record<string, number>}> }
  apk_member_evidence?: { observations?: Array<Record<string, any>>; omitted_observations?: number; status?: string }
  storage_accounting?: string | null
  unique_inode_bytes?: number | null
  warnings?: string[]
  graph?: {
    entities?: Array<Record<string, unknown>>
    edges?: Array<Record<string, unknown>>
  }
}

export interface KernSightCaptureRelation {parentId:string;stageId:string;attemptId:string;attempt:number;stageKey:string}
export interface KernSightCaptureDiagnostic {
  schema: 'mobilee.capture-diagnostic/v1'
  coverageRecords?: Record<string, unknown>[]
  source: 'remote_lifecycle' | 'stderr' | 'stdout' | null
  record: Record<string, unknown> | null
  errorExcerpt: string | null
  stdoutBytes: number | null
  stderrBytes: number | null
  rawTailTruncated: boolean
  errorExcerptTruncated: boolean
  structuredRecordOmitted: boolean
}
export interface KernSightCaptureAttempt {
  coverageContinuation?: Record<string, unknown> | null
  sourceDisposition?: string | null
  relation: KernSightCaptureRelation
  state: string
  startedUnixMs: number
  finishedUnixMs: number | null
  sessionId: string | null
  error: string | null
  diagnosticTail?: string | null
  captureDiagnostic?: KernSightCaptureDiagnostic | null
  remoteArtifactRoot: string | null
  remoteLifecycle?: Record<string, unknown> | null
  processInstances: Array<Record<string, unknown>>
  observationError: string | null
  omittedProcessInstances: number
  stageRecords: Array<Record<string, unknown>>
}
export interface KernSightCaptureGroup {
  budget?:{schema:string;limits:{totalBytes:number;maxSeconds:number};deadlineUnixMs:number;reservations:Array<{id:string;kind:string;reservedBytes:number;chargedBytes:number|null;status:string}>}|null
  schema:'mobilee.capture-group/v1';id:string;serial:string;package:string;createdUnixMs:number;cancelRequested:boolean;
  state:string;unified?:boolean;base:Record<string,unknown>;
  stages:Array<{id:string;key:string;mode:string;durationSeconds:number;launchAfterAttach:boolean;required:boolean;
    attempts:KernSightCaptureAttempt[]}>
}
export interface KernSightGroupStageResult {
  continuationPolicy?: "sealed_partial_snapshot" | "source_absent_independent_start" | null
  group:KernSightCaptureGroup;result:KernSightCaptureResult|null;error:string|null;continueAfterPartial?:boolean}

export interface KernSightCaptureGroupTrash {
  schema: 'mobilee.capture-group-trash/v1'; group: KernSightCaptureGroup;
  trashedUnixMs: number; managed: boolean; trashed?: boolean; retainedSessionIds?: string[]; importedRoots: string[];
}

export interface KernSightGroupPurgeEntry {
  path: string
  kind: string
  logicalBytes: number
  allocatedBytes: number | null
  files: number
}
export interface KernSightGroupPurgeDevice {
  status: 'ready' | 'offline' | 'blocked' | 'not_required'
  entries: KernSightGroupPurgeEntry[]
  warnings: string[]
}
export interface KernSightGroupPurgePlan {
  schema: string
  id: string
  parentId: string
  serial: string
  package: string
  createdUnixMs: number
  expiresUnixMs: number
  confirmationToken: string
  confirmationText: string
  localEntries: KernSightGroupPurgeEntry[]
  device: KernSightGroupPurgeDevice | null
  warnings: string[]
  localOnly: boolean
}
export interface KernSightGroupPurgeReport {
  id: string
  parentId: string
  serial: string
  package: string
  importedRoots: string[]
  retainedSessionIds: string[]
  updatedUnixMs: number
  state: string
  localState: string
  deviceState: string
  removedLocalFiles: number
  removedLocalAllocatedBytes: number | null
  warnings: string[]
  error: string | null
}
