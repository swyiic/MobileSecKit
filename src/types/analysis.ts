export interface AppFinding {
  severity: string
  title: string
  detail: string
}

export interface SensitiveItem {
  item: string
  location: string
  kind: string
  severity: string
  value?: string
  lineNumber?: number
  context?: string
  source?: 'binary-strings' | 'text-resource' | 'archive-entry' | string
  filtered?: boolean
  filterReason?: string
}

export interface RawInventoryItem {
  source: 'string' | 'class' | 'symbol' | 'url' | 'file' | string
  value: string
  frequency: number
  covered: boolean
}

export interface BinaryInsight {
  category: string
  target: string
  severity: string
  detail: string
  evidence: string[]
}

export interface CodeInsight {
  platform: 'android' | 'ios'
  kind: string
  binary: string
  className?: string
  name: string
  signature?: string
  address?: string
  moduleOffset?: string
  sourceFile?: string
  lineNumber?: number
  runtimeTarget?: string
  references: string[]
  snippet: string[]
  confidence: string
}

export interface DataBoundaryObservation {
  id: string
  boundary: string
  direction: string
  title: string
  summary: string
  sourceType: string
  sourceLocation?: string
  platform: 'android' | 'ios' | string
  framework?: string
  dataTypes: string[]
  producer?: string
  consumer?: string
  operation?: string
  endpoint?: string
  runtimeTarget?: string
  severity: string
  confidence: string
  evidence: string[]
  correlationKey?: string
  observedAt?: number
}

export type DataFlowValidationState = 'static-candidate' | 'runtime-observed' | 'correlated' | 'manual-confirmed' | 'blocked'

export interface DataBoundaryFlow {
  id: string
  boundary: string
  title: string
  direction: string
  producer?: string
  consumer?: string
  endpoint?: string
  operation?: string
  frameworks: string[]
  dataTypes: string[]
  severity: string
  validationState: DataFlowValidationState
  evidenceIds: string[]
  sourceTypes: string[]
  sourceLocations: string[]
  observedAt?: number
  observations: DataBoundaryObservation[]
}

export interface ProtectionAssessment {
  status: string
  packers: string[]
  indicators: string[]
}

export interface AntiInstrumentationCandidate {
  label: string
  signal: string
  source: 'archive' | 'content' | string
  location: string
  runtime: 'pending' | 'blocked' | 'passed' | string
  evidence: string[]
  filtered?: boolean
  filterReason?: string
}

export interface AntiInstrumentationAssessment {
  status: 'not-detected' | 'pending' | 'blocked' | 'passed' | string
  candidates: AntiInstrumentationCandidate[]
  indicators: string[]
}

export interface ScanCoverage {
  archiveEntriesTotal: number
  archiveEntriesIndexed: number
  archiveEntriesOmitted: number
  binaryCandidatesTotal: number
  binaryCandidatesSelected: number
  binaryCandidatesScanned: number
  oversizedBinaryCandidates: number
  unreadableBinaryCandidates: number
  sensitiveItemsDiscovered: number
  sensitiveItemsReturned: number
  codeInsightsDiscovered: number
  codeInsightsReturned: number
  complete: boolean
  warnings: string[]
}

export interface MasvsObservation {
  controlId: string
  group: string
  title: string
  status: 'not-assessed' | 'static-candidate' | 'runtime-observed' | string
  severity: string
  confidence: string
  summary: string
  evidence: string[]
  verificationSteps: string[]
}

export interface VerificationRecipe {
  id: string
  title: string
  platform: string
  goal: string
  relatedControls: string[]
  prerequisites: string[]
  steps: string[]
  expectedEvidence: string[]
}

export interface AppAnalysis {
  platform: 'android' | 'ios'
  path: string
  fileName: string
  fileSize: number
  artifactSha256: string
  packageId?: string
  displayName?: string
  versionName?: string
  versionCode?: string
  minSdk?: string
  targetSdk?: string
  architectures: string[]
  frameworks: string[]
  thirdPartyLibraries: string[]
  protection: ProtectionAssessment
  antiInstrumentation: AntiInstrumentationAssessment
  permissions: string[]
  components: string[]
  exportedComponents: string[]
  intentFilters: string[]
  manifestFlags: string[]
  files: string[]
  manifestXml?: string
  sensitiveItems: SensitiveItem[]
  rawInventory: RawInventoryItem[]
  binaryInsights: BinaryInsight[]
  codeInsights: CodeInsight[]
  dataBoundaries: DataBoundaryObservation[]
  scanCoverage: ScanCoverage
  masvsObservations: MasvsObservation[]
  verificationRecipes: VerificationRecipe[]
  signature?: string
  findings: AppFinding[]
  toolsUsed: string[]
  missingDependencies: string[]
}

export interface AnalysisCase {
  schemaVersion: string
  savedAt: number
  analysis: AppAnalysis
  verdicts: Record<string, string>
  notes: string
  runtimeHistory: import('./common').TerminalEntry[]
}

export interface AnalysisBaselineDiff {
  baselineFileName: string
  baselineSha256: string
  currentSha256: string
  addedFindings: string[]
  resolvedFindings: string[]
  addedSensitiveItems: string[]
  resolvedSensitiveItems: string[]
  addedLibraries: string[]
  removedLibraries: string[]
  changed: boolean
}

export interface AnalyzeAppRequest {
  path: string
  apktoolPath?: string
  jadxPath?: string
  excludedUrlPatterns?: string[]
}
