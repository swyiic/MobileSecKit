import type { AppAnalysis, DataBoundaryObservation, RawInventoryItem } from './analysis'
import type { KnowledgePattern } from './knowledge'

export interface AiTaskTemplate {
  id: string
  label: string
  description: string
  focusBoundaries: string[]
  reviewGoals: string[]
}

export interface AiContextOptions {
  maxChars: number
  maxEvidenceItems: number
  maxEvidenceChars: number
  redactSensitive: boolean
  includeRawSensitiveValues: boolean
  includeLowConfidence: boolean
}

export interface BuildAiContextPackRequest {
  analysis: AppAnalysis
  runtimeObservations: DataBoundaryObservation[]
  taskId: string
  options: AiContextOptions
}

export interface AiEvidenceRecord {
  id: string
  kind: string
  observationState: 'static-candidate' | 'runtime-observed' | 'runtime-confirmed' | string
  title: string
  summary: string
  severity: string
  confidence: string
  source: string
  location?: string
  boundary?: string
  framework?: string
  endpoint?: string
  operation?: string
  tags: string[]
  lines: string[]
}

export interface AiEvidenceChunk {
  id: string
  title: string
  evidenceIds: string[]
  estimatedTokens: number
  characterCount: number
  boundaryCounts: Record<string, number>
}

export interface AiContextPack {
  schemaVersion: string
  generatedAt: string
  task: AiTaskTemplate
  app: {
    platform: string
    fileName: string
    packageId?: string
    displayName?: string
    version?: string
    architectures: string[]
    frameworks: string[]
    protectionStatus: string
    protectionIndicators: string[]
    counts: Record<string, number>
  }
  safetyRules: string[]
  analysisInstructions: string[]
  evidence: AiEvidenceRecord[]
  uncoveredTokens: RawInventoryItem[]
  knowledgeHits: KnowledgePattern[]
  chunks: AiEvidenceChunk[]
  omittedEvidenceCount: number
  characterCount: number
  estimatedTokens: number
  resultSchema: Record<string, unknown>
}

export interface AiClaim {
  title: string
  severity: string
  conclusionType: 'hypothesis' | 'verified-finding' | string
  description: string
  evidenceIds: string[]
  confidence: string
}

export interface AiAnalysisResult {
  schemaVersion: string
  summary: string
  hypotheses: AiClaim[]
  findings: AiClaim[]
  missingEvidence: string[]
  recommendedNextObservations: string[]
  confidence: string
  model?: { provider?: string; model?: string; generatedAt?: string }
  proposedPatterns?: KnowledgePattern[]
  proposedExclusions?: ExclusionRule[]
}

export interface ExclusionRule {
  exclusionId: string
  appliesToKind: string
  excludeSignals: string[]
  excludePatterns: string[]
  reason: string
  verifiedIn: string[]
}

export interface ExclusionMutation {
  created: boolean
  rule: ExclusionRule
  total: number
}

export interface AiValidationIssue {
  level: 'error' | 'warning' | string
  code: string
  message: string
  claimTitle?: string
  evidenceId?: string
}

export interface AiValidationReport {
  valid: boolean
  issues: AiValidationIssue[]
  normalizedResult: AiAnalysisResult
  citedEvidenceCount: number
  unknownEvidenceIds: string[]
}

export type AiProviderKind = 'openai-compatible' | 'ollama'

export interface AiProviderRequest {
  providerKind: AiProviderKind
  baseUrl: string
  apiKey?: string
  model: string
  timeoutSeconds: number
  maxOutputTokens: number
}

export interface AiProviderStatus {
  success: boolean
  providerKind: string
  endpoint: string
  message: string
  availableModels: string[]
  elapsedMs: number
}

export interface AiProviderReview {
  providerKind: string
  model: string
  endpoint: string
  rawResult: string
  validation: AiValidationReport
  inputEstimatedTokens: number
  outputEstimatedTokens: number
  elapsedMs: number
}
