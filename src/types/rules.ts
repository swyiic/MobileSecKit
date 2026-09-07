import type { ExclusionRule } from './ai'

export interface SensitiveRuleDefinition {
  label: string
  kind: string
  severity: string
  pattern: string
  requireContext: string[]
  excludeSignals: string[]
  excludePatterns: string[]
}

export interface SignalRuleDefinition {
  label: string
  triggerSignals: string[]
  scope?: string
  indicator?: string
}

export interface RuleInventory {
  sensitive: SensitiveRuleDefinition[]
  frameworks: SignalRuleDefinition[]
  protection: SignalRuleDefinition[]
  antiInstrumentation: SignalRuleDefinition[]
  exclusions: ExclusionRule[]
}

export type RuleCategory = 'sensitive' | 'protection' | 'frameworks' | 'antiInstrumentation' | 'exclusions'
