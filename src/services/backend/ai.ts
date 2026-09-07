import { invoke } from '@tauri-apps/api/core'
import type {
  AiContextPack,
  AiProviderRequest,
  AiProviderReview,
  AiProviderStatus,
  AiTaskTemplate,
  AiValidationReport,
  BuildAiContextPackRequest,
  ExclusionMutation,
  ExclusionRule,
} from '@/types/ai'
import type { KnowledgeImportReport, KnowledgeMutation, KnowledgePattern } from '@/types/knowledge'
import type { RuleInventory } from '@/types/rules'

export const aiBackend = {
  listTaskTemplates: () => invoke<AiTaskTemplate[]>('list_ai_task_templates'),
  buildContextPack: (request: BuildAiContextPackRequest) => invoke<AiContextPack>('build_ai_context_pack', { request }),
  exportContextPack: (pack: AiContextPack, outputPath: string) =>
    invoke<string>('export_ai_context_pack', { request: { pack, outputPath } }),
  validateResult: (pack: AiContextPack, resultJson: string) =>
    invoke<AiValidationReport>('validate_ai_analysis_result', { request: { pack, resultJson } }),
  testProvider: (request: AiProviderRequest) =>
    invoke<AiProviderStatus>('test_ai_provider', { request }),
  runSecurityReview: (provider: AiProviderRequest, pack: AiContextPack) =>
    invoke<AiProviderReview>('run_ai_security_review', { request: { provider, pack } }),
  listKnowledge: () => invoke<KnowledgePattern[]>('list_knowledge'),
  listRules: () => invoke<RuleInventory>('list_rules'),
  addPattern: (pattern: KnowledgePattern) => invoke<KnowledgeMutation>('add_pattern', { pattern }),
  mergePattern: (pattern: KnowledgePattern) => invoke<KnowledgeMutation>('merge_pattern', { pattern }),
  exportKnowledge: (outputPath: string) => invoke<string>('export_knowledge', { outputPath }),
  importKnowledge: (inputPath: string) => invoke<KnowledgeImportReport>('import_knowledge', { inputPath }),
  listExclusions: () => invoke<ExclusionRule[]>('list_exclusions'),
  mergeExclusion: (rule: ExclusionRule) => invoke<ExclusionMutation>('merge_exclusion', { rule }),
}
