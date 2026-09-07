import { invoke } from '@tauri-apps/api/core'
import type { AnalysisBaselineDiff, AnalysisCase, AnalyzeAppRequest, AppAnalysis } from '@/types/analysis'
import type { TerminalEntry } from '@/types/common'

export const analysisBackend = {
  analyze: (request: AnalyzeAppRequest) => invoke<AppAnalysis>('analyze_app', { request }),
  exportHtml: (analysis: AppAnalysis, outputPath: string, compact = false, verdicts: Record<string, string> = {}, notes = '') =>
    invoke<string>(compact ? 'export_analysis_html_compact' : 'export_analysis_html', {
      analysis,
      outputPath,
      verdicts,
      notes,
    }),
  exportSensitiveValue: (value: string, outputPath: string) =>
    invoke<string>('export_sensitive_value', { request: { value, outputPath } }),
  saveCase: (outputPath: string, analysis: AppAnalysis, verdicts: Record<string, string>, notes: string, runtimeHistory: TerminalEntry[] = []) =>
    invoke<string>('save_analysis_case', { request: { outputPath, analysis, verdicts, notes, runtimeHistory } }),
  loadCase: (path: string) => invoke<AnalysisCase>('load_analysis_case', { path }),
  compareCase: (baselinePath: string, current: AppAnalysis) =>
    invoke<AnalysisBaselineDiff>('compare_analysis_case', { request: { baselinePath, current } }),
}
