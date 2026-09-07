export interface KnowledgePattern {
  patternId: string
  boundary: string
  title: string
  triggerSignals: string[]
  playbook: string[]
  evidenceSchema: Record<string, unknown>
  reusableFor: string[]
  verifiedIn: string[]
}

export interface KnowledgeMutation {
  pattern: KnowledgePattern
  created: boolean
  total: number
}

export interface KnowledgeImportReport {
  imported: number
  created: number
  merged: number
  total: number
}
